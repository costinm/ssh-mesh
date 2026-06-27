use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::Mutex;

use crate::jobs::config::{
    BackoffConfig, ConstraintConfig, JobConfig, NetworkType, ScheduleConfig,
};
use crate::jobs::event::SystemEvent;
use crate::jobs::executor::JobExecutor;
use crate::jobs::scheduler::{JobScheduler, JobState};

struct MockExecutor {
    executed_jobs: Mutex<Vec<String>>,
    fail_next: AtomicU32,
}

impl MockExecutor {
    fn new() -> Self {
        Self {
            executed_jobs: Mutex::new(Vec::new()),
            fail_next: AtomicU32::new(0),
        }
    }
}

#[async_trait]
impl JobExecutor for MockExecutor {
    async fn execute(
        &self,
        job: &JobConfig,
        _work_items: &[crate::jobs::config::WorkItem],
    ) -> anyhow::Result<()> {
        let fails = self.fail_next.load(Ordering::SeqCst);
        if fails > 0 {
            self.fail_next.fetch_sub(1, Ordering::SeqCst);
            anyhow::bail!("Mock failure");
        }
        self.executed_jobs.lock().await.push(job.name.clone());
        Ok(())
    }
}

fn create_base_job(name: &str) -> JobConfig {
    JobConfig {
        name: name.to_string(),
        command: "mock".to_string(),
        args: vec![],
        uid: None,
        gid: None,
        user: None,
        group: None,
        env: Default::default(),
        priority: 500,
        oneshot: false,
        oom_score_adjust: None,
        resources: Default::default(),
        activation: vec![],
        network: Default::default(),
        source_path: None,
        auth: None,
        schedule: Some(ScheduleConfig::default()),
        constraints: Some(ConstraintConfig::default()),
        backoff: BackoffConfig::default(),
        persisted: false,
        prefetch: false,
        save_result: false,
        trace_tag: None,
        user_initiated: false,
        expedited: false,
        estimated_download_bytes: None,
        estimated_upload_bytes: None,
        minimum_network_chunk_bytes: None,
    }
}

#[tokio::test]
async fn test_schedule_and_cancel() {
    let executor = Arc::new(MockExecutor::new());
    let scheduler = JobScheduler::new("/tmp/mock_jobs", executor);

    let job = create_base_job("test1");
    scheduler.schedule(job).await.unwrap();

    let jobs = scheduler.jobs.lock().await;
    assert!(jobs.contains_key("test1"));
    assert_eq!(jobs.get("test1").unwrap().state, JobState::Pending);
    drop(jobs);

    scheduler.cancel("test1").await.unwrap();
    let jobs = scheduler.jobs.lock().await;
    assert!(!jobs.contains_key("test1"));
}

#[tokio::test]
async fn test_constraint_charging() {
    let executor = Arc::new(MockExecutor::new());
    let scheduler = JobScheduler::new("/tmp/mock_jobs", executor.clone());

    let mut job = create_base_job("charge_job");
    job.constraints.as_mut().unwrap().requires_charging = true;
    scheduler.schedule(job).await.unwrap();

    // Not charging - shouldn't start
    scheduler
        .on_event(SystemEvent::IdleChanged { is_idle: true })
        .await
        .unwrap();
    assert!(executor.executed_jobs.lock().await.is_empty());

    // Charging - should start
    scheduler
        .on_event(SystemEvent::ChargingChanged { is_charging: true })
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert_eq!(executor.executed_jobs.lock().await.len(), 1);
}

#[tokio::test]
async fn test_constraint_network() {
    let executor = Arc::new(MockExecutor::new());
    let scheduler = JobScheduler::new("/tmp/mock_jobs", executor.clone());

    let mut job = create_base_job("net_job");
    job.constraints.as_mut().unwrap().network_type = Some(NetworkType::Unmetered);
    scheduler.schedule(job).await.unwrap();

    // Any network (e.g. Cellular) - shouldn't start
    scheduler
        .on_event(SystemEvent::NetworkChanged {
            network_type: NetworkType::Cellular,
            connected: true,
        })
        .await
        .unwrap();
    assert!(executor.executed_jobs.lock().await.is_empty());

    // Unmetered network - should start
    scheduler
        .on_event(SystemEvent::NetworkChanged {
            network_type: NetworkType::Unmetered,
            connected: true,
        })
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert_eq!(executor.executed_jobs.lock().await.len(), 1);
}

#[tokio::test]
async fn test_minimum_latency() {
    let executor = Arc::new(MockExecutor::new());
    let scheduler = JobScheduler::new("/tmp/mock_jobs", executor.clone());

    let mut job = create_base_job("latency_job");
    job.schedule.as_mut().unwrap().minimum_latency_secs = Some(3600); // 1 hour
    scheduler.schedule(job).await.unwrap();

    // All constraints met (none), but latency not elapsed
    scheduler.on_event(SystemEvent::TimerTick).await.unwrap();
    assert!(executor.executed_jobs.lock().await.is_empty());

    // Hack: manually advance time in the scheduler's job entry
    let mut jobs = scheduler.jobs.lock().await;
    let entry = jobs.get_mut("latency_job").unwrap();
    entry.next_eligible = Some(JobScheduler::now_secs() - 10);
    drop(jobs);

    scheduler.on_event(SystemEvent::TimerTick).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert_eq!(executor.executed_jobs.lock().await.len(), 1);
}

#[tokio::test]
async fn test_override_deadline() {
    let executor = Arc::new(MockExecutor::new());
    let scheduler = JobScheduler::new("/tmp/mock_jobs", executor.clone());

    let mut job = create_base_job("deadline_job");
    job.constraints.as_mut().unwrap().requires_charging = true; // Never met
    job.schedule.as_mut().unwrap().override_deadline_secs = Some(10);
    scheduler.schedule(job).await.unwrap();

    // Deadline not passed, charging not met
    scheduler.on_event(SystemEvent::TimerTick).await.unwrap();
    assert!(executor.executed_jobs.lock().await.is_empty());

    // Hack: manipulate scheduled_at to simulate deadline passing
    let mut jobs = scheduler.jobs.lock().await;
    let entry = jobs.get_mut("deadline_job").unwrap();
    entry.scheduled_at = JobScheduler::now_secs() - 20;
    drop(jobs);

    scheduler.on_event(SystemEvent::TimerTick).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert_eq!(executor.executed_jobs.lock().await.len(), 1); // Started despite not charging
}

#[tokio::test]
async fn test_pubsub_event_triggers() {
    let executor = Arc::new(MockExecutor::new());
    let scheduler = JobScheduler::new("/tmp/mock_jobs", executor.clone());

    let mut job = create_base_job("pubsub_job");
    job.constraints.as_mut().unwrap().triggers = vec!["my_custom_event".to_string()];
    scheduler.schedule(job).await.unwrap();

    // Wrong event
    scheduler
        .on_event(SystemEvent::CustomCondition {
            key: "wrong_event".to_string(),
            value: true,
        })
        .await
        .unwrap();
    assert!(executor.executed_jobs.lock().await.is_empty());

    // Right event, but value false (doesn't trigger)
    scheduler
        .on_event(SystemEvent::CustomCondition {
            key: "my_custom_event".to_string(),
            value: false,
        })
        .await
        .unwrap();
    assert!(executor.executed_jobs.lock().await.is_empty());

    // Right event, value true - should trigger
    scheduler
        .on_event(SystemEvent::CustomCondition {
            key: "my_custom_event".to_string(),
            value: true,
        })
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert_eq!(executor.executed_jobs.lock().await.len(), 1);
}

#[tokio::test]
async fn test_priority_ordering() {
    let executor = Arc::new(MockExecutor::new());
    let scheduler = JobScheduler::new("/tmp/mock_jobs", executor.clone());

    let mut job1 = create_base_job("low_priority");
    job1.priority = 1000;
    scheduler.schedule(job1).await.unwrap();

    let mut job2 = create_base_job("high_priority");
    job2.priority = 10;
    scheduler.schedule(job2).await.unwrap();

    scheduler.on_event(SystemEvent::TimerTick).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let jobs = executor.executed_jobs.lock().await;
    assert_eq!(jobs.len(), 2);
    assert_eq!(jobs[0], "high_priority");
    assert_eq!(jobs[1], "low_priority");
}

#[tokio::test]
async fn test_periodic_flex() {
    let executor = Arc::new(MockExecutor::new());
    let scheduler = JobScheduler::new("/tmp/mock_jobs", executor.clone());

    let mut job = create_base_job("periodic_job");
    job.schedule.as_mut().unwrap().periodic_secs = Some(3600);
    job.schedule.as_mut().unwrap().flex_secs = Some(600); // 10 minutes flex
    scheduler.schedule(job).await.unwrap();

    // Complete the first run
    scheduler
        .job_finished("periodic_job", false, None)
        .await
        .unwrap();

    let jobs = scheduler.jobs.lock().await;
    let entry = jobs.get("periodic_job").unwrap();
    // 3600 - 600 = 3000 seconds latency
    let expected = JobScheduler::now_secs() + 3000;
    assert!(
        entry.next_eligible.unwrap() >= expected - 1
            && entry.next_eligible.unwrap() <= expected + 1
    );
}

#[tokio::test]
async fn test_programmatic_job_registration() {
    // 1. Create a custom executor that runs a local function instead of spawning a process
    struct LocalFunctionExecutor {
        executed: Arc<Mutex<bool>>,
    }

    #[async_trait]
    impl JobExecutor for LocalFunctionExecutor {
        async fn execute(
            &self,
            job: &JobConfig,
            _work_items: &[crate::jobs::config::WorkItem],
        ) -> anyhow::Result<()> {
            if job.name == "programmatic_job" {
                let mut exec = self.executed.lock().await;
                *exec = true;
                // Example: execute local logic here
                println!("Local function executed for job: {}", job.name);
            }
            Ok(())
        }
    }

    let executed = Arc::new(Mutex::new(false));
    let executor = Arc::new(LocalFunctionExecutor {
        executed: executed.clone(),
    });

    // Create the scheduler
    let scheduler = JobScheduler::new("/tmp/mock_programmatic_jobs", executor);

    // 2. Register a job programmatically (no config file)
    let mut job = JobConfig::default();
    job.name = "programmatic_job".to_string();
    job.command = "local_exec".to_string(); // Not used by our custom executor, but required by validation

    // Set up a constraint and a trigger event
    let mut constraints = ConstraintConfig::default();
    constraints
        .triggers
        .push("my_programmatic_event".to_string());
    job.constraints = Some(constraints);

    // Schedule the job
    scheduler.schedule(job).await.unwrap();

    // 3. Inject an event to trigger the job
    let event = SystemEvent::CustomCondition {
        key: "my_programmatic_event".to_string(),
        value: true,
    };

    // The scheduler processes the event and dispatches the job if constraints are met
    let started = scheduler.on_event(event).await.unwrap();
    assert!(started.contains(&"programmatic_job".to_string()));

    // Wait a brief moment for the async executor task to run
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    // Verify the local function was called
    let was_executed = *executed.lock().await;
    assert!(
        was_executed,
        "The programmatic job should have been executed"
    );
}
