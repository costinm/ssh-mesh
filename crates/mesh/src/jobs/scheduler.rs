use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use super::config::{JobConfig, NetworkType, WorkItem, WorkResult};
use super::event::{SystemEvent, SystemState};
use super::executor::JobExecutor;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobState {
    Pending,
    Running,
    Completed,
    Failed,
}

#[derive(Debug)]
pub struct JobEntry {
    pub config: JobConfig,
    pub state: JobState,
    pub last_run: Option<u64>,
    pub next_eligible: Option<u64>,
    pub scheduled_at: u64,
    pub failure_count: u32,
    pub work_items: Vec<WorkItem>,
}

impl JobEntry {
    pub fn new(config: JobConfig) -> Self {
        Self {
            config,
            state: JobState::Pending,
            last_run: None,
            next_eligible: None,
            scheduled_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            failure_count: 0,
            work_items: Vec::new(),
        }
    }
}

pub struct JobScheduler {
    jobs_dir: PathBuf,
    pub(crate) jobs: Mutex<HashMap<String, JobEntry>>,
    state: Mutex<SystemState>,
    executor: Arc<dyn JobExecutor>,
}

impl JobScheduler {
    pub fn new(jobs_dir: impl Into<PathBuf>, executor: Arc<dyn JobExecutor>) -> Self {
        Self {
            jobs_dir: jobs_dir.into(),
            jobs: Mutex::new(HashMap::new()),
            state: Mutex::new(SystemState::default()),
            executor,
        }
    }

    pub(crate) fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    pub async fn schedule(&self, config: JobConfig) -> Result<()> {
        let name = config.name.clone();
        crate::config::validate_service_name(&name)
            .map_err(|e| anyhow::anyhow!("invalid job name: {e}"))?;
        if config.persisted {
            tokio::fs::create_dir_all(&self.jobs_dir).await?;
            config.save(&self.jobs_dir).await?;
        }

        let mut jobs = self.jobs.lock().await;
        let mut entry = JobEntry::new(config);
        if let Some(schedule) = &entry.config.schedule {
            if let Some(latency) = schedule.minimum_latency_secs {
                entry.next_eligible = Some(Self::now_secs() + latency);
            }
        }
        jobs.insert(name, entry);
        Ok(())
    }

    pub async fn enqueue(&self, job_name: &str, mut work: WorkItem) -> Result<()> {
        crate::config::validate_service_name(job_name)
            .map_err(|e| anyhow::anyhow!("invalid job name: {e}"))?;
        let mut jobs = self.jobs.lock().await;
        if let Some(entry) = jobs.get_mut(job_name) {
            work.enqueued_at = chrono::Utc::now().to_rfc3339();

            if entry.config.persisted {
                let job_dir = self.jobs_dir.join(job_name);
                work.save(&job_dir).await?;
            }

            entry.work_items.push(work);
            Ok(())
        } else {
            anyhow::bail!("Job {} not found", job_name)
        }
    }

    pub async fn cancel(&self, job_name: &str) -> Result<()> {
        crate::config::validate_service_name(job_name)
            .map_err(|e| anyhow::anyhow!("invalid job name: {e}"))?;
        let mut jobs = self.jobs.lock().await;
        if jobs.remove(job_name).is_some() {
            // Remove from disk
            let file_path = self.jobs_dir.join(format!("{}.toml", job_name));
            let _ = tokio::fs::remove_file(&file_path).await;
        }
        Ok(())
    }

    pub async fn cancel_all(&self) -> Result<()> {
        // Refuse to recursively delete a path that is root or suspiciously
        // short, as a guard against misconfiguration.
        let dir = &self.jobs_dir;
        let canonical = tokio::fs::canonicalize(dir)
            .await
            .map_err(|e| anyhow::anyhow!("cannot canonicalize jobs_dir: {e}"))?;
        if canonical.parent().is_none() {
            anyhow::bail!("refusing to remove_dir_all on filesystem root");
        }
        let mut jobs = self.jobs.lock().await;
        jobs.clear();
        let _ = tokio::fs::remove_dir_all(&canonical).await;
        Ok(())
    }

    pub async fn check_jobs(&self) -> Result<()> {
        if !self.jobs_dir.exists() {
            return Ok(());
        }

        let mut jobs_guard = self.jobs.lock().await;
        let mut entries = tokio::fs::read_dir(&self.jobs_dir).await?;

        while let Some(file) = entries.next_entry().await? {
            let path = file.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("toml") {
                if let Ok(config) = JobConfig::load(&path).await {
                    let name = config.name.clone();

                    if !jobs_guard.contains_key(&name) {
                        let mut entry = JobEntry::new(config);
                        let job_dir = self.jobs_dir.join(&name);

                        if let Ok(work_items) = WorkItem::load_all(&job_dir).await {
                            entry.work_items = work_items;
                        }

                        jobs_guard.insert(name, entry);
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn on_event(&self, event: SystemEvent) -> Result<Vec<String>> {
        {
            let mut state = self.state.lock().await;
            state.update(&event);
        }

        let mut started = Vec::new();
        let state = self.state.lock().await;
        let mut jobs = self.jobs.lock().await;
        let now = Self::now_secs();

        // Sort by priority (lowest number first)
        let mut job_refs: Vec<(&String, &mut JobEntry)> = jobs.iter_mut().collect();
        job_refs.sort_by_key(|(_, entry)| entry.config.priority);

        for (name, entry) in job_refs {
            if entry.state == JobState::Running {
                continue;
            }

            if let Some(eligible) = entry.next_eligible {
                if now < eligible {
                    continue;
                }
            }

            let deadline_passed = entry
                .config
                .schedule
                .as_ref()
                .and_then(|s| s.override_deadline_secs)
                .map(|d| now >= entry.scheduled_at + d)
                .unwrap_or(false);

            let transient_trigger_fired = match &event {
                SystemEvent::CustomCondition { key, value: true } => entry
                    .config
                    .constraints
                    .as_ref()
                    .map_or(false, |c| c.triggers.contains(key)),
                _ => false,
            };

            if deadline_passed
                || Self::evaluate_constraints(&entry.config, &state, transient_trigger_fired)
            {
                // Execute
                entry.state = JobState::Running;
                entry.last_run = Some(now);
                started.push(name.clone());

                // We'll execute async to avoid holding the lock
                let executor = self.executor.clone();
                let config = entry.config.clone();
                let work_items = entry.work_items.clone();
                let trace_tag = config
                    .trace_tag
                    .clone()
                    .unwrap_or_else(|| "none".to_string());

                tokio::spawn(async move {
                    info!(trace_tag = %trace_tag, "JobScheduler starting job {}", config.name);
                    if let Err(e) = executor.execute(&config, &work_items).await {
                        error!(trace_tag = %trace_tag, "Failed to execute job {}: {}", config.name, e);
                    }
                });
            }
        }

        Ok(started)
    }

    pub async fn job_finished(
        &self,
        name: &str,
        reschedule: bool,
        result: Option<WorkResult>,
    ) -> Result<()> {
        let mut jobs = self.jobs.lock().await;
        if let Some(entry) = jobs.get_mut(name) {
            entry.state = if reschedule {
                JobState::Pending
            } else {
                JobState::Completed
            };
            let now = Self::now_secs();

            if reschedule {
                entry.failure_count += 1;
                // B19: Honor `max_retries`. When the failure count exceeds the
                // configured limit, give up on rescheduling and mark the job
                // completed/failed so the periodic scheduler doesn't hammer it
                // forever with an unbounded backoff.
                let exceeded_max = entry
                    .config
                    .backoff
                    .max_retries
                    .is_some_and(|max| entry.failure_count > max);
                if exceeded_max {
                    warn!(
                        "Job '{}' hit max_retries ({}), stopping",
                        name,
                        entry.config.backoff.max_retries.unwrap()
                    );
                    entry.state = JobState::Completed;
                    entry.failure_count = 0;
                    if entry.config.save_result && entry.config.persisted {
                        let job_dir = self.jobs_dir.join(name);
                        for item in &entry.work_items {
                            let _ = item.complete(&job_dir, result.clone()).await;
                        }
                    }
                    entry.work_items.clear();
                    return Ok(());
                }

                // B19: Cap the exponent for exponential backoff to avoid u64
                // overflow in `2.pow()` (panics in debug for shift >= 64, wraps
                // in release producing wild values). Cap to 30 shifts and
                // apply a hard `max_secs` ceiling.
                let initial = entry.config.backoff.initial_secs;
                let backoff_secs = match entry.config.backoff.policy {
                    super::config::BackoffPolicy::Linear => {
                        initial.saturating_mul(entry.failure_count as u64)
                    }
                    super::config::BackoffPolicy::Exponential => {
                        let shifts = (entry.failure_count - 1).min(30);
                        let multiplier = 1u64 << shifts;
                        initial.saturating_mul(multiplier)
                    }
                };
                let initial = entry.config.backoff.initial_secs;
                let _ = initial;
                let backoff_secs = backoff_secs.min(entry.config.backoff.max_secs);
                entry.next_eligible = Some(now + backoff_secs);
            } else {
                entry.failure_count = 0;

                if let Some(schedule) = &entry.config.schedule {
                    if let Some(periodic) = schedule.periodic_secs {
                        entry.state = JobState::Pending;
                        let flex = schedule.flex_secs.unwrap_or(periodic).min(periodic);
                        // Next eligible is period minus flex window
                        entry.next_eligible = Some(now + periodic - flex);
                        // Also reset scheduled_at so override_deadline works on the new period
                        entry.scheduled_at = now;
                    }
                }
            }

            // If we are completed (not rescheduled), mark work items as complete
            if !reschedule {
                if entry.config.save_result && entry.config.persisted {
                    let job_dir = self.jobs_dir.join(name);
                    for item in &entry.work_items {
                        let _ = item.complete(&job_dir, result.clone()).await;
                    }
                }
                entry.work_items.clear();
            }

            Ok(())
        } else {
            anyhow::bail!("Job not found")
        }
    }

    fn evaluate_constraints(
        config: &JobConfig,
        state: &SystemState,
        transient_trigger_fired: bool,
    ) -> bool {
        let Some(c) = &config.constraints else {
            return true;
        };

        if !c.triggers.is_empty() && !transient_trigger_fired {
            return false;
        }

        if let Some(net) = &c.network_type {
            match net {
                NetworkType::None => {} // no req
                NetworkType::Any => {
                    if !state.network_connected {
                        return false;
                    }
                }
                NetworkType::Unmetered | NetworkType::NotRoaming | NetworkType::Cellular => {
                    if !state.network_connected {
                        return false;
                    }
                    if state.network_type != *net {
                        return false;
                    }
                }
            }
        }

        if c.requires_charging && !state.is_charging {
            return false;
        }

        if c.requires_device_idle && !state.is_idle {
            return false;
        }

        if c.requires_battery_not_low && state.battery_low {
            return false;
        }

        if c.requires_storage_not_low && state.storage_low {
            return false;
        }

        for (k, v) in &c.custom {
            if state.custom.get(k) != Some(v) {
                return false;
            }
        }

        true
    }
}
