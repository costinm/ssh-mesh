use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Mutex;
use tracing::{debug, error, info};

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
            failure_count: 0,
            work_items: Vec::new(),
        }
    }
}

pub struct JobScheduler {
    jobs_dir: PathBuf,
    jobs: Mutex<HashMap<String, JobEntry>>,
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

    fn now_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    pub async fn schedule(&self, config: JobConfig) -> Result<()> {
        let name = config.name.clone();
        if config.persisted {
            tokio::fs::create_dir_all(&self.jobs_dir).await?;
            config.save(&self.jobs_dir).await?;
        }
        
        let mut jobs = self.jobs.lock().await;
        jobs.insert(name, JobEntry::new(config));
        Ok(())
    }

    pub async fn enqueue(&self, job_name: &str, mut work: WorkItem) -> Result<()> {
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
        let mut jobs = self.jobs.lock().await;
        if jobs.remove(job_name).is_some() {
            // Remove from disk
            let file_path = self.jobs_dir.join(format!("{}.toml", job_name));
            let _ = tokio::fs::remove_file(&file_path).await;
        }
        Ok(())
    }

    pub async fn cancel_all(&self) -> Result<()> {
        let mut jobs = self.jobs.lock().await;
        jobs.clear();
        let _ = tokio::fs::remove_dir_all(&self.jobs_dir).await;
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

        for (name, entry) in jobs.iter_mut() {
            if entry.state == JobState::Running {
                continue;
            }

            if let Some(eligible) = entry.next_eligible {
                if now < eligible {
                    continue;
                }
            }

            if Self::evaluate_constraints(&entry.config, &state) {
                // Execute
                entry.state = JobState::Running;
                entry.last_run = Some(now);
                started.push(name.clone());
                
                // We'll execute async to avoid holding the lock
                let executor = self.executor.clone();
                let config = entry.config.clone();
                let work_items = entry.work_items.clone();
                
                tokio::spawn(async move {
                    if let Err(e) = executor.execute(&config, &work_items).await {
                        error!("Failed to execute job {}: {}", config.name, e);
                    }
                });
            }
        }

        Ok(started)
    }

    pub async fn job_finished(&self, name: &str, reschedule: bool, result: Option<WorkResult>) -> Result<()> {
        let mut jobs = self.jobs.lock().await;
        if let Some(entry) = jobs.get_mut(name) {
            entry.state = if reschedule { JobState::Pending } else { JobState::Completed };
            let now = Self::now_secs();
            
            if reschedule {
                entry.failure_count += 1;
                // apply backoff
                let backoff_secs = match entry.config.backoff.policy {
                    super::config::BackoffPolicy::Linear => {
                        entry.config.backoff.initial_secs * (entry.failure_count as u64)
                    }
                    super::config::BackoffPolicy::Exponential => {
                        entry.config.backoff.initial_secs * (2_u64.pow(entry.failure_count - 1))
                    }
                };
                entry.next_eligible = Some(now + backoff_secs);
            } else {
                entry.failure_count = 0;
                
                if let Some(periodic) = entry.config.schedule.periodic_secs {
                    entry.state = JobState::Pending;
                    entry.next_eligible = Some(now + periodic);
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

    fn evaluate_constraints(config: &JobConfig, state: &SystemState) -> bool {
        let c = &config.constraints;

        if let Some(net) = &c.network_type {
            match net {
                NetworkType::None => {} // no req
                NetworkType::Any | NetworkType::Unmetered | NetworkType::NotRoaming | NetworkType::Cellular => {
                    if !state.network_connected {
                        return false;
                    }
                    // For a real implementation, we'd check if the active network matches the specific type requested.
                    // For now, we just ensure ANY network is connected.
                    if matches!(net, NetworkType::Unmetered) && state.network_type != NetworkType::Unmetered {
                        // This assumes state.network_type holds the actual active network type.
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
