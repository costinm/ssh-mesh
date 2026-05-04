use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::fs;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkType {
    #[default]
    None,
    Any,
    Unmetered,
    NotRoaming,
    Cellular,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BackoffPolicy {
    Linear,
    #[default]
    Exponential,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackoffConfig {
    pub initial_secs: u64,
    #[serde(default)]
    pub policy: BackoffPolicy,
    pub max_retries: Option<u32>,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial_secs: 30,
            policy: BackoffPolicy::Exponential,
            max_retries: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScheduleConfig {
    pub periodic_secs: Option<u64>,
    pub flex_secs: Option<u64>,
    pub minimum_latency_secs: Option<u64>,
    pub override_deadline_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConstraintConfig {
    pub network_type: Option<NetworkType>,
    #[serde(default)]
    pub requires_charging: bool,
    #[serde(default)]
    pub requires_device_idle: bool,
    #[serde(default)]
    pub requires_battery_not_low: bool,
    #[serde(default)]
    pub requires_storage_not_low: bool,
    #[serde(default)]
    pub triggers: Vec<String>,
    pub trigger_max_delay_secs: Option<u64>,
    #[serde(default)]
    pub custom: HashMap<String, bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobConfig {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub schedule: ScheduleConfig,
    #[serde(default)]
    pub constraints: ConstraintConfig,
    #[serde(default)]
    pub backoff: BackoffConfig,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default = "default_true")]
    pub persisted: bool,
    #[serde(default)]
    pub prefetch: bool,
    #[serde(default)]
    pub environment: HashMap<String, String>,
    #[serde(default)]
    pub save_result: bool,
    pub trace_tag: Option<String>,
    #[serde(default)]
    pub user_initiated: bool,
    #[serde(default)]
    pub expedited: bool,
    pub estimated_download_bytes: Option<u64>,
    pub estimated_upload_bytes: Option<u64>,
    pub minimum_network_chunk_bytes: Option<u64>,
}

fn default_priority() -> u32 {
    500
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkItem {
    pub id: String,
    #[serde(default)]
    pub data: HashMap<String, String>,
    pub enqueued_at: String, // RFC3339
    #[serde(default)]
    pub delivery_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkResult {
    #[serde(default)]
    pub data: HashMap<String, String>,
    #[serde(default)]
    pub blob: Vec<u8>,
}

impl JobConfig {
    pub fn parse(content: &str) -> Result<Self> {
        toml::from_str(content).context("Failed to parse JobConfig from TOML")
    }

    pub async fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path).await?;
        Self::parse(&content)
    }

    pub async fn save(&self, dir: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        let path = dir.join(format!("{}.toml", self.name));
        fs::write(&path, content).await.context("Failed to write JobConfig")
    }
}

impl WorkItem {
    pub async fn load_all(job_dir: &Path) -> Result<Vec<Self>> {
        let work_dir = job_dir.join("work");
        if !work_dir.exists() {
            return Ok(vec![]);
        }

        let mut items = Vec::new();
        let mut entries = fs::read_dir(work_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.path().extension().and_then(|s| s.to_str()) == Some("toml") {
                let content = fs::read_to_string(entry.path()).await?;
                if let Ok(item) = toml::from_str::<WorkItem>(&content) {
                    items.push(item);
                }
            }
        }
        Ok(items)
    }

    pub async fn save(&self, job_dir: &Path) -> Result<()> {
        let work_dir = job_dir.join("work");
        fs::create_dir_all(&work_dir).await?;
        let content = toml::to_string_pretty(self)?;
        let path = work_dir.join(format!("{}.toml", self.id));
        fs::write(&path, content).await.context("Failed to save WorkItem")
    }

    pub async fn complete(&self, job_dir: &Path, result: Option<WorkResult>) -> Result<()> {
        let work_dir = job_dir.join("work");
        let completed_dir = job_dir.join("completed");
        fs::create_dir_all(&completed_dir).await?;
        
        let src = work_dir.join(format!("{}.toml", self.id));
        let dst = completed_dir.join(format!("{}.toml", self.id));
        
        if src.exists() {
            fs::rename(&src, &dst).await?;
        }

        if let Some(res) = result {
            let res_content = toml::to_string_pretty(&res)?;
            let res_dst = completed_dir.join(format!("{}_result.toml", self.id));
            fs::write(&res_dst, res_content).await?;
        }
        
        Ok(())
    }
}
