use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::fs;

// Re-export the unified configuration types from the base mesh config.
pub use crate::config::*;

// Type alias for backwards compatibility and clarity in job modules.
pub type JobConfig = crate::config::AppConfig;

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
        crate::config::parse_toml(content).map_err(|e| anyhow::anyhow!("Failed to parse JobConfig from TOML: {}", e))
    }

    pub async fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path).await?;
        Self::parse(&content)
    }

    pub async fn save(&self, dir: &Path) -> Result<()> {
        let file = crate::config::AppConfigFile {
            service: crate::config::ServiceSection {
                name: self.name.clone(),
                command: self.command.clone(),
                args: self.args.clone(),
                user: self.user.clone(),
                group: self.group.clone(),
                uid: self.uid,
                gid: self.gid,
                priority: self.priority,
                oneshot: self.oneshot,
                oom_score_adjust: self.oom_score_adjust,
            },
            resources: crate::config::ResourceLimits {
                // These are resolved in runtime, saving doesn't reconstruct human strings currently
                // Usually we don't save back these configs dynamically anyway.
                memory_low: None,
                memory_high: None,
                memory_max: None,
                cpu_weight: self.resources.cpu_weight,
            },
            environment: self.env.clone(),
            activation: self.activation.clone(),
            schedule: self.schedule.clone(),
            constraints: self.constraints.clone(),
            backoff: self.backoff.clone(),
            persisted: self.persisted,
            prefetch: self.prefetch,
            save_result: self.save_result,
            trace_tag: self.trace_tag.clone(),
            user_initiated: self.user_initiated,
            expedited: self.expedited,
            estimated_download_bytes: self.estimated_download_bytes,
            estimated_upload_bytes: self.estimated_upload_bytes,
            minimum_network_chunk_bytes: self.minimum_network_chunk_bytes,
        };
        
        let content = toml::to_string_pretty(&file)?;
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
