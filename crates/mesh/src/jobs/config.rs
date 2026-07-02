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
        crate::config::parse_toml(content)
            .map_err(|e| anyhow::anyhow!("Failed to parse JobConfig from TOML: {}", e))
    }

    pub async fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path).await?;
        let name = path.file_stem().and_then(|s| s.to_str());
        crate::config::parse_service(&content, name)
            .map_err(|e| anyhow::anyhow!("Failed to parse JobConfig from TOML: {}", e))
    }

    pub async fn save(&self, dir: &Path) -> Result<()> {
        let file = crate::config::AppConfigFile {
            service: crate::config::ServiceSection {
                exec_start: exec_start_to_toml(&self.command, &self.args),
                exec_start_pre: self.exec_start_pre.clone(),
                exec_start_post: self.exec_start_post.clone(),
                exec_stop: self.exec_stop.clone(),
                exec_reload: self.exec_reload.clone(),
                activation_mode: self.activation_mode,
                activation_socket: self.activation_socket.clone(),
                user: self.user.clone(),
                group: self.group.clone(),
                working_directory: self.working_directory.clone(),
                restart: self.restart,
                restart_sec: Some(self.restart_sec.to_string()),
                timeout_start_sec: self.timeout_start_sec.map(|secs| secs.to_string()),
                timeout_stop_sec: self.timeout_stop_sec.map(|secs| secs.to_string()),
                kill_signal: Some(self.kill_signal.to_string()),
                kill_mode: self.kill_mode,
                send_sigkill: self.send_sigkill,
                umask: self.umask.map(|mask| format!("{mask:04o}")),
                supplementary_groups: Vec::new(),
                service_type: self.oneshot.then(|| "oneshot".to_string()),
                oom_score_adjust: self.oom_score_adjust,
                no_new_privileges: self.no_new_privileges,
                private_tmp: self.private_tmp,
                private_devices: self.private_devices,
                private_network: self.private_network,
                protect_system: self.protect_system.clone(),
                protect_home: self.protect_home.clone(),
                read_write_paths: self.read_write_paths.clone(),
                read_only_paths: self.read_only_paths.clone(),
                inaccessible_paths: self.inaccessible_paths.clone(),
                capability_bounding_set: self.capability_bounding_set.clone(),
                ambient_capabilities: self.ambient_capabilities.clone(),
            },
            resources: crate::config::ResourceLimits {
                memory_low: memory_limit_to_toml(self.resources.memory_low),
                memory_high: memory_limit_to_toml(self.resources.memory_high),
                memory_max: memory_limit_to_toml(self.resources.memory_max),
                cpu_weight: self.resources.cpu_weight,
            },
            environment: self.env.clone(),
            network: self.network.clone(),
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
            peers: self
                .auth
                .as_ref()
                .map(|a| a.peers.clone())
                .unwrap_or_default(),
            impersonation: self
                .auth
                .as_ref()
                .map(|a| a.impersonation.clone())
                .unwrap_or_default(),
        };

        let content = toml::to_string_pretty(&file)?;
        let path = dir.join(format!("{}.toml", self.name));
        fs::write(&path, content)
            .await
            .context("Failed to write JobConfig")
    }
}

fn memory_limit_to_toml(limit: Option<u64>) -> Option<String> {
    limit.map(|bytes| bytes.to_string())
}

fn exec_start_to_toml(command: &str, args: &[String]) -> String {
    std::iter::once(command)
        .chain(args.iter().map(String::as_str))
        .map(quote_exec_word)
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_exec_word(word: &str) -> String {
    if !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | ':' | '='))
    {
        return word.to_string();
    }

    format!("'{}'", word.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::memory_limit_to_toml;

    #[test]
    fn memory_limit_to_toml_preserves_byte_values() {
        assert_eq!(memory_limit_to_toml(None), None);
        assert_eq!(memory_limit_to_toml(Some(0)), Some("0".to_string()));
        assert_eq!(
            memory_limit_to_toml(Some(512 * 1024 * 1024)),
            Some("536870912".to_string())
        );
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
        fs::write(&path, content)
            .await
            .context("Failed to save WorkItem")
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
