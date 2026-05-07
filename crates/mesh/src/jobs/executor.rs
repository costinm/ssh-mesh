use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::Command;
use tracing::{debug, error, info};

use crate::protocol::{Request, Response};
use super::config::{JobConfig, WorkItem};

/// Trait for executing scheduled jobs.
#[async_trait]
pub trait JobExecutor: Send + Sync {
    /// Execute a job with its pending work items.
    /// Returns Ok(()) if the job was started successfully.
    async fn execute(&self, job: &JobConfig, work_items: &[WorkItem]) -> Result<()>;
}

/// Executor that spawns jobs directly via standard tokio::process::Command.
/// Useful for standalone apps or tests without a running mesh-init daemon.
pub struct CommandExecutor;

#[async_trait]
impl JobExecutor for CommandExecutor {
    async fn execute(&self, job: &JobConfig, work_items: &[WorkItem]) -> Result<()> {
        info!("CommandExecutor starting job: {}", job.name);
        
        let mut cmd = Command::new(&job.command);
        cmd.args(&job.args);
        
        // Pass environment variables
        for (k, v) in &job.env {
            cmd.env(k, v);
        }

        // Pass work item IDs via env var, or just ignore for simple jobs
        if !work_items.is_empty() {
            let ids: Vec<String> = work_items.iter().map(|w| w.id.clone()).collect();
            cmd.env("MESH_JOB_WORK_ITEMS", ids.join(","));
        }

        match cmd.spawn() {
            Ok(mut child) => {
                let name = job.name.clone();
                tokio::spawn(async move {
                    match child.wait().await {
                        Ok(status) => debug!("Job {} exited with status: {}", name, status),
                        Err(e) => error!("Job {} wait error: {}", name, e),
                    }
                });
                Ok(())
            }
            Err(e) => {
                error!("Failed to spawn job {}: {}", job.name, e);
                Err(anyhow::anyhow!("Failed to spawn job {}: {}", job.name, e))
            }
        }
    }
}

/// Executor that sends a start request over UDS to the mesh-init daemon.
/// External processes spawned this way are isolated, treated as services,
/// and may run as separate users.
pub struct MeshInitExecutor {
    pub socket_path: String,
}

impl MeshInitExecutor {
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self { socket_path: socket_path.into() }
    }
}

#[async_trait]
impl JobExecutor for MeshInitExecutor {
    async fn execute(&self, job: &JobConfig, work_items: &[WorkItem]) -> Result<()> {
        info!("MeshInitExecutor requesting start for job: {}", job.name);
        
        let mut env = job.env.clone();
        if !work_items.is_empty() {
            let ids: Vec<String> = work_items.iter().map(|w| w.id.clone()).collect();
            env.insert("MESH_JOB_WORK_ITEMS".to_string(), ids.join(","));
        }
        
        let request = Request::Start {
            name: job.name.clone(),
            args: job.args.clone(),
            env,
        };

        // Connect and send
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .context("failed to connect to mesh-init socket")?;
        
        let (reader, mut writer) = stream.into_split();
        let request_json = serde_json::to_string(&request)?;
        
        writer.write_all(request_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        drop(writer);

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        
        let response: Response = serde_json::from_str(line.trim())
            .context("failed to parse daemon response")?;
            
        if !response.success {
            let err_msg = response.error.unwrap_or_else(|| "Unknown error".to_string());
            anyhow::bail!("MeshInit daemon failed to start job: {}", err_msg);
        }

        Ok(())
    }
}
