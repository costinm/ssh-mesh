use mesh::ConfigProvider;
use serde_json::Value;
use std::path::PathBuf;
use tracing::debug;

/// File-based ConfigProvider implementation.
///
/// `kind` maps to a subdirectory of `base_dir`.
/// `name` maps to a file within that subdirectory.
/// Probes extensions: `.yaml`, `.json`, `.toml`, then extensionless.
pub struct FileConfigProvider {
    base_dir: PathBuf,
}

impl FileConfigProvider {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }
}

#[async_trait::async_trait]
impl ConfigProvider for FileConfigProvider {
    async fn get(&self, kind: &str, name: &str) -> Option<Value> {
        let dir = self.base_dir.join(kind);

        // Probe for files with known extensions, then extensionless
        let candidates = [
            dir.join(format!("{}.yaml", name)),
            dir.join(format!("{}.yml", name)),
            dir.join(format!("{}.json", name)),
            dir.join(format!("{}.toml", name)),
            dir.join(name),
        ];

        for path in &candidates {
            if path.is_file() {
                debug!("FileConfigProvider loading {:?}", path);
                let builder =
                    config::Config::builder().add_source(config::File::from(path.as_path()));
                match builder.build() {
                    Ok(cfg) => match cfg.try_deserialize::<Value>() {
                        Ok(val) => return Some(val),
                        Err(e) => {
                            tracing::error!("Failed to deserialize {:?}: {}", path, e);
                            return None;
                        }
                    },
                    Err(e) => {
                        tracing::error!("Failed to load config {:?}: {}", path, e);
                        return None;
                    }
                }
            }
        }

        debug!(
            "FileConfigProvider: no config found for kind={}, name={}",
            kind, name
        );
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_config_provider_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let nodes_dir = dir.path().join("nodes");
        std::fs::create_dir_all(&nodes_dir).unwrap();
        std::fs::write(
            nodes_dir.join("myhost.yaml"),
            "name: myhost\nhostname: 10.0.0.1\nport: 2222\nuser: admin\npublic_keys:\n  - ssh-ed25519 AAAAC3...\n",
        )
        .unwrap();

        let provider = FileConfigProvider::new(dir.path().to_path_buf());
        let val = provider.get("nodes", "myhost").await;
        assert!(val.is_some());
        let val = val.unwrap();
        assert_eq!(val["name"], "myhost");
        assert_eq!(val["hostname"], "10.0.0.1");
        assert_eq!(val["port"], 2222);
        assert_eq!(val["user"], "admin");
        assert!(val["public_keys"].is_array());
    }

    #[tokio::test]
    async fn test_file_config_provider_json() {
        let dir = tempfile::tempdir().unwrap();
        let nodes_dir = dir.path().join("nodes");
        std::fs::create_dir_all(&nodes_dir).unwrap();
        std::fs::write(
            nodes_dir.join("server1.json"),
            r#"{"name": "server1", "hostname": "192.168.1.1", "port": 22, "user": "root"}"#,
        )
        .unwrap();

        let provider = FileConfigProvider::new(dir.path().to_path_buf());
        let val = provider.get("nodes", "server1").await;
        assert!(val.is_some());
        let val = val.unwrap();
        assert_eq!(val["name"], "server1");
        assert_eq!(val["port"], 22);
    }

    #[tokio::test]
    async fn test_file_config_provider_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let provider = FileConfigProvider::new(dir.path().to_path_buf());
        let val = provider.get("nodes", "nonexistent").await;
        assert!(val.is_none());
    }
}
