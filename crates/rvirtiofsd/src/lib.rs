use std::path::PathBuf;
use virtiofsd::passthrough::{
    CachePolicy, Config, InodeFileHandlesMode, MigrationMode, MigrationOnError, PassthroughFs,
};

pub fn create_passthrough_fs(root_dir: PathBuf) -> PassthroughFs {
    let config = Config {
        root_dir: root_dir.to_string_lossy().to_string(),
        cache_policy: CachePolicy::Auto,
        inode_file_handles: InodeFileHandlesMode::Prefer,
        entry_timeout: std::time::Duration::from_secs(1),
        attr_timeout: std::time::Duration::from_secs(1),
        readdirplus: true,
        announce_submounts: true,
        migration_mode: MigrationMode::FindPaths,
        migration_on_error: MigrationOnError::Abort,
        ..Config::default()
    };

    PassthroughFs::new(config).expect("Failed to create PassthroughFs")
}

// Re-export some useful types
pub use virtiofsd::passthrough::PassthroughFs as FileSystem;
pub use virtiofsd::server::Server as FuseServer;
