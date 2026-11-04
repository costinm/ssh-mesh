//! Supervisor-specific log location and system-account access policy.

use mesh::logging::{LogFileAccess, StdioCapture};
use std::io;
use std::path::PathBuf;

/// Prepared logging policy. Initialize tracing and capture through mesh's common
/// logging code after setting the directory, and keep the capture guard alive.
pub struct ProcessLogging {
    /// Shared operational log directory.
    pub directory: PathBuf,
    /// System-account ownership and regular-file permissions.
    pub access: LogFileAccess,
    capture_output: bool,
}

impl ProcessLogging {
    /// Capture daemon and inherited child output with common bounded rotation.
    /// Foreground commands retain the caller's output streams.
    pub fn capture(&self) -> io::Result<Option<StdioCapture>> {
        if !self.capture_output {
            return Ok(None);
        }
        let writer = mesh::logging::open_log_writer(
            self.directory.join("mesh-init-console.log"),
            self.access,
        )?;
        mesh::logging::capture_stdio(writer).map(Some)
    }
}

/// Resolve the supervisor's log location and access policy before starting threads.
/// Root uses the system application's logs directory; non-root uses `$HOME/logs`.
/// `MESH_LOG_DIR` overrides the location. No structured file is pre-created:
/// common tracing resolves MESH_LOG_FILE/MESH_SERVICE_NAME and owns that file.
pub fn prepare_process_logging(capture_output: bool) -> io::Result<ProcessLogging> {
    let root = unsafe { libc::geteuid() } == 0;
    let directory = std::env::var_os("MESH_LOG_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            if root {
                mesh::paths::AppPaths::for_app("system").logs
            } else {
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("logs")
            }
        });
    let owner = if root {
        mesh::auth::system_uid()
            .and_then(users::get_user_by_uid)
            .map(|user| (user.uid(), user.primary_group_id()))
    } else {
        None
    };
    Ok(ProcessLogging {
        directory,
        access: LogFileAccess {
            owner,
            mode: Some(0o640),
        },
        capture_output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    #[test]
    fn inherited_output_and_startup_panic_are_saved_without_a_journal() {
        let directory = tempfile::tempdir().unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "logging::tests::logging_child", "--nocapture"])
            .env("MESH_INIT_LOGGING_PROBE", "capture")
            .env("MESH_LOG_DIR", directory.path())
            .env_remove("MESH_LOG_FILE")
            .output()
            .unwrap();
        assert!(!output.status.success());
        let console = fs::read_to_string(directory.path().join("mesh-init-console.log")).unwrap();
        assert!(console.contains("child stdout"), "{console}");
        assert!(console.contains("child stderr"), "{console}");
        assert!(console.contains("startup panic probe"), "{console}");
        let metadata = fs::metadata(directory.path().join("mesh-init.log")).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o640);
    }

    #[test]
    fn foreground_commands_keep_the_callers_output_streams() {
        let directory = tempfile::tempdir().unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "logging::tests::logging_child", "--nocapture"])
            .env("MESH_INIT_LOGGING_PROBE", "foreground")
            .env("MESH_LOG_DIR", directory.path())
            .env_remove("MESH_LOG_FILE")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("child stdout"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("child stderr"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("startup panic probe"));
        assert_eq!(
            directory.path().join("mesh-init-console.log").exists(),
            false
        );
    }

    #[test]
    fn logging_child() {
        if std::env::var_os("MESH_INIT_LOGGING_PROBE").is_none() {
            return;
        }
        let mode = std::env::var("MESH_INIT_LOGGING_PROBE").unwrap();
        let capture = mode != "foreground";
        let logging = prepare_process_logging(capture).unwrap();
        let _capture = logging.capture().unwrap();
        let (_buffer, _trace) =
            mesh::local_trace::init_with_log_access("mesh-init", logging.access);
        tracing::warn!("structured startup proof");
        let status = Command::new("/bin/sh")
            .args(["-c", "echo 'child stdout'; echo 'child stderr' >&2"])
            .status()
            .unwrap();
        assert!(status.success());
        if mode == "rotate" {
            use std::io::Write;
            std::io::stdout().write_all(&vec![b'x'; 64 * 1024]).unwrap();
            eprintln!("last stderr proof");
        }
        panic!("startup panic probe");
    }

    #[test]
    fn captured_console_uses_common_rotation_and_structured_service_name() {
        let directory = tempfile::tempdir().unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "logging::tests::logging_child", "--nocapture"])
            .env("MESH_INIT_LOGGING_PROBE", "rotate")
            .env("MESH_LOG_DIR", directory.path())
            .env("MESH_SERVICE_NAME", "supervisor-alias")
            .env("MESH_LOG_FILE_MAX_BYTES", "512")
            .env("MESH_LOG_MAX_TOTAL_BYTES", "4096")
            .env_remove("MESH_LOG_FILE")
            .output()
            .unwrap();
        assert!(!output.status.success());
        let mut contents = String::new();
        let mut total = 0;
        for entry in fs::read_dir(directory.path()).unwrap() {
            let entry = entry.unwrap();
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with("mesh-init-console.log")
            {
                let metadata = entry.metadata().unwrap();
                assert_eq!(metadata.permissions().mode() & 0o777, 0o640);
                assert!(metadata.len() <= 512);
                total += metadata.len();
                contents.push_str(&fs::read_to_string(entry.path()).unwrap());
            }
        }
        assert!(total <= 4096, "retained {total} console bytes");
        assert!(contents.contains("last stderr proof"));
        assert!(contents.contains("startup panic probe"));
        assert!(directory.path().join("supervisor-alias.log").exists());
        assert!(!directory.path().join("mesh-init.log").exists());
    }

    #[test]
    fn log_symlink_is_rejected_without_touching_its_target() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        fs::write(&target, "preserve").unwrap();
        std::os::unix::fs::symlink(&target, directory.path().join("mesh-init-console.log"))
            .unwrap();
        assert!(
            mesh::logging::open_log_writer(
                directory.path().join("mesh-init-console.log"),
                LogFileAccess::default()
            )
            .is_err()
        );
        assert_eq!(fs::read_to_string(target).unwrap(), "preserve");
    }

    #[test]
    fn existing_log_directory_permissions_are_preserved() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        mesh::logging::open_log_writer(
            directory.path().join("mesh-init-console.log"),
            LogFileAccess::default(),
        )
        .unwrap();
        assert_eq!(
            fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}
