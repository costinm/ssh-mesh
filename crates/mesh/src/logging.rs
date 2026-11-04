//! Shared operational log files, rotation and supervisor output capture.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Access policy for regular operational logs, applied again after rotation.
#[derive(Clone, Copy, Debug, Default)]
pub struct LogFileAccess {
    /// Unix owner and group; unset preserves an existing file's ownership.
    pub owner: Option<(u32, u32)>,
    /// Unix permission bits; unset preserves existing permissions or the umask.
    pub mode: Option<u32>,
}

/// Resolve the common file destination, including the supervised service name.
pub fn log_path(app: &str) -> PathBuf {
    if let Some(path) = std::env::var_os("MESH_LOG_FILE").filter(|s| !s.is_empty()) {
        return PathBuf::from(path);
    }
    let directory = std::env::var_os("MESH_LOG_DIR")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::paths::AppPaths::for_accessible_app(app).logs);
    let name = std::env::var("MESH_SERVICE_NAME").unwrap_or_else(|_| app.to_owned());
    directory.join(format!("{name}.log"))
}

/// Open an operational writer using the common file and total-size limits.
/// Regular files rotate; device destinations remain unrotated. Explicit access
/// is reapplied whenever rotation creates a replacement file. Symlinks are
/// rejected for regular files. Existing directory permissions are preserved.
pub fn open_log_writer(path: PathBuf, access: LogFileAccess) -> io::Result<Box<dyn Write + Send>> {
    if is_special_log_path(&path) {
        let fd = match path.to_str() {
            Some("/dev/stderr") => Some(libc::STDERR_FILENO),
            Some("/dev/stdout") => Some(libc::STDOUT_FILENO),
            _ => None,
        };
        if let Some(fd) = fd {
            let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            if copy < 0 {
                return Err(io::Error::last_os_error());
            }
            return Ok(Box::new(unsafe { File::from_raw_fd(copy) }));
        }
        return Ok(Box::new(
            OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(path)?,
        ));
    }
    let limits = LogRotationLimits::from_env();
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        prune_log_files(parent, &name.to_string_lossy(), limits.max_total_bytes);
    }
    Ok(Box::new(SizeRotatingWriter::open_with_access(
        path, limits, access,
    )?))
}

fn open_regular_log(path: &Path, access: LogFileAccess) -> io::Result<File> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let existed = parent.try_exists()?;
        std::fs::create_dir_all(parent)?;
        if !existed && (access.owner.is_some() || access.mode.is_some()) {
            let dir = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(parent)?;
            apply_access(
                &dir,
                LogFileAccess {
                    owner: access.owner,
                    mode: Some(0o750),
                },
            )?;
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(access.mode.unwrap_or(0o666))
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("log must be a regular file"));
    }
    apply_access(&file, access)?;
    Ok(file)
}

fn apply_access(file: &File, access: LogFileAccess) -> io::Result<()> {
    if let Some((uid, gid)) = access.owner {
        let current = file.metadata()?;
        if (current.uid(), current.gid()) != (uid, gid)
            && unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    if let Some(mode) = access.mode {
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

/// Size limits for log file rotation, read from the environment.
pub(crate) struct LogRotationLimits {
    pub(crate) max_file_bytes: u64,
    pub(crate) max_total_bytes: u64,
}

impl LogRotationLimits {
    pub(crate) fn from_env() -> Self {
        Self {
            max_file_bytes: parse_size_env("MESH_LOG_FILE_MAX_BYTES", 8 * 1024 * 1024),
            max_total_bytes: parse_size_env("MESH_LOG_MAX_TOTAL_BYTES", 64 * 1024 * 1024),
        }
    }
}

/// Parse a byte-count environment variable with optional k/m/g suffixes.
/// Invalid or missing values fall back to `default`.
pub(crate) fn parse_size_env(key: &str, default: u64) -> u64 {
    let Ok(raw) = std::env::var(key) else {
        return default;
    };
    let raw = raw.trim().to_ascii_lowercase();
    let (num, multiplier): (&str, u64) = if raw.ends_with("kib") {
        (raw.strip_suffix("kib").unwrap(), 1024)
    } else if raw.ends_with("mib") {
        (raw.strip_suffix("mib").unwrap(), 1024 * 1024)
    } else if raw.ends_with("gib") {
        (raw.strip_suffix("gib").unwrap(), 1024 * 1024 * 1024)
    } else if raw.ends_with('k') {
        (raw.strip_suffix('k').unwrap(), 1024)
    } else if raw.ends_with('m') {
        (raw.strip_suffix('m').unwrap(), 1024 * 1024)
    } else if raw.ends_with('g') {
        (raw.strip_suffix('g').unwrap(), 1024 * 1024 * 1024)
    } else {
        (raw.as_str(), 1)
    };
    num.trim()
        .parse::<u64>()
        .map(|value| value.saturating_mul(multiplier))
        .unwrap_or(default)
}

/// True for paths that must be opened exactly as-is without rotation,
/// such as `/dev/stderr`, `/dev/null`, or `/dev/console`.
fn is_special_log_path(path: &std::path::Path) -> bool {
    if path.parent() == Some(std::path::Path::new("/dev")) {
        return true;
    }
    match path.symlink_metadata() {
        Ok(metadata) => !metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        Err(_) => false,
    }
}

/// File writer that rotates by size.
///
/// The active file stays under `limits.max_file_bytes`. When it is
/// reached, the active file is renamed to `<file>.1` and existing backups
/// are shifted (`.1` to `.2`, and so on). The oldest backups are removed
/// first so the combined size of the active file and all backups fits in
/// `limits.max_total_bytes` at each rotation. Rotation runs on the
/// non-blocking writer's background thread, so logging never stalls the
/// caller.
pub(crate) struct SizeRotatingWriter {
    path: std::path::PathBuf,
    limits: LogRotationLimits,
    file: Option<std::fs::File>,
    size: u64,
    access: LogFileAccess,
}

impl SizeRotatingWriter {
    #[cfg(test)]
    pub(crate) fn open(
        path: std::path::PathBuf,
        limits: LogRotationLimits,
    ) -> std::io::Result<Self> {
        Self::open_with_access(path, limits, LogFileAccess::default())
    }

    fn open_with_access(
        path: PathBuf,
        mut limits: LogRotationLimits,
        access: LogFileAccess,
    ) -> io::Result<Self> {
        if limits.max_total_bytes > 0 && limits.max_file_bytes > limits.max_total_bytes {
            limits.max_file_bytes = limits.max_total_bytes;
        }
        let file = open_regular_log(&path, access)?;
        let metadata = file.metadata()?;
        let size = metadata.len();
        let access = LogFileAccess {
            owner: Some(access.owner.unwrap_or((metadata.uid(), metadata.gid()))),
            mode: Some(access.mode.unwrap_or(metadata.permissions().mode() & 0o777)),
        };
        let mut writer = Self {
            path,
            limits,
            file: Some(file),
            size,
            access,
        };
        if writer.limits.max_file_bytes > 0 && writer.size >= writer.limits.max_file_bytes {
            // Already at or over the cap from a previous run; start fresh.
            writer.rotate()?;
        }
        Ok(writer)
    }

    fn backup_path(&self, index: usize) -> std::path::PathBuf {
        let name = self.path.file_name().unwrap_or_default().to_string_lossy();
        self.path.with_file_name(format!("{name}.{index}"))
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
        }
        let mut oldest = 0usize;
        let mut total = 0u64;
        for index in 1.. {
            let backup = self.backup_path(index);
            match backup.metadata() {
                Ok(metadata) => {
                    total += metadata.len();
                    oldest = index;
                }
                Err(_) => break,
            }
        }
        // The active file becomes the newest backup, so bound the combined
        // size of all log files at each rotation.
        while oldest > 0 && total + self.size > self.limits.max_total_bytes {
            let path = self.backup_path(oldest);
            let size = path.metadata().map(|metadata| metadata.len()).unwrap_or(0);
            if std::fs::remove_file(&path).is_ok() {
                total = total.saturating_sub(size);
            }
            oldest -= 1;
        }
        for index in (1..=oldest).rev() {
            let _ = std::fs::rename(self.backup_path(index), self.backup_path(index + 1));
        }
        if self.path.exists() {
            std::fs::rename(&self.path, self.backup_path(1))?;
            // An old unbounded console file can already exceed the whole
            // retention budget. Do not retain it until another write arrives.
            if self.limits.max_total_bytes > 0 && self.size > self.limits.max_total_bytes {
                std::fs::remove_file(self.backup_path(1))?;
            }
        }
        let file = open_regular_log(&self.path, self.access)?;
        self.file = Some(file);
        self.size = 0;
        Ok(())
    }
}

impl std::io::Write for SizeRotatingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Keep ordinary event-sized writes intact at a boundary. Only a write
        // larger than the entire cap needs splitting (e.g. bulk console output).
        if self.limits.max_file_bytes > 0
            && self.size > 0
            && buf.len() as u64 <= self.limits.max_file_bytes
            && self.size + buf.len() as u64 > self.limits.max_file_bytes
        {
            self.rotate()?;
        }
        let count = if self.limits.max_file_bytes > 0 {
            (buf.len() as u64).min(self.limits.max_file_bytes.saturating_sub(self.size)) as usize
        } else {
            buf.len()
        };
        if self.limits.max_total_bytes > 0 {
            if let (Some(parent), Some(name)) = (self.path.parent(), self.path.file_name()) {
                let backup_budget = self
                    .limits
                    .max_total_bytes
                    .saturating_sub(self.size + count as u64);
                prune_log_files(parent, &name.to_string_lossy(), backup_budget);
            }
        }
        let Some(file) = self.file.as_mut() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "log file is closed",
            ));
        };
        file.write_all(&buf[..count])?;
        self.size += count as u64;
        if self.limits.max_file_bytes > 0 && self.size >= self.limits.max_file_bytes {
            self.rotate()?;
        }
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

/// Keep historical per-app logs bounded. The active file is retained;
/// oldest rotated files are removed first. Failure is deliberately best
/// effort because logging must never prevent the service from starting.
pub(crate) fn prune_log_files(dir: &std::path::Path, basename: &str, max_bytes: u64) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_string_lossy();
            if name == basename || !name.starts_with(&format!("{basename}.")) {
                return None;
            }
            let metadata = entry.metadata().ok()?;
            Some((path, metadata.len(), metadata.modified().ok()))
        })
        .collect::<Vec<_>>();
    let mut total = files.iter().map(|(_, size, _)| *size).sum::<u64>();
    if total <= max_bytes {
        return;
    }
    files.sort_by_key(|(_, _, modified)| *modified);
    for (path, size, _) in files {
        if total <= max_bytes {
            break;
        }
        if std::fs::remove_file(path).is_ok() {
            total = total.saturating_sub(size);
        }
    }
}

/// Restores the caller's output and drains pending captured output on drop.
/// Keep this guard until supervised children have stopped and tracing is flushed.
pub struct StdioCapture {
    stdout: OwnedFd,
    stderr: OwnedFd,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

fn duplicate_fd(fd: i32) -> io::Result<OwnedFd> {
    // SAFETY: fcntl duplicates the descriptor; ownership belongs to the result.
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}

/// Capture inherited stdout/stderr through a bounded pipe into a shared writer.
///
/// Call before starting other threads or spawning children. Unlike duplicating
/// a regular file onto fd 1/2, the collector retains control of rotation even
/// while long-running children keep their inherited output descriptors open.
/// Errors during setup restore the original output. A write failure falls back
/// to the original stderr, without recursively writing into the capture pipe.
pub fn capture_stdio(mut writer: Box<dyn Write + Send>) -> io::Result<StdioCapture> {
    let stdout = duplicate_fd(libc::STDOUT_FILENO)?;
    let stderr = duplicate_fd(libc::STDERR_FILENO)?;
    let mut fallback = File::from(duplicate_fd(libc::STDERR_FILENO)?);
    let mut pipe = [-1; 2];
    // SAFETY: pipe points to two writable descriptor slots.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut reader = unsafe { File::from_raw_fd(pipe[0]) };
    let output = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let thread = std::thread::Builder::new()
        .name("mesh-console-log".into())
        .spawn(move || {
            let mut buffer = [0u8; 8192];
            let mut drain_budget: usize = 1024 * 1024;
            let mut failed = false;
            loop {
                let finishing = stopping.load(Ordering::Acquire);
                let mut poll = libc::pollfd {
                    fd: reader.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: the reader descriptor remains valid throughout the collector.
                let ready = unsafe { libc::poll(&mut poll, 1, if finishing { 0 } else { 100 }) };
                if ready < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    break;
                }
                if ready == 0 {
                    if finishing {
                        break;
                    }
                    continue;
                }
                let size = match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(size) => size,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                };
                if !failed {
                    if let Err(error) = writer.write_all(&buffer[..size]) {
                        let _ = writeln!(fallback, "mesh: console log write failed: {error}");
                        failed = true;
                    }
                }
                if failed {
                    let _ = fallback.write_all(&buffer[..size]);
                }
                if finishing {
                    drain_budget = drain_budget.saturating_sub(size);
                    if drain_budget == 0 {
                        break;
                    }
                }
            }
            let _ = writer.flush();
        })?;
    let guard = StdioCapture {
        stdout,
        stderr,
        stop,
        thread: Some(thread),
    };
    for target in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: output owns a valid writable pipe endpoint.
        if unsafe { libc::dup2(output.as_raw_fd(), target) } < 0 {
            return Err(io::Error::last_os_error()); // guard restores both descriptors
        }
    }
    Ok(guard)
}

impl Drop for StdioCapture {
    fn drop(&mut self) {
        // SAFETY: both saved descriptors remain owned until this guard is dropped.
        unsafe {
            libc::dup2(self.stdout.as_raw_fd(), libc::STDOUT_FILENO);
            libc::dup2(self.stderr.as_raw_fd(), libc::STDERR_FILENO);
        }
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_legacy_file_is_bounded_on_open_without_another_write() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy.log");
        std::fs::write(&path, vec![b'x'; 1024]).unwrap();
        let _writer = SizeRotatingWriter::open(
            path,
            LogRotationLimits {
                max_file_bytes: 32,
                max_total_bytes: 96,
            },
        )
        .unwrap();
        let size: u64 = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().metadata().unwrap().len())
            .sum();
        assert!(size <= 96);
    }

    #[test]
    fn ordinary_json_events_are_not_split_at_rotation_boundaries() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("events.log");
        let mut writer = SizeRotatingWriter::open(
            path,
            LogRotationLimits {
                max_file_bytes: 10,
                max_total_bytes: 40,
            },
        )
        .unwrap();
        writer.write_all(b"{\"x\":1}\n").unwrap();
        writer.write_all(b"{\"x\":2}\n").unwrap();
        for entry in std::fs::read_dir(directory.path()).unwrap() {
            let contents = std::fs::read_to_string(entry.unwrap().path()).unwrap();
            for line in contents.lines() {
                serde_json::from_str::<serde_json::Value>(line).unwrap();
            }
        }
    }

    #[test]
    fn rotation_preserves_access_and_bounds_oversized_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owned.log");
        let owner = (unsafe { libc::geteuid() }, unsafe { libc::getegid() });
        let access = LogFileAccess {
            owner: Some(owner),
            mode: Some(0o640),
        };
        let mut writer = SizeRotatingWriter::open_with_access(
            path.clone(),
            LogRotationLimits {
                max_file_bytes: 32,
                max_total_bytes: 96,
            },
            access,
        )
        .unwrap();
        writer.write_all(&vec![b'x'; 512]).unwrap();
        writer.write_all(b"tail").unwrap();
        writer.flush().unwrap();
        let mut total = 0;
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let metadata = entry.unwrap().metadata().unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o640);
            assert_eq!((metadata.uid(), metadata.gid()), owner);
            assert!(metadata.len() <= 32);
            total += metadata.len();
        }
        assert!(total <= 96, "retained {total} bytes");
        assert_eq!(std::fs::read(path).unwrap(), b"tail");
    }

    #[test]
    fn existing_permissions_survive_default_writer_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing.log");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let before = path.metadata().unwrap();
        let mut writer = SizeRotatingWriter::open(
            path,
            LogRotationLimits {
                max_file_bytes: 8,
                max_total_bytes: 32,
            },
        )
        .unwrap();
        writer
            .write_all(b"multiple rotations of an existing log")
            .unwrap();
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let metadata = entry.unwrap().metadata().unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(
                (metadata.uid(), metadata.gid()),
                (before.uid(), before.gid())
            );
        }
    }

    #[test]
    fn device_destinations_duplicate_stdio_without_changing_device_permissions() {
        let path = PathBuf::from("/dev/stderr");
        let before = path.symlink_metadata().unwrap().permissions().mode();
        let writer = open_log_writer(
            path.clone(),
            LogFileAccess {
                owner: None,
                mode: Some(0o640),
            },
        )
        .unwrap();
        drop(writer);
        assert_eq!(
            path.symlink_metadata().unwrap().permissions().mode(),
            before
        );
    }
}
