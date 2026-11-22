//! Operator-trusted, pre-mounted roots; deliberately not an OCI container runtime.
//!
//! Missing optional mount destinations inside `RootDirectory` are skipped when
//! `RootOverlay` is off. When `RootOverlay` is on, a kernel overlay is mounted
//! ONCE per app at `$APP_HOME/rootfs/merged` and reused by all concurrent
//! sessions. Writes go to `$APP_HOME/rootfs/rw` (upper), never the lower image.
//! A regular-file lock serializes the first mount; concurrent sessions detect
//! the existing mount via /proc/self/mountinfo and bind-mount into it.
use super::*;
use std::path::{Component, PathBuf};

#[derive(Debug, Clone)]
pub(super) struct RootPlan {
    root: CString,
    home: CString,
    app: CString,
    cwd: CString,
    /// Optional subdirs present inside `root` (under the pre-overlay image).
    present: RootDirs,
    overlay: bool,
    /// Resolved numeric app identity for overlay ownership.
    overlay_uid: Option<u32>,
    overlay_gid: Option<u32>,
}

#[derive(Debug, Clone, Default)]
struct RootDirs {
    home: bool,
    proc: bool,
    sys: bool,
    dev: bool,
    nix: bool,
    z: bool,
    z_composefs: bool,
}

fn invalid(message: impl Into<String>) -> ProcessError {
    ProcessError::SpawnFailed(message.into())
}

impl RootPlan {
    pub(super) fn overlay_enabled(&self) -> bool {
        self.overlay
    }

    /// Mount overlay once in daemon namespace before fork.
    /// Creates /home/APP/rootfs/{rw,work,merged}, mounts overlay at merged,
    /// and updates self.root to point to merged.
    pub(super) fn prepare_overlay(&mut self) -> Result<(), ProcessError> {
        use std::os::fd::AsRawFd;

        let home_path = PathBuf::from(
            self.home
                .to_str()
                .map_err(|_| invalid("invalid home path"))?,
        );
        let rootfs = home_path.join("rootfs");
        let upper = rootfs.join("rw");
        let work = rootfs.join("work");
        let merged = rootfs.join("merged");

        // Create directories
        std::fs::create_dir_all(&upper).map_err(|e| ProcessError::SpawnFailed(e.to_string()))?;
        std::fs::create_dir_all(&work).map_err(|e| ProcessError::SpawnFailed(e.to_string()))?;
        std::fs::create_dir_all(&merged).map_err(|e| ProcessError::SpawnFailed(e.to_string()))?;

        // Chown to app uid/gid if set
        if let (Some(uid), Some(gid)) = (self.overlay_uid, self.overlay_gid) {
            unsafe {
                chown_recursive(&rootfs, uid, gid)
                    .map_err(|e| ProcessError::SpawnFailed(e.to_string()))?;
            }
        }

        // Acquire lock
        let lock_path = rootfs.join(".lock");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lock_path)
            .map_err(|e| ProcessError::SpawnFailed(e.to_string()))?;

        let lock_fd = lock_file.as_raw_fd();
        if unsafe { libc::flock(lock_fd, libc::LOCK_EX) } < 0 {
            return Err(ProcessError::SpawnFailed(
                "failed to acquire overlay lock".into(),
            ));
        }

        // Check if overlay already mounted at merged
        let merged_str = merged.to_string_lossy();
        let already_mounted =
            check_mountinfo_for_overlay(&merged_str, &self.root.to_string_lossy())?;

        if !already_mounted {
            // Mount overlay
            let lower = self
                .root
                .to_str()
                .map_err(|_| invalid("invalid root path"))?;
            let opts = format!(
                "lowerdir={},upperdir={},workdir={}\0",
                lower,
                upper.display(),
                work.display()
            );
            let merged_cstr =
                CString::new(merged_str.as_bytes()).map_err(|_| invalid("invalid merged path"))?;

            unsafe {
                if mount_checked(
                    cstr(b"overlay\0"),
                    merged_cstr.as_ptr(),
                    cstr(b"overlay\0"),
                    0,
                    opts.as_ptr().cast(),
                )
                .is_err()
                {
                    libc::flock(lock_fd, libc::LOCK_UN);
                    return Err(ProcessError::SpawnFailed("failed to mount overlay".into()));
                }
            }
        }

        // Release lock and close fd
        unsafe {
            libc::flock(lock_fd, libc::LOCK_UN);
        }
        drop(lock_file);

        // Update self.root to merged path
        self.root =
            CString::new(merged_str.as_bytes()).map_err(|_| invalid("invalid merged path"))?;

        Ok(())
    }

    pub(super) fn build(config: &AppConfig) -> Result<Option<Self>, ProcessError> {
        let Some(root) = &config.root_directory else {
            return Ok(None);
        };
        path_to_cstring(root, "RootDirectory")?;
        if Path::new(root)
            .components()
            .any(|c| c == Component::ParentDir)
        {
            return Err(invalid("RootDirectory must not contain '..'"));
        }
        crate::config::validate_cgroup_name(&config.name).map_err(invalid)?;
        let root = std::fs::canonicalize(root)?;
        if root == Path::new("/") || !root.is_dir() {
            return Err(invalid("RootDirectory must be a directory other than /"));
        }
        // Only RootDirectory itself must exist as a real directory. Optional
        // mount destinations inside are probed and skipped when absent; a
        // non-directory (regular file, symlink) at a mount target also skips
        // that mount rather than silently following the link outside the root.
        let real_dir = |rel: &str| -> bool {
            let p = root.join(rel);
            std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir())
        };
        let present = RootDirs {
            home: real_dir("home"),
            proc: real_dir("proc"),
            sys: real_dir("sys"),
            dev: real_dir("dev"),
            nix: real_dir("nix"),
            z: real_dir("z"),
            z_composefs: real_dir("z/composefs"),
        };
        let home = std::fs::canonicalize(mesh::paths::AppPaths::for_app(&config.name).home)?;
        if !home.is_dir() {
            return Err(invalid("application home must be a directory"));
        }
        let cwd = config
            .working_directory
            .as_deref()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("/home/{}", config.name));
        let cwd = path_to_cstring(&cwd, "WorkingDirectory")?;
        // Overlay no longer requires /home in the lower image: the merged
        // view will create /home (and /home/APP) on demand in upper.
        Ok(Some(Self {
            root: path_to_cstring(&root.to_string_lossy(), "RootDirectory")?,
            home: path_to_cstring(&home.to_string_lossy(), "application home")?,
            app: CString::new(config.name.as_bytes()).map_err(|_| invalid("invalid app name"))?,
            cwd,
            present,
            overlay: config.root_overlay,
            overlay_uid: config.uid,
            overlay_gid: config.gid,
        }))
    }

    /// Run only after CLONE_NEWNS and MS_PRIVATE, before dropping identity.
    pub(super) unsafe fn enter(&self) -> std::io::Result<()> {
        unsafe {
            let base = PathBuf::from(self.root.to_str().map_err(std::io::Error::other)?);
            let target = |p: &str| -> std::io::Result<CString> {
                CString::new(base.join(p).as_os_str().as_encoded_bytes())
                    .map_err(std::io::Error::other)
            };
            // Mark inherited descriptors CLOEXEC, including host directory FDs.
            // Authorized activation descriptors are explicitly installed later.
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            bind_tree(&self.root, &self.root, !self.overlay)?;
            // Overlay is already mounted in daemon namespace by prepare_overlay().
            // self.root points to the merged view. Child inherits it via mount
            // namespace copy from the daemon. No per-session overlay mount needed.
            let need_or_overlay = |rel: &str| -> bool {
                if self.overlay {
                    true
                } else {
                    match rel {
                        "home" => self.present.home,
                        "proc" => self.present.proc,
                        "sys" => self.present.sys,
                        "dev" => self.present.dev,
                        "nix" => self.present.nix,
                        "z" => self.present.z,
                        "z/composefs" => self.present.z_composefs,
                        _ => false,
                    }
                }
            };
            if need_or_overlay("home") {
                ensure_dir(target("home")?.as_ptr())?;
                mount_tmpfs(target("home")?.as_ptr(), b"mode=0755,size=1m\0")?;
            }
            if need_or_overlay("z") {
                ensure_dir(target("z")?.as_ptr())?;
                mount_tmpfs(target("z")?.as_ptr(), b"mode=0755,size=1m\0")?;
            }
            if need_or_overlay("home") {
                let home = target(&format!("home/{}", self.app.to_string_lossy()))?;
                ensure_dir(home.as_ptr())?;
                bind_tree(&self.home, &home, false)?;
            }
            if need_or_overlay("nix") {
                let source = CString::new("/nix").map_err(std::io::Error::other)?;
                let dest = target("nix")?;
                ensure_dir(dest.as_ptr())?;
                bind_tree(&source, &dest, true)?;
            }
            if need_or_overlay("z/composefs") {
                let source = CString::new("/z/composefs").map_err(std::io::Error::other)?;
                let dest = target("z/composefs")?;
                ensure_dir(dest.as_ptr())?;
                bind_tree(&source, &dest, true)?;
            }
            if need_or_overlay("sys") {
                let source = CString::new("/sys").map_err(std::io::Error::other)?;
                let dest = target("sys")?;
                ensure_dir(dest.as_ptr())?;
                bind_tree(&source, &dest, true)?;
            }
            if need_or_overlay("proc") {
                let dest = target("proc")?;
                ensure_dir(dest.as_ptr())?;
                mount_checked(
                    cstr(b"proc\0"),
                    dest.as_ptr(),
                    cstr(b"proc\0"),
                    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RDONLY,
                    std::ptr::null(),
                )?;
            }
            if need_or_overlay("dev") {
                let dev = target("dev")?;
                ensure_dir(dev.as_ptr())?;
                mount_checked(
                    cstr(b"tmpfs\0"),
                    dev.as_ptr(),
                    cstr(b"tmpfs\0"),
                    libc::MS_NOSUID,
                    cstr(b"mode=0755,size=1m\0").cast(),
                )?;
                for name in ["null", "zero", "full", "random", "urandom", "tty"] {
                    let dest = target(&format!("dev/{name}"))?;
                    let fd = libc::open(
                        dest.as_ptr(),
                        libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC,
                        0o666,
                    );
                    if fd < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    libc::close(fd);
                    bind_tree(
                        &CString::new(format!("/dev/{name}")).map_err(std::io::Error::other)?,
                        &dest,
                        false,
                    )?;
                }
                let pts = target("dev/pts")?;
                ensure_dir(pts.as_ptr())?;
                mount_checked(
                    cstr(b"devpts\0"),
                    pts.as_ptr(),
                    cstr(b"devpts\0"),
                    libc::MS_NOSUID | libc::MS_NOEXEC,
                    cstr(b"newinstance,ptmxmode=0666,mode=0620\0").cast(),
                )?;
                if libc::symlink(cstr(b"pts/ptmx\0"), target("dev/ptmx")?.as_ptr()) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if libc::chroot(self.root.as_ptr()) < 0 || libc::chdir(cstr(b"/\0")) < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub(super) unsafe fn chdir(&self) -> std::io::Result<()> {
        if unsafe { libc::chdir(self.cwd.as_ptr()) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Check /proc/self/mountinfo to see if an overlay is already mounted at the given path.
/// Validates that the existing overlay has the correct lower and upper directories.
fn check_mountinfo_for_overlay(mount_point: &str, lower_dir: &str) -> Result<bool, ProcessError> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|e| ProcessError::SpawnFailed(format!("failed to read mountinfo: {}", e)))?;

    let upper_dir = format!(
        "{}/rootfs/rw",
        PathBuf::from(mount_point)
            .parent()
            .ok_or_else(|| ProcessError::SpawnFailed("invalid mount point".into()))?
            .display()
    );

    for line in mountinfo.lines() {
        // mountinfo format: mount-id parent-id major:minor root mount-point options optional-fields - fstype source super-options
        // We need to find lines where mount-point matches and fstype is overlay
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        // Find the separator "-"
        let sep_pos = parts.iter().position(|&p| p == "-");
        let Some(sep) = sep_pos else { continue };

        if sep + 2 >= parts.len() {
            continue;
        }

        let fstype = parts[sep + 1];
        let super_options = parts.get(sep + 3).unwrap_or(&"");

        // Check if this is our mount point (field 4, 0-indexed)
        let mp = parts[4];
        if mp != mount_point {
            continue;
        }

        // Check if it's an overlay
        if fstype != "overlay" {
            continue;
        }

        // Parse super options to validate lowerdir and upperdir
        // Format: lowerdir=...,upperdir=...,workdir=...
        let has_lower = super_options.contains(&format!("lowerdir={}", lower_dir));
        let has_upper = super_options.contains(&format!("upperdir={}", upper_dir));

        if has_lower && has_upper {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Create a directory only if it does not already exist; non-directory
/// existing entries are rejected. Under overlay, mkdir writes to upper.
unsafe fn ensure_dir(path: *const libc::c_char) -> std::io::Result<()> {
    unsafe {
        if libc::mkdir(path, 0o755) < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EEXIST) {
                Ok(())
            } else {
                Err(e)
            }
        } else {
            Ok(())
        }
    }
}

unsafe fn chown_recursive(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::unix::fs::chown;
    chown(path, Some(uid), Some(gid))?;
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            unsafe { chown_recursive(&entry.path(), uid, gid)? };
        }
    }
    Ok(())
}

unsafe fn bind_tree(source: &CString, target: &CString, readonly: bool) -> std::io::Result<()> {
    unsafe {
        mount_checked(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )?;
        if readonly {
            // mount_setattr recursively covers nested mounts (e.g. /nix/store).
            // Older kernels fail closed rather than silently leaving children RW.
            #[repr(C)]
            struct Attr {
                set: u64,
                clear: u64,
                propagation: u64,
                userns: u64,
            }
            let attr = Attr {
                set: 1,
                clear: 0,
                propagation: 0,
                userns: 0,
            };
            if libc::syscall(
                libc::SYS_mount_setattr,
                libc::AT_FDCWD,
                target.as_ptr(),
                0x8000u32,
                &attr,
                std::mem::size_of::<Attr>(),
            ) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_directory_config_validation_and_compatibility() {
        for bad in ["relative", "/root/../other"] {
            let text = format!("[Service]\nExecStart='/bin/true'\nRootDirectory='{bad}'");
            assert!(mesh::config::parse_service(&text, Some("demo")).is_err());
        }
        let old = mesh::config::parse_service(
            "[Service]\nExecStart='/bin/true'\nWorkingDirectory='/tmp'",
            Some("demo"),
        )
        .unwrap();
        assert_eq!(old.working_directory.as_deref(), Some("/tmp"));
        assert!(old.root_directory.is_none());
        assert!(!build_sandbox_plan(&old).unwrap().needs_mount_namespace());
    }

    #[test]
    fn root_overlay_requires_root_directory() {
        let text = "[Service]\nExecStart='/bin/true'\nRootOverlay=true";
        let err = mesh::config::parse_service(&text, Some("demo")).unwrap_err();
        assert!(
            err.to_string()
                .contains("RootOverlay requires RootDirectory")
        );
    }

    #[test]
    fn root_directory_missing_subdirs_builds_plan() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let home = base.join("homes/demo");
        std::fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("MESH_HOME_BASE", base.join("homes"));
            std::env::set_var("MESH_RUN_BASE", base.join("run"));
        }
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let mut config = AppConfig {
            name: "demo".into(),
            root_directory: Some(root.display().to_string()),
            ..Default::default()
        };
        // No /home etc inside root: build should succeed and record them absent.
        let plan = RootPlan::build(&config).unwrap().unwrap();
        assert!(!plan.present.home);
        assert!(!plan.present.proc);
        assert!(!plan.present.z);
        // Symlink at a mount target is skipped (not a real dir), not an error.
        std::os::unix::fs::symlink("/home", root.join("home")).unwrap();
        let plan = RootPlan::build(&config).unwrap().unwrap();
        assert!(!plan.present.home);
        // Missing root itself still fails.
        config.root_directory = Some("/definitely-missing-mesh-root".into());
        assert!(RootPlan::build(&config).is_err());
    }

    #[test]
    fn root_overlay_allows_missing_home_in_lower() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let home = base.join("homes/demo");
        std::fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("MESH_HOME_BASE", base.join("homes"));
            std::env::set_var("MESH_RUN_BASE", base.join("run"));
        }
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        // No /home in lower; overlay should still build.
        let config = AppConfig {
            name: "demo".into(),
            root_directory: Some(root.display().to_string()),
            root_overlay: true,
            ..Default::default()
        };
        let plan = RootPlan::build(&config).unwrap().unwrap();
        assert!(plan.overlay);
        assert!(!plan.present.home);
    }

    /// Run explicitly in a disposable user/mount/PID namespace.
    #[test]
    #[ignore = "requires namespace mount capabilities; see CONFIG.md"]
    fn root_directory_namespace_integration() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let root = base.join("root");
        for dir in ["bin", "etc"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::copy("/bin/busybox", root.join("bin/sh")).unwrap();
        std::fs::copy("/bin/busybox", root.join("bin/busybox")).unwrap();
        let home = base.join("homes/demo");
        std::fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("MESH_HOME_BASE", base.join("homes"));
            std::env::set_var("MESH_RUN_BASE", base.join("run"));
        }
        let outside = base.join("host-secret");
        std::fs::write(&outside, "host-only").unwrap();
        let parent_namespace = std::fs::read_link("/proc/self/ns/mnt").unwrap();
        let mut config = AppConfig {
            name: "demo".into(),
            command: "/bin/sh".into(),
            root_directory: Some(root.display().to_string()),
            working_directory: Some("/".into()),
            no_new_privileges: true,
            capability_bounding_set: Some(Vec::new()),
            ..Default::default()
        };
        // Fixture omits /home /proc /sys /dev /nix /z on purpose: the launch
        // must still succeed and the host root must not leak through. Without
        // overlay, missing dirs are skipped.
        let script = format!(
            "test \"$PWD\" = / && \
             test ! -e '{}' && test ! -e /home && \
             test \"$(/bin/busybox readlink /proc/self/ns/mnt)\" != '{}' && \
             ! test -d /proc && ! test -d /dev && ! test -d /nix && ! test -d /z",
            outside.display(),
            parent_namespace.display(),
        );
        config.args = vec!["-c".into(), script.clone()];
        let (pid, _) = spawn_process(&config, "/nonexistent-cgroup", None).unwrap();
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid as i32, &mut status, 0) },
            pid as i32
        );
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "no-overlay missing mounts skip"
        );
        assert!(outside.is_file());
        config.command = "/bin/definitely-absent".into();
        assert!(spawn_process(&config, "/nonexistent-cgroup", None).is_err());
    }

    /// Overlay integration: shared upper, concurrent sessions see each other's writes.
    #[test]
    #[ignore = "requires namespace mount capabilities; see CONFIG.md"]
    fn root_overlay_namespace_integration() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let root = base.join("root");
        for dir in ["bin", "etc"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::copy("/bin/busybox", root.join("bin/sh")).unwrap();
        std::fs::copy("/bin/busybox", root.join("bin/busybox")).unwrap();
        std::fs::write(root.join("etc/readonly"), "lower-value").unwrap();
        let home = base.join("homes/demo");
        std::fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("MESH_HOME_BASE", base.join("homes"));
            std::env::set_var("MESH_RUN_BASE", base.join("run"));
        }
        let mut config = AppConfig {
            name: "demo".into(),
            command: "/bin/sh".into(),
            root_directory: Some(root.display().to_string()),
            root_overlay: true,
            working_directory: Some("/home/demo".into()),
            no_new_privileges: true,
            capability_bounding_set: Some(Vec::new()),
            ..Default::default()
        };
        // First launch: creates overlay, writes to upper.
        let script = "echo first-write > /etc/shared && cat /etc/shared";
        config.args = vec!["-c".into(), script.to_string()];
        let (pid1, _) = spawn_process(&config, "/nonexistent-cgroup", None).unwrap();
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid1 as i32, &mut status, 0) },
            pid1 as i32
        );
        assert_eq!(libc::WEXITSTATUS(status), 0);
        // Verify lower unchanged.
        assert_eq!(
            std::fs::read_to_string(root.join("etc/readonly")).unwrap(),
            "lower-value",
            "lower must remain unchanged"
        );
        // Verify no missing dirs in lower.
        assert!(!root.join("proc").exists());
        assert!(!root.join("dev").exists());
        assert!(!root.join("home").exists());
        // Verify upper has the write.
        let upper_file = home.join("rootfs/rw/etc/shared");
        assert!(upper_file.exists());
        assert_eq!(
            std::fs::read_to_string(&upper_file).unwrap().trim(),
            "first-write"
        );
        // Verify missing dirs created in upper.
        assert!(home.join("rootfs/rw/proc").exists());
        assert!(home.join("rootfs/rw/dev").exists());
        assert!(home.join("rootfs/rw/home").exists());
        // Second launch (sequential): reuses upper, sees first write.
        config.args = vec!["-c".into(), "cat /etc/shared".into()];
        let (pid2, _) = spawn_process(&config, "/nonexistent-cgroup", None).unwrap();
        assert_eq!(
            unsafe { libc::waitpid(pid2 as i32, &mut status, 0) },
            pid2 as i32
        );
        assert_eq!(libc::WEXITSTATUS(status), 0);
        // Third launch: writes second value.
        config.args = vec![
            "-c".into(),
            "echo second-write >> /etc/shared && cat /etc/shared".into(),
        ];
        let (pid3, _) = spawn_process(&config, "/nonexistent-cgroup", None).unwrap();
        assert_eq!(
            unsafe { libc::waitpid(pid3 as i32, &mut status, 0) },
            pid3 as i32
        );
        assert_eq!(libc::WEXITSTATUS(status), 0);
        // Verify both writes in upper.
        let content = std::fs::read_to_string(upper_file).unwrap();
        assert!(content.contains("first-write"));
        assert!(content.contains("second-write"));
    }

    /// True concurrency test: two sessions run simultaneously and see each other's writes.
    #[test]
    #[ignore = "requires namespace mount capabilities; see CONFIG.md"]
    fn root_overlay_concurrent_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let root = base.join("root");
        for dir in ["bin", "etc"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::copy("/bin/busybox", root.join("bin/sh")).unwrap();
        std::fs::copy("/bin/busybox", root.join("bin/busybox")).unwrap();
        let home = base.join("homes/demo");
        std::fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("MESH_HOME_BASE", base.join("homes"));
            std::env::set_var("MESH_RUN_BASE", base.join("run"));
        }
        let mut config = AppConfig {
            name: "demo".into(),
            command: "/bin/sh".into(),
            root_directory: Some(root.display().to_string()),
            root_overlay: true,
            working_directory: Some("/home/demo".into()),
            no_new_privileges: true,
            capability_bounding_set: Some(Vec::new()),
            ..Default::default()
        };
        // Session 1: writes and sleeps to allow session 2 to run concurrently.
        config.args = vec![
            "-c".into(),
            "echo session1 > /etc/concurrent && sleep 0.1 && cat /etc/concurrent".into(),
        ];
        let (pid1, _) = spawn_process(&config, "/nonexistent-cgroup", None).unwrap();
        // Session 2: starts shortly after, writes and reads.
        std::thread::sleep(std::time::Duration::from_millis(50));
        config.args = vec![
            "-c".into(),
            "echo session2 >> /etc/concurrent && cat /etc/concurrent".into(),
        ];
        let (pid2, _) = spawn_process(&config, "/nonexistent-cgroup", None).unwrap();
        // Wait for both to complete.
        let mut status1 = 0;
        let mut status2 = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid1 as i32, &mut status1, 0) },
            pid1 as i32
        );
        assert_eq!(
            unsafe { libc::waitpid(pid2 as i32, &mut status2, 0) },
            pid2 as i32
        );
        assert_eq!(libc::WEXITSTATUS(status1), 0);
        assert_eq!(libc::WEXITSTATUS(status2), 0);
        // Verify both writes are in upper.
        let upper_file = home.join("rootfs/rw/etc/concurrent");
        assert!(upper_file.exists());
        let content = std::fs::read_to_string(upper_file).unwrap();
        assert!(
            content.contains("session1"),
            "session1 write must be visible"
        );
        assert!(
            content.contains("session2"),
            "session2 write must be visible"
        );
    }

    /// Exercise PTY branch.
    #[test]
    #[ignore = "requires namespace mount capabilities; see CONFIG.md"]
    fn root_directory_pty_integration() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let root = base.join("root");
        for dir in ["home/demo", "bin", "etc"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::copy("/bin/busybox", root.join("bin/sh")).unwrap();
        std::fs::copy("/bin/busybox", root.join("bin/busybox")).unwrap();
        let home = base.join("homes/demo");
        std::fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("MESH_HOME_BASE", base.join("homes"));
            std::env::set_var("MESH_RUN_BASE", base.join("run"));
        }
        let mut config = AppConfig {
            name: "demo".into(),
            command: "/bin/sh".into(),
            root_directory: Some(root.display().to_string()),
            working_directory: Some("/home/demo".into()),
            no_new_privileges: true,
            capability_bounding_set: Some(Vec::new()),
            ..Default::default()
        };
        let mut master = -1;
        let mut slave = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let _master = unsafe { std::os::fd::OwnedFd::from_raw_fd(master) };
        let slave = unsafe { std::os::fd::OwnedFd::from_raw_fd(slave) };
        config.args = vec![
            "-c".into(),
            "test -t 0 && test -t 1 && test -t 2 && test \"$PWD\" = /home/demo".into(),
        ];
        let (pid, _) = spawn_process(
            &config,
            "/nonexistent-cgroup",
            Some(ActivationFd::Pty(slave)),
        )
        .unwrap();
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid as i32, &mut status, 0) },
            pid as i32
        );
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
}
