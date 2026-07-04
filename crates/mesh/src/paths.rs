//! Shared application path layout helpers.

use std::ffi::OsString;
use std::path::PathBuf;

/// Standard mutable and packaged paths for one mesh component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    pub app: String,
    pub home: PathBuf,
    pub opt: PathBuf,
    pub mesh_run_base: PathBuf,
    pub mesh_ipc_dir: PathBuf,
    pub mesh_socket: PathBuf,
    pub etc: PathBuf,
    pub files: PathBuf,
    pub cache: PathBuf,
    pub run: PathBuf,
    pub tmp: PathBuf,
    pub logs: PathBuf,
    pub opt_bin: PathBuf,
    pub opt_etc: PathBuf,
    pub opt_resources: PathBuf,
    pub opt_web: PathBuf,
    pub opt_share: PathBuf,
    pub opt_lib: PathBuf,
}

impl AppPaths {
    /// Resolve standard paths for an app.
    ///
    /// Defaults are `/home/<app>` for mutable state and `/opt/<app>` for
    /// packaged read-only files. `MESH_HOME_BASE` and `MESH_OPT_BASE` change
    /// those bases; `MESH_APP_HOME` and `MESH_APP_OPT` override the final app
    /// paths directly.
    pub fn for_app(app: impl Into<String>) -> Self {
        Self::for_app_with_env_and_context(
            app,
            |key| std::env::var_os(key),
            || std::env::current_dir().ok(),
            current_uid(),
        )
    }

    #[cfg(test)]
    fn for_app_with_env<F>(app: impl Into<String>, mut env: F) -> Self
    where
        F: FnMut(&str) -> Option<OsString>,
    {
        Self::for_app_with_env_and_context(app, &mut env, || None, 0)
    }

    fn for_app_with_env_and_context<F, C>(
        app: impl Into<String>,
        mut env: F,
        current_dir: C,
        uid: u32,
    ) -> Self
    where
        F: FnMut(&str) -> Option<OsString>,
        C: FnOnce() -> Option<PathBuf>,
    {
        let app = app.into();
        let mesh_root = env("MESH_HOME").map(PathBuf::from).or_else(|| {
            if uid == 0 {
                None
            } else {
                Some(
                    current_dir()
                        .unwrap_or_else(|| PathBuf::from("."))
                        .join("mesh"),
                )
            }
        });
        let home = env("MESH_APP_HOME").map(PathBuf::from).unwrap_or_else(|| {
            env("MESH_HOME_BASE")
                .map(PathBuf::from)
                .or_else(|| mesh_root.as_ref().map(|root| root.join("home")))
                .unwrap_or_else(|| PathBuf::from("/home"))
                .join(&app)
        });
        let opt = env("MESH_APP_OPT").map(PathBuf::from).unwrap_or_else(|| {
            env("MESH_OPT_BASE")
                .map(PathBuf::from)
                .or_else(|| mesh_root.as_ref().map(|root| root.join("opt")))
                .unwrap_or_else(|| PathBuf::from("/opt"))
                .join(&app)
        });
        let mesh_run_base = env("MESH_RUN_BASE").map(PathBuf::from).unwrap_or_else(|| {
            mesh_root
                .as_ref()
                .map(|root| root.join("run/mesh"))
                .unwrap_or_else(|| PathBuf::from("/run/mesh"))
        });
        let mesh_ipc_dir = mesh_run_base.join(&app);
        let mesh_socket = mesh_ipc_dir.join("mesh.sock");

        Self {
            app,
            mesh_run_base,
            mesh_ipc_dir,
            mesh_socket,
            etc: home.join("etc"),
            files: home.join("files"),
            cache: home.join("cache"),
            run: home.join("run"),
            tmp: home.join("tmp"),
            logs: home.join("logs"),
            opt_bin: opt.join("bin"),
            opt_etc: opt.join("etc"),
            opt_resources: opt.join("resources"),
            opt_web: opt.join("web"),
            opt_share: opt.join("share"),
            opt_lib: opt.join("lib"),
            home,
            opt,
        }
    }

    /// Runtime directory for a service namespace under the app home.
    pub fn run_dir(&self, name: impl AsRef<str>) -> PathBuf {
        self.run.join(name.as_ref())
    }

    /// Default control socket for a service namespace under the app home.
    pub fn control_socket(&self, name: impl AsRef<str>) -> PathBuf {
        self.run_dir(name).join("control.sock")
    }

    /// Public mesh IPC directory for this app.
    pub fn mesh_ipc_dir(&self) -> &PathBuf {
        &self.mesh_ipc_dir
    }

    /// Public protocol-neutral mesh endpoint for this app.
    pub fn mesh_socket(&self) -> &PathBuf {
        &self.mesh_socket
    }

    /// Mutable resource override directory.
    pub fn mutable_resources(&self) -> PathBuf {
        self.etc.join("resources")
    }

    /// Resource directories in lookup order.
    pub fn resource_dirs(&self) -> Vec<PathBuf> {
        self.resource_dirs_with_env(|key| std::env::var_os(key))
    }

    fn resource_dirs_with_env<F>(&self, mut env: F) -> Vec<PathBuf>
    where
        F: FnMut(&str) -> Option<OsString>,
    {
        if let Some(dir) = env("MESH_RES_DIR") {
            return vec![PathBuf::from(dir)];
        }
        vec![self.mutable_resources(), self.opt_resources.clone()]
    }
}

/// Resolve the base directory that contains app home directories.
pub fn default_home_base() -> PathBuf {
    home_base_with_env_and_context(
        |key| std::env::var_os(key),
        || std::env::current_dir().ok(),
        current_uid(),
    )
}

fn home_base_with_env_and_context<F, C>(mut env: F, current_dir: C, uid: u32) -> PathBuf
where
    F: FnMut(&str) -> Option<OsString>,
    C: FnOnce() -> Option<PathBuf>,
{
    if let Some(base) = env("MESH_HOME_BASE") {
        return PathBuf::from(base);
    }
    if let Some(root) = env("MESH_HOME") {
        return PathBuf::from(root).join("home");
    }
    if uid == 0 {
        PathBuf::from("/home")
    } else {
        current_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("mesh/home")
    }
}

fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    fn paths_with(vars: &[(&str, &str)]) -> AppPaths {
        let map: HashMap<&str, &str> = vars.iter().copied().collect();
        AppPaths::for_app_with_env("demo", |key| map.get(key).map(OsString::from))
    }

    #[test]
    fn root_default_paths_use_system_home_and_opt_bases() {
        let paths = AppPaths::for_app_with_env_and_context("demo", |_| None, || None, 0);
        assert_eq!(paths.home, PathBuf::from("/home/demo"));
        assert_eq!(paths.mesh_run_base, PathBuf::from("/run/mesh"));
        assert_eq!(paths.mesh_ipc_dir, PathBuf::from("/run/mesh/demo"));
        assert_eq!(paths.mesh_socket, PathBuf::from("/run/mesh/demo/mesh.sock"));
        assert_eq!(paths.run, PathBuf::from("/home/demo/run"));
        assert_eq!(paths.etc, PathBuf::from("/home/demo/etc"));
        assert_eq!(paths.files, PathBuf::from("/home/demo/files"));
        assert_eq!(paths.cache, PathBuf::from("/home/demo/cache"));
        assert_eq!(paths.opt, PathBuf::from("/opt/demo"));
        assert_eq!(paths.opt_resources, PathBuf::from("/opt/demo/resources"));
        assert_eq!(
            paths.control_socket("demo"),
            PathBuf::from("/home/demo/run/demo/control.sock")
        );
    }

    #[test]
    fn non_root_default_paths_use_mesh_home_under_cwd() {
        let cwd = PathBuf::from("/workspace");
        let paths =
            AppPaths::for_app_with_env_and_context("demo", |_| None, || Some(cwd.clone()), 1000);
        assert_eq!(paths.home, PathBuf::from("/workspace/mesh/home/demo"));
        assert_eq!(
            paths.mesh_run_base,
            PathBuf::from("/workspace/mesh/run/mesh")
        );
        assert_eq!(
            paths.mesh_socket,
            PathBuf::from("/workspace/mesh/run/mesh/demo/mesh.sock")
        );
        assert_eq!(paths.run, PathBuf::from("/workspace/mesh/home/demo/run"));
        assert_eq!(paths.etc, PathBuf::from("/workspace/mesh/home/demo/etc"));
        assert_eq!(paths.opt, PathBuf::from("/workspace/mesh/opt/demo"));
        assert_eq!(
            paths.control_socket("demo"),
            PathBuf::from("/workspace/mesh/home/demo/run/demo/control.sock")
        );
    }

    #[test]
    fn mesh_home_overrides_root_for_home_and_opt() {
        let paths = paths_with(&[("MESH_HOME", "/tmp/mesh-root")]);
        assert_eq!(paths.home, PathBuf::from("/tmp/mesh-root/home/demo"));
        assert_eq!(paths.opt, PathBuf::from("/tmp/mesh-root/opt/demo"));
        assert_eq!(
            paths.mesh_socket,
            PathBuf::from("/tmp/mesh-root/run/mesh/demo/mesh.sock")
        );
    }

    #[test]
    fn base_overrides_keep_app_suffix() {
        let paths = paths_with(&[
            ("MESH_HOME_BASE", "/apex/home"),
            ("MESH_OPT_BASE", "/apex/opt"),
        ]);
        assert_eq!(paths.home, PathBuf::from("/apex/home/demo"));
        assert_eq!(paths.opt, PathBuf::from("/apex/opt/demo"));
        assert_eq!(paths.mesh_socket, PathBuf::from("/run/mesh/demo/mesh.sock"));
    }

    #[test]
    fn mesh_run_base_overrides_public_ipc_base() {
        let paths = paths_with(&[("MESH_RUN_BASE", "/mesh-ipc")]);
        assert_eq!(paths.mesh_run_base, PathBuf::from("/mesh-ipc"));
        assert_eq!(paths.mesh_ipc_dir, PathBuf::from("/mesh-ipc/demo"));
        assert_eq!(paths.mesh_socket, PathBuf::from("/mesh-ipc/demo/mesh.sock"));
    }

    #[test]
    fn direct_overrides_replace_app_paths() {
        let paths = paths_with(&[
            ("MESH_APP_HOME", "/data/user/demo"),
            ("MESH_APP_OPT", "/apex/demo"),
            ("MESH_HOME_BASE", "/ignored"),
            ("MESH_OPT_BASE", "/ignored"),
        ]);
        assert_eq!(paths.home, PathBuf::from("/data/user/demo"));
        assert_eq!(paths.opt, PathBuf::from("/apex/demo"));
    }

    #[test]
    fn resource_dirs_use_explicit_override_or_overlay() {
        let paths = AppPaths::for_app_with_env_and_context("demo", |_| None, || None, 0);
        assert_eq!(
            paths.resource_dirs_with_env(|_| None),
            vec![
                PathBuf::from("/home/demo/etc/resources"),
                PathBuf::from("/opt/demo/resources"),
            ]
        );
        assert_eq!(
            paths.resource_dirs_with_env(|key| {
                (key == "MESH_RES_DIR").then(|| OsString::from("/custom/resources"))
            }),
            vec![PathBuf::from("/custom/resources")]
        );
    }

    #[test]
    fn default_home_base_uses_mesh_home_for_non_root() {
        let base =
            home_base_with_env_and_context(|_| None, || Some(PathBuf::from("/workspace")), 1000);
        assert_eq!(base, PathBuf::from("/workspace/mesh/home"));
    }
}
