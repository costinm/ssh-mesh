//! Shared application path layout helpers.

use std::ffi::OsString;
use std::path::PathBuf;

/// Standard mutable and packaged paths for one mesh component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    pub app: String,
    pub home: PathBuf,
    pub opt: PathBuf,
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
        Self::for_app_with_env(app, |key| std::env::var_os(key))
    }

    fn for_app_with_env<F>(app: impl Into<String>, mut env: F) -> Self
    where
        F: FnMut(&str) -> Option<OsString>,
    {
        let app = app.into();
        let home = env("MESH_APP_HOME").map(PathBuf::from).unwrap_or_else(|| {
            env("MESH_HOME_BASE")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/home"))
                .join(&app)
        });
        let opt = env("MESH_APP_OPT").map(PathBuf::from).unwrap_or_else(|| {
            env("MESH_OPT_BASE")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/opt"))
                .join(&app)
        });

        Self {
            app,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    fn paths_with(vars: &[(&str, &str)]) -> AppPaths {
        let map: HashMap<&str, &str> = vars.iter().copied().collect();
        AppPaths::for_app_with_env("pmond", |key| map.get(key).map(OsString::from))
    }

    #[test]
    fn default_paths_use_home_and_opt_bases() {
        let paths = paths_with(&[]);
        assert_eq!(paths.home, PathBuf::from("/home/pmond"));
        assert_eq!(paths.run, PathBuf::from("/home/pmond/run"));
        assert_eq!(paths.etc, PathBuf::from("/home/pmond/etc"));
        assert_eq!(paths.files, PathBuf::from("/home/pmond/files"));
        assert_eq!(paths.cache, PathBuf::from("/home/pmond/cache"));
        assert_eq!(paths.opt, PathBuf::from("/opt/pmond"));
        assert_eq!(paths.opt_resources, PathBuf::from("/opt/pmond/resources"));
        assert_eq!(
            paths.control_socket("pmond"),
            PathBuf::from("/home/pmond/run/pmond/control.sock")
        );
    }

    #[test]
    fn base_overrides_keep_app_suffix() {
        let paths = paths_with(&[
            ("MESH_HOME_BASE", "/apex/home"),
            ("MESH_OPT_BASE", "/apex/opt"),
        ]);
        assert_eq!(paths.home, PathBuf::from("/apex/home/pmond"));
        assert_eq!(paths.opt, PathBuf::from("/apex/opt/pmond"));
    }

    #[test]
    fn direct_overrides_replace_app_paths() {
        let paths = paths_with(&[
            ("MESH_APP_HOME", "/data/user/pmond"),
            ("MESH_APP_OPT", "/apex/pmond"),
            ("MESH_HOME_BASE", "/ignored"),
            ("MESH_OPT_BASE", "/ignored"),
        ]);
        assert_eq!(paths.home, PathBuf::from("/data/user/pmond"));
        assert_eq!(paths.opt, PathBuf::from("/apex/pmond"));
    }

    #[test]
    fn resource_dirs_use_explicit_override_or_overlay() {
        let paths = paths_with(&[]);
        assert_eq!(
            paths.resource_dirs_with_env(|_| None),
            vec![
                PathBuf::from("/home/pmond/etc/resources"),
                PathBuf::from("/opt/pmond/resources"),
            ]
        );
        assert_eq!(
            paths.resource_dirs_with_env(|key| {
                (key == "MESH_RES_DIR").then(|| OsString::from("/custom/resources"))
            }),
            vec![PathBuf::from("/custom/resources")]
        );
    }
}
