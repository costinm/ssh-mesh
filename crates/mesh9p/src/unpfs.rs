use {
    crate::{
        error::errno::*,
        srv::{Fid, Filesystem},
        *,
    },
    async_trait::async_trait,
    filetime::FileTime,
    nix::libc::{O_CREAT, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY},
    std::{
        collections::{BTreeMap, BTreeSet},
        hash::{Hash, Hasher},
        io::SeekFrom,
        os::unix::{fs::PermissionsExt, io::FromRawFd},
        path::{Component, Path, PathBuf},
    },
    tokio::{
        fs,
        io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
        sync::{Mutex, RwLock},
    },
    tokio_stream::{wrappers::ReadDirStream, StreamExt},
};

mod utils;
use crate::unpfs::utils::*;

// Some clients will incorrectly set bits in 9p flags that don't make sense.
// For exmaple, the linux 9p kernel client propagates O_DIRECT to TCREATE and TOPEN
// and from there to the server.
// Processes on client machines set O_DIRECT to bypass the cache, but if
// the server uses O_DIRECT in the open or create, then subsequent server
// write and read system calls will fail, as O_DIRECT requires at minimum 512
// byte aligned data, and the data is almost always not aligned.
// While the linux kernel client is arguably broken, we won't be able
// to fix every kernel out there, and this is surely not the only buggy client
// we will see.
// The fix is to enumerate the set of flags we support and then and that with
// the flags received in a TCREATE or TOPEN. This nicely fixes a real problem
// we are seeing with a file system benchmark.
const UNIX_FLAGS: u32 = (O_WRONLY | O_RDONLY | O_RDWR | O_CREAT | O_TRUNC) as u32;

pub struct UnpfsFid {
    vpath: RwLock<PathBuf>,
    file: Mutex<Option<fs::File>>,
}

impl Default for UnpfsFid {
    fn default() -> Self {
        Self {
            vpath: RwLock::new(PathBuf::from("/")),
            file: Mutex::new(None),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Export {
    pub source: PathBuf,
    pub mountpoint: PathBuf,
    pub writable: bool,
}

#[derive(Clone)]
pub struct Unpfs {
    pub exports: Vec<Export>,
}

#[derive(Clone, Debug)]
enum ResolvedPath {
    Real { realpath: PathBuf, writable: bool },
    VirtualDir { virtual_path: PathBuf },
}

impl Unpfs {
    pub fn new(exports: Vec<Export>) -> Result<Self> {
        if exports.is_empty() {
            return Err(error::Error::No(EINVAL));
        }

        Ok(Self { exports })
    }

    fn resolve(&self, vpath: &Path) -> Result<ResolvedPath> {
        let normalized = normalize_virtual_path(vpath)?;
        let mut best: Option<(usize, &Export)> = None;

        for export in &self.exports {
            if has_path_prefix(&normalized, &export.mountpoint) {
                let len = component_count(&export.mountpoint);
                if best.map_or(true, |(best_len, _)| len > best_len) {
                    best = Some((len, export));
                }
            }
        }

        if let Some((_, export)) = best {
            let suffix = strip_path_prefix(&normalized, &export.mountpoint);
            return Ok(ResolvedPath::Real {
                realpath: export.source.join(suffix),
                writable: export.writable,
            });
        }

        if self
            .exports
            .iter()
            .any(|export| has_path_prefix(&export.mountpoint, &normalized))
        {
            return Ok(ResolvedPath::VirtualDir {
                virtual_path: normalized,
            });
        }

        Err(error::Error::No(ENOENT))
    }

    fn child_path(&self, parent: &Path, name: &str) -> Result<PathBuf> {
        if name.contains('/') {
            return Err(error::Error::No(EINVAL));
        }

        let mut path = normalize_virtual_path(parent)?;
        match name {
            "" | "." => {}
            ".." => {
                path.pop();
                if path.as_os_str().is_empty() {
                    path = PathBuf::from("/");
                }
            }
            _ => path.push(name),
        }

        normalize_virtual_path(&path)
    }

    fn direct_virtual_children(&self, parent: &Path) -> BTreeSet<String> {
        let Ok(parent) = normalize_virtual_path(parent) else {
            return BTreeSet::new();
        };
        let parent_len = component_count(&parent);
        let mut children = BTreeSet::new();

        for export in &self.exports {
            if !has_path_prefix(&export.mountpoint, &parent) {
                continue;
            }
            if component_count(&export.mountpoint) <= parent_len {
                continue;
            }
            if let Some(name) = path_components(&export.mountpoint).get(parent_len) {
                children.insert(name.clone());
            }
        }

        children
    }
}

fn normalize_virtual_path(path: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
                if normalized.as_os_str().is_empty() {
                    normalized = PathBuf::from("/");
                }
            }
            Component::Normal(name) => normalized.push(name),
            _ => return Err(error::Error::No(EINVAL)),
        }
    }
    Ok(normalized)
}

fn path_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

fn component_count(path: &Path) -> usize {
    path_components(path).len()
}

fn has_path_prefix(path: &Path, prefix: &Path) -> bool {
    let path_parts = path_components(path);
    let prefix_components = path_components(prefix);
    path_parts.len() >= prefix_components.len()
        && path_parts
            .iter()
            .zip(prefix_components.iter())
            .all(|(path, prefix)| path == prefix)
}

fn strip_path_prefix(path: &Path, prefix: &Path) -> PathBuf {
    path_components(path)
        .into_iter()
        .skip(component_count(prefix))
        .collect()
}

fn virtual_qid(path: &Path) -> Qid {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    Qid {
        typ: QidType::DIR,
        version: 0,
        path: hasher.finish(),
    }
}

fn virtual_stat() -> Stat {
    Stat {
        mode: nix::libc::S_IFDIR as u32 | 0o555,
        uid: 0,
        gid: 0,
        nlink: 2,
        rdev: 0,
        size: 0,
        blksize: 4096,
        blocks: 0,
        atime: Time { sec: 0, nsec: 0 },
        mtime: Time { sec: 0, nsec: 0 },
        ctime: Time { sec: 0, nsec: 0 },
    }
}

async fn node_qid(node: &ResolvedPath) -> Result<Qid> {
    match node {
        ResolvedPath::Real { realpath, .. } => get_qid(realpath).await,
        ResolvedPath::VirtualDir { virtual_path } => Ok(virtual_qid(virtual_path)),
    }
}

fn ensure_writable(node: &ResolvedPath) -> Result<()> {
    match node {
        ResolvedPath::Real { writable, .. } if *writable => Ok(()),
        _ => Err(error::Error::No(EROFS)),
    }
}

#[async_trait]
impl Filesystem for Unpfs {
    type Fid = UnpfsFid;

    async fn rattach(
        &self,
        fid: &Fid<Self::Fid>,
        _afid: Option<&Fid<Self::Fid>>,
        _uname: &str,
        _aname: &str,
        _n_uname: u32,
    ) -> Result<Fcall> {
        {
            let mut vpath = fid.aux.vpath.write().await;
            *vpath = PathBuf::from("/");
        }

        Ok(Fcall::Rattach {
            qid: node_qid(&self.resolve(Path::new("/"))?).await?,
        })
    }

    async fn rwalk(
        &self,
        fid: &Fid<Self::Fid>,
        newfid: &Fid<Self::Fid>,
        wnames: &[String],
    ) -> Result<Fcall> {
        let mut wqids = Vec::new();
        let mut path = {
            let vpath = fid.aux.vpath.read().await;
            vpath.clone()
        };

        for (i, name) in wnames.iter().enumerate() {
            let next_path = self.child_path(&path, name)?;

            let qid = match self.resolve(&next_path) {
                Ok(node) => node_qid(&node).await,
                Err(e) => Err(e),
            };
            let qid = match qid {
                Ok(qid) => qid,
                Err(e) => {
                    if i == 0 {
                        return Err(e);
                    } else {
                        break;
                    }
                }
            };

            path = next_path;
            wqids.push(qid);
        }

        {
            let mut new_vpath = newfid.aux.vpath.write().await;
            *new_vpath = path;
        }

        Ok(Fcall::Rwalk { wqids })
    }

    async fn rgetattr(&self, fid: &Fid<Self::Fid>, req_mask: GetattrMask) -> Result<Fcall> {
        let attr = {
            let vpath = fid.aux.vpath.read().await;
            match self.resolve(&vpath)? {
                ResolvedPath::Real { realpath, .. } => fs::symlink_metadata(realpath).await?,
                ResolvedPath::VirtualDir { .. } => {
                    return Ok(Fcall::Rgetattr {
                        valid: req_mask,
                        qid: virtual_qid(&vpath),
                        stat: virtual_stat(),
                    })
                }
            }
        };

        Ok(Fcall::Rgetattr {
            valid: req_mask,
            qid: qid_from_attr(&attr),
            stat: From::from(attr),
        })
    }

    async fn rsetattr(
        &self,
        fid: &Fid<Self::Fid>,
        valid: SetattrMask,
        stat: &SetAttr,
    ) -> Result<Fcall> {
        let filepath = {
            let vpath = fid.aux.vpath.read().await;
            let node = self.resolve(&vpath)?;
            ensure_writable(&node)?;
            match node {
                ResolvedPath::Real { realpath, .. } => realpath,
                ResolvedPath::VirtualDir { .. } => return Err(error::Error::No(EROFS)),
            }
        };

        if valid.contains(SetattrMask::MODE) {
            fs::set_permissions(&filepath, PermissionsExt::from_mode(stat.mode)).await?;
        }

        if valid.intersects(SetattrMask::UID | SetattrMask::GID) {
            let uid = if valid.contains(SetattrMask::UID) {
                Some(nix::unistd::Uid::from_raw(stat.uid))
            } else {
                None
            };
            let gid = if valid.contains(SetattrMask::GID) {
                Some(nix::unistd::Gid::from_raw(stat.gid))
            } else {
                None
            };
            nix::unistd::chown(&filepath, uid, gid)?;
        }

        if valid.contains(SetattrMask::SIZE) {
            let _ = fs::OpenOptions::new()
                .write(true)
                .create(false)
                .open(&filepath)
                .await?
                .set_len(stat.size)
                .await?;
        }

        if valid.intersects(SetattrMask::ATIME_SET | SetattrMask::MTIME_SET) {
            let attr = fs::metadata(&filepath).await?;
            let atime = if valid.contains(SetattrMask::ATIME_SET) {
                FileTime::from_unix_time(stat.atime.sec as i64, stat.atime.nsec as u32)
            } else {
                FileTime::from_last_access_time(&attr)
            };

            let mtime = if valid.contains(SetattrMask::MTIME_SET) {
                FileTime::from_unix_time(stat.mtime.sec as i64, stat.mtime.nsec as u32)
            } else {
                FileTime::from_last_modification_time(&attr)
            };

            let _ = tokio::task::spawn_blocking(move || {
                filetime::set_file_times(filepath, atime, mtime)
            })
            .await;
        }

        Ok(Fcall::Rsetattr)
    }

    async fn rreadlink(&self, fid: &Fid<Self::Fid>) -> Result<Fcall> {
        let link = {
            let vpath = fid.aux.vpath.read().await;
            match self.resolve(&vpath)? {
                ResolvedPath::Real { realpath, .. } => fs::read_link(realpath).await?,
                ResolvedPath::VirtualDir { .. } => return Err(error::Error::No(EINVAL)),
            }
        };

        Ok(Fcall::Rreadlink {
            target: link.to_string_lossy().into_owned(),
        })
    }

    async fn rreaddir(&self, fid: &Fid<Self::Fid>, off: u64, count: u32) -> Result<Fcall> {
        let mut dirents = DirEntryData::new();

        let vpath = {
            let vpath = fid.aux.vpath.read().await;
            vpath.clone()
        };
        let node = self.resolve(&vpath)?;

        let offset = if off == 0 {
            dirents.push(DirEntry {
                qid: node_qid(&node).await?,
                offset: 0,
                typ: 0,
                name: ".".to_string(),
            });
            let parent = self.child_path(&vpath, "..")?;
            dirents.push(DirEntry {
                qid: node_qid(&self.resolve(&parent)?).await?,
                offset: 1,
                typ: 0,
                name: "..".to_string(),
            });
            off
        } else {
            off - 1
        } as usize;

        let mut entries_by_name: BTreeMap<String, Qid> = BTreeMap::new();

        if let ResolvedPath::Real { realpath, .. } = &node {
            let mut entries = ReadDirStream::new(fs::read_dir(realpath).await?);
            while let Some(entry) = entries.next().await {
                let entry = entry?;
                entries_by_name.insert(
                    entry.file_name().to_string_lossy().into_owned(),
                    qid_from_attr(&entry.metadata().await?),
                );
            }
        }

        for name in self.direct_virtual_children(&vpath) {
            let child = self.child_path(&vpath, &name)?;
            let qid = node_qid(&self.resolve(&child)?).await?;
            entries_by_name.insert(name, qid);
        }

        for (i, (name, qid)) in entries_by_name.into_iter().skip(offset).enumerate() {
            let dirent = DirEntry {
                qid,
                offset: 2 + offset as u64 + i as u64,
                typ: 0,
                name,
            };
            if dirents.size() + dirent.size() > count {
                break;
            }
            dirents.push(dirent);
        }

        Ok(Fcall::Rreaddir { data: dirents })
    }

    async fn rlopen(&self, fid: &Fid<Self::Fid>, flags: u32) -> Result<Fcall> {
        let realpath = {
            let vpath = fid.aux.vpath.read().await;
            match self.resolve(&vpath)? {
                ResolvedPath::Real {
                    realpath, writable, ..
                } => {
                    let oflags = nix::fcntl::OFlag::from_bits_truncate((flags & UNIX_FLAGS) as i32);
                    if !writable
                        && oflags.intersects(
                            nix::fcntl::OFlag::O_WRONLY
                                | nix::fcntl::OFlag::O_RDWR
                                | nix::fcntl::OFlag::O_TRUNC,
                        )
                    {
                        return Err(error::Error::No(EROFS));
                    }
                    realpath
                }
                ResolvedPath::VirtualDir { virtual_path } => {
                    return Ok(Fcall::Rlopen {
                        qid: virtual_qid(&virtual_path),
                        iounit: 0,
                    })
                }
            }
        };

        let qid = get_qid(&realpath).await?;
        if !qid.typ.contains(QidType::DIR) {
            let oflags = nix::fcntl::OFlag::from_bits_truncate((flags & UNIX_FLAGS) as i32);
            let omode = nix::sys::stat::Mode::from_bits_truncate(0);
            let fd = nix::fcntl::open(&realpath, oflags, omode)?;

            {
                let mut file = fid.aux.file.lock().await;
                *file = Some(fs::File::from_std(unsafe {
                    std::fs::File::from_raw_fd(fd)
                }));
            }
        }

        Ok(Fcall::Rlopen { qid, iounit: 0 })
    }

    async fn rlcreate(
        &self,
        fid: &Fid<Self::Fid>,
        name: &str,
        flags: u32,
        mode: u32,
        _gid: u32,
    ) -> Result<Fcall> {
        let path = {
            let vpath = fid.aux.vpath.read().await;
            let node = self.resolve(&vpath)?;
            ensure_writable(&node)?;
            match node {
                ResolvedPath::Real { realpath, .. } => realpath.join(name),
                ResolvedPath::VirtualDir { .. } => return Err(error::Error::No(EROFS)),
            }
        };
        let oflags = nix::fcntl::OFlag::from_bits_truncate((flags & UNIX_FLAGS) as i32);
        let omode = nix::sys::stat::Mode::from_bits_truncate(mode);
        let fd = nix::fcntl::open(&path, oflags, omode)?;

        let qid = get_qid(&path).await?;
        {
            let parent = {
                let vpath = fid.aux.vpath.read().await;
                vpath.clone()
            };
            let mut vpath = fid.aux.vpath.write().await;
            *vpath = self.child_path(&parent, name)?;
        }
        {
            let mut file = fid.aux.file.lock().await;
            *file = Some(fs::File::from_std(unsafe {
                std::fs::File::from_raw_fd(fd)
            }));
        }

        Ok(Fcall::Rlcreate { qid, iounit: 0 })
    }

    async fn rread(&self, fid: &Fid<Self::Fid>, offset: u64, count: u32) -> Result<Fcall> {
        let buf = {
            let mut file = fid.aux.file.lock().await;
            let file = file.as_mut().ok_or_else(|| INVALID_FID!())?;
            file.seek(SeekFrom::Start(offset)).await?;

            let mut buf = create_buffer(count as usize);
            let bytes = file.read(&mut buf[..]).await?;
            buf.truncate(bytes);
            buf
        };

        Ok(Fcall::Rread { data: Data(buf) })
    }

    async fn rwrite(&self, fid: &Fid<Self::Fid>, offset: u64, data: &Data) -> Result<Fcall> {
        let count = {
            let mut file = fid.aux.file.lock().await;
            let file = file.as_mut().ok_or_else(|| INVALID_FID!())?;
            file.seek(SeekFrom::Start(offset)).await?;
            file.write(&data.0).await? as u32
        };

        Ok(Fcall::Rwrite { count })
    }

    async fn rmkdir(
        &self,
        dfid: &Fid<Self::Fid>,
        name: &str,
        _mode: u32,
        _gid: u32,
    ) -> Result<Fcall> {
        let path = {
            let vpath = dfid.aux.vpath.read().await;
            let node = self.resolve(&vpath)?;
            ensure_writable(&node)?;
            match node {
                ResolvedPath::Real { realpath, .. } => realpath.join(name),
                ResolvedPath::VirtualDir { .. } => return Err(error::Error::No(EROFS)),
            }
        };

        fs::create_dir(&path).await?;

        Ok(Fcall::Rmkdir {
            qid: get_qid(&path).await?,
        })
    }

    async fn rrenameat(
        &self,
        olddir: &Fid<Self::Fid>,
        oldname: &str,
        newdir: &Fid<Self::Fid>,
        newname: &str,
    ) -> Result<Fcall> {
        let oldpath = {
            let vpath = olddir.aux.vpath.read().await;
            let node = self.resolve(&vpath)?;
            ensure_writable(&node)?;
            match node {
                ResolvedPath::Real { realpath, .. } => realpath.join(oldname),
                ResolvedPath::VirtualDir { .. } => return Err(error::Error::No(EROFS)),
            }
        };

        let newpath = {
            let vpath = newdir.aux.vpath.read().await;
            let node = self.resolve(&vpath)?;
            ensure_writable(&node)?;
            match node {
                ResolvedPath::Real { realpath, .. } => realpath.join(newname),
                ResolvedPath::VirtualDir { .. } => return Err(error::Error::No(EROFS)),
            }
        };

        fs::rename(&oldpath, &newpath).await?;

        Ok(Fcall::Rrenameat)
    }

    async fn runlinkat(&self, dirfid: &Fid<Self::Fid>, name: &str, _flags: u32) -> Result<Fcall> {
        let path = {
            let vpath = dirfid.aux.vpath.read().await;
            let node = self.resolve(&vpath)?;
            ensure_writable(&node)?;
            match node {
                ResolvedPath::Real { realpath, .. } => realpath.join(name),
                ResolvedPath::VirtualDir { .. } => return Err(error::Error::No(EROFS)),
            }
        };

        match fs::symlink_metadata(&path).await? {
            ref attr if attr.is_dir() => fs::remove_dir(&path).await?,
            _ => fs::remove_file(&path).await?,
        };

        Ok(Fcall::Runlinkat)
    }

    async fn rfsync(&self, fid: &Fid<Self::Fid>) -> Result<Fcall> {
        {
            let mut file = fid.aux.file.lock().await;
            file.as_mut()
                .ok_or_else(|| INVALID_FID!())?
                .sync_all()
                .await?;
        }

        Ok(Fcall::Rfsync)
    }

    async fn rclunk(&self, _: &Fid<Self::Fid>) -> Result<Fcall> {
        Ok(Fcall::Rclunk)
    }

    async fn rstatfs(&self, fid: &Fid<Self::Fid>) -> Result<Fcall> {
        let path = {
            let vpath = fid.aux.vpath.read().await;
            match self.resolve(&vpath)? {
                ResolvedPath::Real { realpath, .. } => realpath,
                ResolvedPath::VirtualDir { .. } => return Err(error::Error::No(EINVAL)),
            }
        };

        //let fs = nix::sys::statvfs::statvfs(&path)?;
        let fs = tokio::task::spawn_blocking(move || nix::sys::statvfs::statvfs(&path))
            .await
            .unwrap()?;

        Ok(Fcall::Rstatfs {
            statfs: From::from(fs),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fs() -> Unpfs {
        Unpfs::new(vec![
            Export {
                source: PathBuf::from("/real/nix"),
                mountpoint: PathBuf::from("/nix"),
                writable: false,
            },
            Export {
                source: PathBuf::from("/real/app"),
                mountpoint: PathBuf::from("/home/app"),
                writable: true,
            },
        ])
        .unwrap()
    }

    #[test]
    fn resolves_exports_and_virtual_parent_directories() {
        let fs = test_fs();

        match fs.resolve(Path::new("/home")).unwrap() {
            ResolvedPath::VirtualDir { virtual_path } => {
                assert_eq!(virtual_path, PathBuf::from("/home"));
            }
            other => panic!("expected virtual /home, got {other:?}"),
        }

        match fs.resolve(Path::new("/home/app/.ssh")).unwrap() {
            ResolvedPath::Real { realpath, writable } => {
                assert_eq!(realpath, PathBuf::from("/real/app/.ssh"));
                assert!(writable);
            }
            other => panic!("expected real app path, got {other:?}"),
        }

        match fs.resolve(Path::new("/nix/store")).unwrap() {
            ResolvedPath::Real { realpath, writable } => {
                assert_eq!(realpath, PathBuf::from("/real/nix/store"));
                assert!(!writable);
            }
            other => panic!("expected real nix path, got {other:?}"),
        }
    }

    #[test]
    fn normalizes_walk_components_without_escaping_root() {
        let fs = test_fs();

        assert_eq!(
            fs.child_path(Path::new("/home/app"), "../app/file")
                .err()
                .unwrap()
                .errno(),
            EINVAL
        );
        assert_eq!(
            fs.child_path(Path::new("/home"), "..").unwrap(),
            PathBuf::from("/")
        );
    }
}
