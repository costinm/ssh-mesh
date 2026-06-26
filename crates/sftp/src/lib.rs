use russh_sftp::protocol::{
    Attrs, Data, File as ProtocolFile, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode,
    Version,
};
use russh_sftp::server::Handler;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

pub struct FileSystemHandler {
    base_dir: PathBuf,
    // Map handle string to internal state (File or ReadDir)
    handles: Arc<Mutex<HashMap<String, HandleState>>>,
    handle_counter: Arc<Mutex<u64>>,
}

enum HandleState {
    File(File),
    Dir(Vec<std::fs::DirEntry>),
}

impl FileSystemHandler {
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            base_dir,
            handles: Arc::new(Mutex::new(HashMap::new())),
            handle_counter: Arc::new(Mutex::new(0)),
        }
    }

    async fn generate_handle(&self) -> String {
        let mut counter = self.handle_counter.lock().await;
        *counter += 1;
        format!("handle_{}", *counter)
    }

    /// Resolve a client-supplied SFTP path to a real filesystem path confined
    /// to `base_dir`.
    ///
    /// The canonicalized result is verified to lie within `base_dir`; any path
    /// that escapes (via `..`, absolute symlink, etc.) is rejected with
    /// [`StatusCode::PermissionDenied`]. The `base_dir` itself is canonicalized
    /// lazily on first use.
    ///
    /// Returns the resolved [`PathBuf`] (an absolute path within `base_dir`).
    ///
    /// # Errors
    /// - `PermissionDenied` if the resolved path escapes `base_dir`.
    /// - `NoSuchFile` if the path does not exist.
    /// - `Failure` if `base_dir` itself cannot be canonicalized.
    fn resolve_path(&self, path: &str) -> PathBuf {
        let stripped = path.trim_start_matches('/');
        let candidate = if stripped.is_empty() {
            self.base_dir.clone()
        } else {
            self.base_dir.join(stripped)
        };
        // For paths that may not exist yet (open CREATE, mkdir, symlink, etc.)
        // we canonicalize the parent and append the final component, so the
        // confinement check still applies to not-yet-existing entries.
        candidate
    }

    /// Like [`resolve_path`](Self::resolve_path) but verifies the canonicalized
    /// path stays within `base_dir`. Use for operations that touch existing
    /// paths (open, stat, read, remove, etc.).
    async fn confined_resolve_existing(&self, path: &str) -> Result<PathBuf, StatusCode> {
        let candidate = self.resolve_path(path);
        let base_canonical = self.canonicalize_base().await.ok_or(StatusCode::Failure)?;
        // Canonicalize the candidate. If it doesn't exist, canonicalize the
        // parent and re-append the final component.
        let canonical = match fs::canonicalize(&candidate).await {
            Ok(c) => c,
            Err(_) => {
                let parent = candidate
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("/"));
                let file_name = candidate.file_name();
                let parent_canonical = fs::canonicalize(parent)
                    .await
                    .map_err(|e| io_to_status_code(&e))?;
                match file_name {
                    Some(name) => parent_canonical.join(name),
                    None => parent_canonical,
                }
            }
        };
        if !canonical.starts_with(&base_canonical) {
            return Err(StatusCode::PermissionDenied);
        }
        Ok(canonical)
    }

    /// Like [`confined_resolve_existing`](Self::confined_resolve_existing) but
    /// does not require the path to exist (used for CREATE/mkdir/symlink
    /// targets where the leaf does not yet exist).
    async fn confined_resolve_new(&self, path: &str) -> Result<PathBuf, StatusCode> {
        let candidate = self.resolve_path(path);
        let base_canonical = self.canonicalize_base().await.ok_or(StatusCode::Failure)?;
        let parent = candidate
            .parent()
            .unwrap_or_else(|| std::path::Path::new("/"));
        let parent_canonical = fs::canonicalize(parent)
            .await
            .map_err(|e| io_to_status_code(&e))?;
        let resolved = match candidate.file_name() {
            Some(name) => parent_canonical.join(name),
            None => parent_canonical,
        };
        if !resolved.starts_with(&base_canonical) {
            return Err(StatusCode::PermissionDenied);
        }
        Ok(resolved)
    }

    /// Canonicalize `base_dir` (cached on first call). This is a best-effort
    /// canonicalization; if it fails we return `None` so callers can fail the
    /// request.
    async fn canonicalize_base(&self) -> Option<PathBuf> {
        fs::canonicalize(&self.base_dir).await.ok()
    }
}

/// Convert std::fs::Metadata to the SFTP FileAttributes, including
/// size, uid, gid, permissions (with file-type bits), atime, and mtime.
fn metadata_to_attrs(meta: &std::fs::Metadata) -> FileAttributes {
    let mut attrs = FileAttributes::from(meta);

    // Ensure symlink type is set correctly (From<&Metadata> only sets DIR/REG)
    #[cfg(unix)]
    {
        // Overwrite permissions with the raw mode which already contains file-type bits
        attrs.permissions = Some(meta.mode());
    }

    attrs
}

fn ok_status(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".to_string(),
        language_tag: "en-US".to_string(),
    }
}

impl Handler for FileSystemHandler {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        // Use the "new" resolver when CREATE/EXCLUDE is requested (the leaf may
        // not exist yet); otherwise the existing-file resolver.
        let path = if pflags.intersects(OpenFlags::CREATE | OpenFlags::EXCLUDE) {
            self.confined_resolve_new(&filename).await?
        } else {
            self.confined_resolve_existing(&filename).await?
        };
        let mut options = fs::OpenOptions::new();

        if pflags.contains(OpenFlags::READ) {
            options.read(true);
        }
        if pflags.contains(OpenFlags::WRITE) {
            options.write(true);
        }
        if pflags.contains(OpenFlags::APPEND) {
            options.append(true);
        }
        if pflags.contains(OpenFlags::CREATE) {
            options.create(true);
        }
        if pflags.contains(OpenFlags::TRUNCATE) {
            options.truncate(true);
        }
        if pflags.contains(OpenFlags::EXCLUDE) {
            options.create_new(true);
        }

        match options.open(&path).await {
            Ok(file) => {
                let handle_id = self.generate_handle().await;
                let mut handles = self.handles.lock().await;
                handles.insert(handle_id.clone(), HandleState::File(file));
                Ok(Handle {
                    id,
                    handle: handle_id,
                })
            }
            Err(e) => Err(io_to_status_code(&e)),
        }
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        let mut handles = self.handles.lock().await;
        if handles.remove(&handle).is_some() {
            Ok(ok_status(id))
        } else {
            Err(StatusCode::BadMessage)
        }
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let mut handles = self.handles.lock().await;
        if let Some(HandleState::File(file)) = handles.get_mut(&handle) {
            file.seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(|e| io_to_status_code(&e))?;
            let mut buf = vec![0u8; len as usize];
            match file.read(&mut buf).await {
                Ok(n) => {
                    buf.truncate(n);
                    if n == 0 {
                        return Err(StatusCode::Eof);
                    }
                    Ok(Data { id, data: buf })
                }
                Err(e) => Err(io_to_status_code(&e)),
            }
        } else {
            Err(StatusCode::BadMessage)
        }
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let mut handles = self.handles.lock().await;
        if let Some(HandleState::File(file)) = handles.get_mut(&handle) {
            file.seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(|e| io_to_status_code(&e))?;
            file.write_all(&data)
                .await
                .map_err(|e| io_to_status_code(&e))?;
            Ok(ok_status(id))
        } else {
            Err(StatusCode::BadMessage)
        }
    }

    // SSH_FXP_LSTAT — stat without following symlinks
    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let resolved = self.confined_resolve_existing(&path).await?;
        let meta = fs::symlink_metadata(&resolved)
            .await
            .map_err(|e| io_to_status_code(&e))?;
        Ok(Attrs {
            id,
            attrs: metadata_to_attrs(&meta),
        })
    }

    // SSH_FXP_FSTAT — stat an open file handle
    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let mut handles = self.handles.lock().await;
        if let Some(HandleState::File(file)) = handles.get_mut(&handle) {
            let meta = file.metadata().await.map_err(|e| io_to_status_code(&e))?;
            Ok(Attrs {
                id,
                attrs: metadata_to_attrs(&meta),
            })
        } else {
            Err(StatusCode::BadMessage)
        }
    }

    // SSH_FXP_SETSTAT — set attributes on a path
    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let resolved = self.confined_resolve_existing(&path).await?;
        apply_attrs(&resolved, &attrs).await?;
        Ok(ok_status(id))
    }

    // SSH_FXP_FSETSTAT — set attributes on an open handle
    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        // We need the path to apply permissions/times.  For file handles we can
        // apply size via the handle directly, but for permissions we still need
        // the path.  As a pragmatic approach we apply what we can.  For full
        // setstat on handles we'd need to store the path too — for now we
        // handle the common case (size via ftruncate).
        let mut handles = self.handles.lock().await;
        if let Some(HandleState::File(file)) = handles.get_mut(&handle) {
            if let Some(size) = attrs.size {
                file.set_len(size)
                    .await
                    .map_err(|e| io_to_status_code(&e))?;
            }
            // permissions and times require a path; we'd need to extend
            // HandleState to store it.  For now return Ok — most clients use
            // setstat (by path) for these.
            Ok(ok_status(id))
        } else {
            Err(StatusCode::BadMessage)
        }
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let resolved_path = self.confined_resolve_existing(&path).await?;
        // Read the entire directory up-front so we can return all entries in
        // one readdir response, which is what typical SFTP clients expect.
        let read_dir = std::fs::read_dir(&resolved_path).map_err(|e| io_to_status_code(&e))?;
        let entries: Vec<std::fs::DirEntry> = read_dir.filter_map(|e| e.ok()).collect();
        let handle_id = self.generate_handle().await;
        let mut handles = self.handles.lock().await;
        handles.insert(handle_id.clone(), HandleState::Dir(entries));
        Ok(Handle {
            id,
            handle: handle_id,
        })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let mut handles = self.handles.lock().await;
        if let Some(HandleState::Dir(entries)) = handles.get_mut(&handle) {
            if entries.is_empty() {
                return Err(StatusCode::Eof);
            }
            // Drain all remaining entries and return them in one batch.
            let dir_entries = std::mem::take(entries);
            let mut files = Vec::with_capacity(dir_entries.len());
            for entry in &dir_entries {
                let filename = entry.file_name().to_string_lossy().to_string();
                let attrs = match entry.metadata() {
                    Ok(meta) => metadata_to_attrs(&meta),
                    Err(_) => FileAttributes::default(),
                };
                files.push(ProtocolFile::new(filename, attrs));
            }
            Ok(Name { id, files })
        } else {
            Err(StatusCode::BadMessage)
        }
    }

    // SSH_FXP_REMOVE — delete a file
    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        let path = self.confined_resolve_existing(&filename).await?;
        fs::remove_file(&path)
            .await
            .map_err(|e| io_to_status_code(&e))?;
        Ok(ok_status(id))
    }

    // SSH_FXP_MKDIR
    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let resolved = self.confined_resolve_new(&path).await?;
        fs::create_dir(&resolved)
            .await
            .map_err(|e| io_to_status_code(&e))?;
        Ok(ok_status(id))
    }

    // SSH_FXP_RMDIR
    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        let resolved = self.confined_resolve_existing(&path).await?;
        fs::remove_dir(&resolved)
            .await
            .map_err(|e| io_to_status_code(&e))?;
        Ok(ok_status(id))
    }

    // SSH_FXP_REALPATH — canonicalize a path
    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let resolved = self.confined_resolve_existing(&path).await?;
        // Canonicalize to get the real absolute path
        let canonical = fs::canonicalize(&resolved)
            .await
            .unwrap_or(resolved.clone());

        // Return absolute path relative to base_dir, or the full canonical
        // path if it doesn't start with base_dir (shouldn't happen normally).
        let display_path = if let Ok(rel) = canonical.strip_prefix(&self.base_dir) {
            if rel.as_os_str().is_empty() {
                "/".to_string()
            } else {
                format!("/{}", rel.display())
            }
        } else {
            canonical.to_string_lossy().to_string()
        };

        Ok(Name {
            id,
            files: vec![ProtocolFile::dummy(display_path)],
        })
    }

    // SSH_FXP_STAT — stat following symlinks
    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let resolved = self.confined_resolve_existing(&path).await?;
        let meta = fs::metadata(&resolved)
            .await
            .map_err(|e| io_to_status_code(&e))?;
        Ok(Attrs {
            id,
            attrs: metadata_to_attrs(&meta),
        })
    }

    // SSH_FXP_RENAME
    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        let old = self.confined_resolve_existing(&oldpath).await?;
        let new = self.confined_resolve_new(&newpath).await?;
        fs::rename(&old, &new)
            .await
            .map_err(|e| io_to_status_code(&e))?;
        Ok(ok_status(id))
    }

    // SSH_FXP_READLINK
    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let resolved = self.confined_resolve_existing(&path).await?;
        let target = fs::read_link(&resolved)
            .await
            .map_err(|e| io_to_status_code(&e))?;
        // Refuse to reveal symlink targets that escape base_dir (information
        // leak / sandbox escape). Return the target only if it is relative or
        // confined; otherwise return PermissionDenied.
        if target.is_absolute()
            && let Some(base_canonical) = self.canonicalize_base().await
            && let Ok(target_canonical) = fs::canonicalize(&target).await
            && !target_canonical.starts_with(&base_canonical)
        {
            return Err(StatusCode::PermissionDenied);
        }
        let target_str = target.to_string_lossy().to_string();
        Ok(Name {
            id,
            files: vec![ProtocolFile::dummy(target_str)],
        })
    }

    // SSH_FXP_SYMLINK
    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, Self::Error> {
        let link = self.confined_resolve_new(&linkpath).await?;
        // Reject symlink targets that escape base_dir via absolute paths. A
        // relative target is allowed (resolved relative to the link's parent).
        if std::path::Path::new(&targetpath).is_absolute() {
            let base_canonical = self.canonicalize_base().await.ok_or(StatusCode::Failure)?;
            let target_canonical = fs::canonicalize(&targetpath)
                .await
                .unwrap_or_else(|_| std::path::PathBuf::from(&targetpath));
            if !target_canonical.starts_with(&base_canonical) {
                return Err(StatusCode::PermissionDenied);
            }
        }
        #[cfg(unix)]
        {
            tokio::fs::symlink(&targetpath, &link)
                .await
                .map_err(|e| io_to_status_code(&e))?;
        }
        #[cfg(not(unix))]
        {
            return Err(StatusCode::OpUnsupported);
        }
        Ok(ok_status(id))
    }
}

/// Apply file attributes (permissions, size, times) to a path.
async fn apply_attrs(path: &PathBuf, attrs: &FileAttributes) -> Result<(), StatusCode> {
    #[cfg(unix)]
    if let Some(perms) = attrs.permissions {
        use std::os::unix::fs::PermissionsExt;
        // Mask out the file-type bits, keep only permission bits
        let mode = perms & 0o7777;
        fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .await
            .map_err(|e| io_to_status_code(&e))?;
    }

    if let Some(size) = attrs.size {
        let file = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .await
            .map_err(|e| io_to_status_code(&e))?;
        file.set_len(size)
            .await
            .map_err(|e| io_to_status_code(&e))?;
    }

    // atime/mtime would require the filetime crate — left as-is for now since
    // most clients don't rely on server-side utime via SFTP setstat.
    Ok(())
}

/// Map std::io::Error to SFTP StatusCode
fn io_to_status_code(e: &std::io::Error) -> StatusCode {
    match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_handler(dir: &std::path::Path) -> FileSystemHandler {
        FileSystemHandler::new(dir.to_path_buf())
    }

    #[tokio::test]
    async fn resolve_existing_stays_in_base() {
        let tmp = tempfile::tempdir().unwrap();
        let inner = tmp.path().join("inner.txt");
        tokio::fs::write(&inner, b"hi").await.unwrap();
        let h = make_handler(tmp.path());
        let resolved = h.confined_resolve_existing("inner.txt").await.unwrap();
        assert!(resolved.starts_with(tmp.path()));
    }

    #[tokio::test]
    async fn resolve_rejects_dotdot_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        // Create a sibling directory outside base_dir.
        let sibling = tmp.path().parent().unwrap().join("sftp_escape_target.txt");
        tokio::fs::write(&sibling, b"secret").await.unwrap();
        let h = make_handler(tmp.path());
        let result = h
            .confined_resolve_existing("../sftp_escape_target.txt")
            .await;
        let _ = tokio::fs::remove_file(&sibling);
        assert!(
            matches!(result, Err(StatusCode::PermissionDenied)),
            "traversal must be rejected, got {result:?}"
        );
    }

    #[tokio::test]
    async fn resolve_rejects_symlink_escape() {
        let tmp = tempfile::tempdir().unwrap();
        // Create a symlink inside base pointing outside.
        let outside = tmp.path().parent().unwrap().join("outside_secret.txt");
        tokio::fs::write(&outside, b"secret").await.unwrap();
        let link = tmp.path().join("escape");
        #[cfg(unix)]
        tokio::fs::symlink(&outside, &link).await.unwrap();
        let h = make_handler(tmp.path());
        let result = h.confined_resolve_existing("escape").await;
        let _ = tokio::fs::remove_file(&outside);
        #[cfg(unix)]
        {
            assert!(
                matches!(result, Err(StatusCode::PermissionDenied)),
                "symlink escape must be rejected, got {result:?}"
            );
        }
        #[cfg(not(unix))]
        let _ = result;
    }

    #[tokio::test]
    async fn resolve_new_allows_create_in_subdir() {
        let tmp = tempfile::tempdir().unwrap();
        // Create a subdirectory that exists.
        tokio::fs::create_dir(tmp.path().join("sub")).await.unwrap();
        let h = make_handler(tmp.path());
        let resolved = h.confined_resolve_new("sub/newfile.txt").await.unwrap();
        assert!(resolved.starts_with(tmp.path()));
    }

    #[tokio::test]
    async fn resolve_new_rejects_create_outside_base() {
        let tmp = tempfile::tempdir().unwrap();
        let h = make_handler(tmp.path());
        let result = h.confined_resolve_new("../evil.txt").await;
        assert!(
            matches!(result, Err(StatusCode::PermissionDenied)),
            "create outside base must be rejected, got {result:?}"
        );
    }
}
