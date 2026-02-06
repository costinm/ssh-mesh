use russh_sftp::protocol::{
    Data, File as ProtocolFile, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode,
    Version,
};
use russh_sftp::server::Handler;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;

pub struct FileSystemHandler {
    base_dir: PathBuf,
    // Map handle string to internal state (File or ReadDir)
    handles: Arc<Mutex<HashMap<String, HandleState>>>,
    handle_counter: Arc<Mutex<u64>>,
}

enum HandleState {
    File(File),
    Dir(fs::ReadDir),
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

    fn resolve_path(&self, path: &str) -> PathBuf {
        // Simple path resolution, preventing directory traversal would be better but this is MVP
        // Assuming path is absolute from the perspective of SFTP root.
        let path = path.trim_start_matches('/');
        if path.is_empty() {
            self.base_dir.clone()
        } else {
            self.base_dir.join(path)
        }
    }
}

// We need to implement Handler trait.
// Note: The trait is async_trait based in the example but we should check if we need #[async_trait] or generic impl.
// The example text showed #[async_trait] for the impl.
// Since russh-sftp re-exports async_trait if feature is on, or uses native async (Rust 1.75+).
// The cargo.toml of `russh` showed `async-trait`. `russh-sftp` also has it.
// We will use #[async_trait] macro if available, or just async fn.
// Based on the example, `russh-sftp` handler methods return `impl Future`. So we don't need #[async_trait] if we write async fn directly in impl block?
// No, trait definition in `russh-sftp` might be using `async_trait` crate or `impl Future`.
// The definition I saw in `handler.rs` was:
/*
    pub trait Handler: Sized {
        fn init(...) -> impl Future<...> + Send { ... }
    }
*/
// It returns `impl Future`. So we can write standard async fn in impl but we need to match the signature.

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
        // Ignore version negotiation for now and just return empty version
        Ok(Version::new())
    }

    async fn open(
        &mut self,
        _id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let path = self.resolve_path(&filename);
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
        // OpenFlags::EXCL not directly supported by tokio OpenOptions but create_new is close
        if pflags.contains(OpenFlags::EXCLUDE) {
            options.create_new(true);
        }

        match options.open(&path).await {
            Ok(file) => {
                let handle_id = self.generate_handle().await;
                let mut handles = self.handles.lock().await;
                handles.insert(handle_id.clone(), HandleState::File(file));
                Ok(Handle {
                    id: _id,
                    handle: handle_id,
                })
            }
            Err(_) => Err(StatusCode::NoSuchFile),
        }
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        let mut handles = self.handles.lock().await;
        if handles.remove(&handle).is_some() {
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "Ok".to_string(),
                language_tag: "en-US".to_string(),
            })
        } else {
            Err(StatusCode::BadMessage)
        }
    }

    async fn read(
        &mut self,
        _id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let mut handles = self.handles.lock().await;
        if let Some(HandleState::File(file)) = handles.get_mut(&handle) {
            if let Err(_) = file.seek(std::io::SeekFrom::Start(offset)).await {
                return Err(StatusCode::Failure);
            }
            let mut buf = vec![0u8; len as usize];
            match file.read(&mut buf).await {
                Ok(n) => {
                    buf.truncate(n);
                    if n == 0 {
                        return Result::<Data, Self::Error>::Err(StatusCode::Eof);
                    }
                    Ok(Data { id: _id, data: buf })
                }
                Err(_) => Err(StatusCode::Failure),
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
            if let Err(_) = file.seek(std::io::SeekFrom::Start(offset)).await {
                return Err(StatusCode::Failure);
            }
            match file.write_all(&data).await {
                Ok(_) => Ok(Status {
                    id,
                    status_code: StatusCode::Ok,
                    error_message: "Ok".to_string(),
                    language_tag: "en-US".to_string(),
                }),
                Err(_) => Err(StatusCode::Failure),
            }
        } else {
            Err(StatusCode::BadMessage)
        }
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let resolved_path = self.resolve_path(&path);
        match fs::read_dir(&resolved_path).await {
            Ok(read_dir) => {
                let handle_id = self.generate_handle().await;
                let mut handles = self.handles.lock().await;
                handles.insert(handle_id.clone(), HandleState::Dir(read_dir));
                Ok(Handle {
                    id,
                    handle: handle_id,
                })
            }
            Err(_) => Err(StatusCode::NoSuchFile),
        }
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let mut handles = self.handles.lock().await;
        if let Some(HandleState::Dir(read_dir)) = handles.get_mut(&handle) {
            match read_dir.next_entry().await {
                Ok(Some(entry)) => {
                    let filename = entry.file_name().to_string_lossy().to_string();
                    let metadata = entry.metadata().await.ok();
                    let attrs = if let Some(meta) = metadata {
                        let mut a = FileAttributes::default();
                        a.size = Some(meta.len());
                        // Helper to convert std Metadata to FileAttributes would be complex, keeping it minimal
                        a
                    } else {
                        FileAttributes::default()
                    };

                    Ok(Name {
                        id,
                        files: vec![ProtocolFile::new(filename, attrs)],
                    })
                }
                Ok(None) => Err(StatusCode::Eof),
                Err(_) => Err(StatusCode::Failure),
            }
        } else {
            Err(StatusCode::BadMessage)
        }
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        // Just echo back providing absolute path
        let resolved = if path.starts_with("/") {
            path
        } else {
            format!("/{}", path)
        };

        Ok(Name {
            id,
            files: vec![ProtocolFile::dummy(resolved)],
        })
    }
}
