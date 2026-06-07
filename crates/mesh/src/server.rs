use crate::auth::AuthConfig;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::FromRawFd;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info};

pub enum MeshStream {
    Uds(UnixStream),
    Stdio {
        stdin: tokio::io::Stdin,
        stdout: tokio::io::Stdout,
    },
}

impl AsyncRead for MeshStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MeshStream::Uds(s) => Pin::new(s).poll_read(cx, buf),
            MeshStream::Stdio { stdin, .. } => Pin::new(stdin).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MeshStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            MeshStream::Uds(s) => Pin::new(s).poll_write(cx, buf),
            MeshStream::Stdio { stdout, .. } => Pin::new(stdout).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MeshStream::Uds(s) => Pin::new(s).poll_flush(cx),
            MeshStream::Stdio { stdout, .. } => Pin::new(stdout).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MeshStream::Uds(s) => Pin::new(s).poll_shutdown(cx),
            MeshStream::Stdio { stdout, .. } => Pin::new(stdout).poll_shutdown(cx),
        }
    }
}

enum ListenerMode {
    Uds(UnixListener),
    Stdio(bool), // bool is `has_yielded`
}

pub struct MeshListener {
    mode: ListenerMode,
    auth: Option<AuthConfig>,
    current_uid: u32,
}

impl MeshListener {
    pub fn new(
        app_name: &str,
        listen_path: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let auth = AuthConfig::load_for_app(app_name);
        let current_uid = unsafe { libc::getuid() };

        let mode = if let Ok(fd_str) = std::env::var("LISTEN_FD") {
            if let Ok(fd) = fd_str.parse::<i32>() {
                info!("MeshListener: Using activated listener FD {}", fd);
                let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
                std_listener.set_nonblocking(true)?;
                ListenerMode::Uds(UnixListener::from_std(std_listener)?)
            } else {
                return Err("Invalid LISTEN_FD".into());
            }
        } else if let Some(path_str) = listen_path {
            let actual_path = if path_str.starts_with('_') {
                path_str.replacen('_', "\0", 1)
            } else if path_str.starts_with('/') {
                path_str.to_string()
            } else {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                let dir = format!("{}/.run/{}", home, app_name);
                let _ = std::fs::create_dir_all(&dir);
                format!("{}/{}", dir, path_str)
            };

            if !actual_path.starts_with('\0') {
                let path = std::path::Path::new(&actual_path);
                if path.exists() {
                    let _ = std::fs::remove_file(path);
                }
            }
            let listener = UnixListener::bind(&actual_path)?;
            info!("MeshListener: Listening on UDS {:?}", actual_path);

            if !actual_path.starts_with('\0') {
                // Set permissions to 0660
                let mut perms = std::fs::metadata(&actual_path)?.permissions();
                perms.set_mode(0o660);
                std::fs::set_permissions(&actual_path, perms)?;
            }

            ListenerMode::Uds(listener)
        } else {
            info!("MeshListener: Serving over stdin/stdout");
            ListenerMode::Stdio(false)
        };

        Ok(Self {
            mode,
            auth,
            current_uid,
        })
    }

    pub async fn accept(&mut self) -> Result<Option<MeshStream>, Box<dyn std::error::Error>> {
        match &mut self.mode {
            ListenerMode::Uds(listener) => loop {
                let (stream, _) = listener.accept().await?;
                let peer_uid = stream.peer_cred()?.uid();

                let is_authorized = match &self.auth {
                    Some(a) => a.is_uid_authorized(peer_uid, self.current_uid),
                    None => peer_uid == 0 || peer_uid == self.current_uid,
                };

                if is_authorized {
                    return Ok(Some(MeshStream::Uds(stream)));
                } else {
                    error!(
                        "MeshListener: Unauthorized UDS connection from UID {}",
                        peer_uid
                    );
                }
            },
            ListenerMode::Stdio(yielded) => {
                if *yielded {
                    return Ok(None);
                }
                *yielded = true;

                // For stdio mode, mesh-init handles auth checking prior to activation
                // No need to check X_PEER_UID here.
                Ok(Some(MeshStream::Stdio {
                    stdin: tokio::io::stdin(),
                    stdout: tokio::io::stdout(),
                }))
            }
        }
    }
}

pub async fn run_axum_server(
    app_name: &str,
    listen_path: Option<&str>,
    app: axum::Router,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut listener = MeshListener::new(app_name, listen_path)?;

    while let Some(stream) = listener.accept().await? {
        let app_clone = app.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, TowerToHyperService::new(app_clone))
                .with_upgrades()
                .await
            {
                let err_str = err.to_string();
                if !err_str.contains("connection error: not connected")
                    && !err_str.contains("early eof")
                {
                    error!("Error serving HTTP connection: {:?}", err);
                }
            }
        });
    }

    Ok(())
}
