use axum::Router;
use std::os::unix::fs::PermissionsExt;
use tokio::net::UnixListener;
use tracing::{error, info};

/// Run a HTTP server over UDS, verifying peer identity.
pub async fn run_uds_server(
    app: Router,
    path: &str,
    authorized_uid: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    info!("MeshApp HTTP UDS server listening on {}", path);

    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o666);
    std::fs::set_permissions(path, perms)?;

    let current_uid = unsafe { libc::getuid() };

    loop {
        let (stream, _) = listener.accept().await?;
        let peer_cred = stream.peer_cred()?;
        let peer_uid = peer_cred.uid();

        let is_authorized = peer_uid == 0
            || peer_uid == current_uid
            || (authorized_uid.is_some() && authorized_uid == Some(peer_uid));

        if !is_authorized {
            error!(
                "MeshApp: Unauthorized UDS HTTP connection from UID {}",
                peer_uid
            );
            continue;
        }

        let app_clone = app.clone();
        tokio::spawn(async move {
            use hyper_util::rt::TokioIo;
            use hyper_util::service::TowerToHyperService;
            let io = TokioIo::new(stream);

            // For older hyper and simple axum usage, TowerToHyperService isn't strictly needed for serve_connection
            // if we are using axum 0.7 which handles service mapping natively or with tower::ServiceBuilder
            // but we stick to the provided pattern that compiled previously in pmond.
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, TowerToHyperService::new(app_clone))
                .with_upgrades()
                .await
            {
                error!("Error serving UDS HTTP connection: {:?}", err);
            }
        });
    }
}
