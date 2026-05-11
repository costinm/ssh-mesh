use pyo3::prelude::*;
use ssh_mesh::{MeshNode, MeshNodeConfig, sshc::SshClientManager};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::runtime::{Runtime, Handle};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

#[pyclass]
pub struct PyMeshNode {
    node: Arc<MeshNode>,
    client_manager: Arc<SshClientManager>,
    runtime: Arc<Runtime>,
    handle: Handle,
}

#[pymethods]
impl PyMeshNode {
    #[new]
    fn new(base_dir: String, ssh_port: u16, http_port: u16) -> PyResult<Self> {
        let base_path = PathBuf::from(base_dir);
        let mut cfg = MeshNodeConfig::default();
        cfg.base_dir = Some(base_path.clone());
        cfg.ssh_port = Some(ssh_port);
        if http_port > 0 {
            cfg.http_port = Some(http_port);
        }

        let node = Arc::new(MeshNode::new(Some(base_path), Some(cfg)));
        let client_manager = Arc::new(SshClientManager::new(
            node.private_key().clone(),
            node.ca_keys.as_ref().clone(),
            Some(node.base_dir().join("config")),
            None,
        ));

        let runtime = Arc::new(Runtime::new().map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?);
        let handle = runtime.handle().clone();

        Ok(Self {
            node,
            client_manager,
            runtime,
            handle,
        })
    }

    fn start(&self) {
        let node = self.node.clone();
        let port = node.ssh_port();
        let config = node.get_config();
        let handle = self.handle.clone();
        
        handle.spawn(async move {
            if let Err(e) = ssh_mesh::run_ssh_server(port, config, (*node).clone()).await {
                eprintln!("SSH server error: {}", e);
            }
        });

        if let Some(h_port) = self.node.http_port() {
            let app_state = ssh_mesh::AppState {
                ssh_server: self.node.clone(),
                target_http_address: None,
                ssh_client_manager: self.client_manager.clone(),
            };
            let app = ssh_mesh::handlers::app(app_state);
            let handle = self.handle.clone();
            handle.spawn(async move {
                let addr = format!("0.0.0.0:{}", h_port);
                match tokio::net::TcpListener::bind(&addr).await {
                    Ok(listener) => {
                        if let Err(e) = axum::serve(listener, app.into_make_service()).await {
                            eprintln!("HTTP server error: {}", e);
                        }
                    }
                    Err(e) => eprintln!("Failed to bind HTTP server: {}", e),
                }
            });
        }
    }

    fn get_public_key(&self) -> String {
        self.node.private_key().public_key().to_openssh().unwrap_or_default()
    }

    fn connect(&self, host: String, port: u16, user: String, server_key: String) -> PyResult<u64> {
        let client_manager = self.client_manager.clone();
        let handle = self.handle.clone();

        let res = handle.block_on(async {
            client_manager.connect(&host, port, &user, &server_key).await
        });

        match res {
            Ok(id) => Ok(id),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())),
        }
    }

    fn exec(&self, conn_id: u64, command: String) -> PyResult<String> {
        let client_manager = self.client_manager.clone();
        let handle = self.handle.clone();

        let res = handle.block_on(async {
            client_manager.exec(conn_id, &command).await
        });

        match res {
            Ok(exec_res) => Ok(exec_res.stdout),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())),
        }
    }

    fn open_stream(&self, conn_id: u64, host: String, port: u16) -> PyResult<PyMeshStream> {
        let client_manager = self.client_manager.clone();
        let handle = self.handle.clone();

        let res = handle.block_on(async {
            client_manager.open_stream(conn_id, &host, port).await
        });

        match res {
            Ok(stream) => Ok(PyMeshStream {
                stream: Arc::new(tokio::sync::Mutex::new(stream)),
                handle,
            }),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())),
        }
    }
}

#[pyclass]
pub struct PyMeshStream {
    stream: Arc<tokio::sync::Mutex<DuplexStream>>,
    handle: Handle,
}

#[pymethods]
impl PyMeshStream {
    fn read(&self, buf: Vec<u8>) -> PyResult<Vec<u8>> {
        let mut stream = self.stream.blocking_lock();
        let handle = self.handle.clone();
        let mut buf = buf;

        let res = handle.block_on(async {
            stream.read(&mut buf).await
        });

        match res {
            Ok(n) => Ok(buf[..n].to_vec()),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())),
        }
    }

    fn write(&self, data: Vec<u8>) -> PyResult<()> {
        let mut stream = self.stream.blocking_lock();
        let handle = self.handle.clone();

        let res = handle.block_on(async {
            stream.write_all(&data).await
        });

        match res {
            Ok(_) => Ok(()),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())),
        }
    }
}

#[pymodule]
fn ssh_mesh_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyMeshNode>()?;
    m.add_class::<PyMeshStream>()?;
    Ok(())
}
