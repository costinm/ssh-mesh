use pyo3::prelude::*;
use pyo3::types::PyBytes;
use ssh_mesh::{MeshNode, MeshNodeConfig, sshc::SshClientManager, MeshListener, sshc::SshClientListener};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::runtime::{Runtime, Handle};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tracing::debug;

#[pyclass]
pub struct PyMeshNode {
    node: Arc<MeshNode>,
    client_manager: Arc<SshClientManager>,
    runtime: Arc<Runtime>,
    handle: Handle,
}

struct PyMeshListener {
    callback: PyObject,
    runtime: Handle,
}

impl MeshListener for PyMeshListener {
    fn on_ssh_connection(&self, client_id: u64, user: &str) {
        let callback = Python::with_gil(|py| self.callback.clone_ref(py));
        let user = user.to_string();
        self.runtime.spawn(async move {
            tokio::task::spawn_blocking(move || {
                Python::with_gil(|py| {
                    let _ = callback.call_method1(py, "on_ssh_connection", (client_id, user));
                });
            }).await.unwrap_or_default();
        });
    }

    fn on_stream(&self, client_id: u64, host: &str, port: u16, stream: DuplexStream) {
        let callback = Python::with_gil(|py| self.callback.clone_ref(py));
        let host = host.to_string();
        let runtime = self.runtime.clone();
        self.runtime.spawn(async move {
            let py_stream = PyMeshStream {
                stream: Arc::new(tokio::sync::Mutex::new(stream)),
                handle: runtime.clone(),
            };
            tokio::task::spawn_blocking(move || {
                Python::with_gil(|py| {
                    let _ = callback.call_method1(py, "on_stream", (client_id, host, port, py_stream));
                });
            }).await.unwrap_or_default();
        });
    }
}

struct PySshClientListener {
    callback: PyObject,
    runtime: Handle,
}

impl SshClientListener for PySshClientListener {
    fn on_forwarded_tcpip(&self, conn_id: u64, host: &str, port: u16, stream: DuplexStream) {
        let callback = Python::with_gil(|py| self.callback.clone_ref(py));
        let host = host.to_string();
        let runtime = self.runtime.clone();
        self.runtime.spawn(async move {
            let py_stream = PyMeshStream {
                stream: Arc::new(tokio::sync::Mutex::new(stream)),
                handle: runtime.clone(),
            };
            tokio::task::spawn_blocking(move || {
                Python::with_gil(|py| {
                    let _ = callback.call_method1(py, "on_forwarded_tcpip", (conn_id, host, port, py_stream));
                });
            }).await.unwrap_or_default();
        });
    }
}

#[pymethods]
impl PyMeshNode {
    #[new]
    fn new(base_dir: String) -> PyResult<Self> {
        let _ = tracing_subscriber::fmt::try_init();
        
        let base_path = PathBuf::from(base_dir);
        let mut cfg = MeshNodeConfig::default();
        cfg.base_dir = Some(base_path.clone());

        let node = Arc::new(MeshNode::new(Some(base_path.clone()), Some(cfg)));
        let client_manager = Arc::new(SshClientManager::new(
            node.private_key().clone(),
            (*node.ca_keys).clone(),
            Some(base_path.join("config")),
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

    fn start(&self, ssh_port: u16, http_port: u16) {
        let node = self.node.clone();
        let config = node.get_config();
        let handle = self.handle.clone();
        
        handle.spawn(async move {
            if let Err(e) = ssh_mesh::run_ssh_server(ssh_port, config, (*node).clone()).await {
                eprintln!("SSH server error: {}", e);
            }
        });

        if http_port > 0 {
            let app_state = ssh_mesh::AppState {
                ssh_server: self.node.clone(),
                target_http_address: None,
                ssh_client_manager: self.client_manager.clone(),
            };
            let app = ssh_mesh::handlers::app(app_state);
            let handle = self.handle.clone();
            handle.spawn(async move {
                let addr = format!("0.0.0.0:{}", http_port);
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

    fn set_callback(&self, py: Python<'_>, callback: PyObject) {
        let mesh_listener = Arc::new(PyMeshListener {
            callback: callback.clone_ref(py),
            runtime: self.handle.clone(),
        });
        self.node.add_listener(mesh_listener);

        let client_listener = Arc::new(PySshClientListener {
            callback: callback.clone_ref(py),
            runtime: self.handle.clone(),
        });
        self.client_manager.add_listener(client_listener);
    }

    fn get_public_key(&self) -> String {
        self.node.private_key().public_key().to_openssh().unwrap_or_default()
    }

    fn connect(&self, py: Python<'_>, host: String, port: u16, user: String, server_key: String) -> PyResult<u64> {
        let client_manager = self.client_manager.clone();
        let handle = self.handle.clone();

        let res = py.allow_threads(|| {
            handle.block_on(async {
                client_manager.connect(&host, port, &user, &server_key).await
            })
        });

        match res {
            Ok(id) => Ok(id),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())),
        }
    }

    fn add_remote_forward(&self, py: Python<'_>, conn_id: u64, remote_port: u16, local_host: String, local_port: u16) -> PyResult<u32> {
        let client_manager = self.client_manager.clone();
        let handle = self.handle.clone();

        let res = py.allow_threads(|| {
            handle.block_on(async {
                client_manager.add_remote_forward(conn_id, remote_port, &local_host, local_port).await
            })
        });

        match res {
            Ok(port) => Ok(port),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())),
        }
    }

    fn exec(&self, py: Python<'_>, conn_id: u64, command: String) -> PyResult<String> {
        let client_manager = self.client_manager.clone();
        let handle = self.handle.clone();

        let res = py.allow_threads(|| {
            handle.block_on(async {
                client_manager.exec(conn_id, &command).await
            })
        });

        match res {
            Ok(exec_res) => Ok(exec_res.stdout),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())),
        }
    }

    fn open_stream(&self, py: Python<'_>, conn_id: u64, host: String, port: u16) -> PyResult<PyMeshStream> {
        let client_manager = self.client_manager.clone();
        let handle = self.handle.clone();

        let res = py.allow_threads(|| {
            handle.block_on(async {
                client_manager.open_stream(conn_id, &host, port).await
            })
        });

        match res {
            Ok(stream) => Ok(PyMeshStream {
                stream: Arc::new(tokio::sync::Mutex::new(stream)),
                handle,
            }),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())),
        }
    }

    fn stop(&self) {
        // Shutdown runtime and any other cleanup needed
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyMeshStream {
    stream: Arc<tokio::sync::Mutex<DuplexStream>>,
    handle: Handle,
}

#[pymethods]
impl PyMeshStream {
    fn read(&self, py: Python<'_>, size: usize) -> PyResult<PyObject> {
        let mut stream = self.stream.blocking_lock();
        let handle = self.handle.clone();
        let mut buf = vec![0u8; size];

        let res = py.allow_threads(|| {
            handle.block_on(async {
                stream.read(&mut buf).await
            })
        });

        match res {
            Ok(n) => {
                let bytes = PyBytes::new_bound(py, &buf[..n]);
                Ok(bytes.into_any().unbind())
            },
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())),
        }
    }

    fn write(&self, py: Python<'_>, data: Bound<'_, PyBytes>) -> PyResult<usize> {
        let mut stream = self.stream.blocking_lock();
        let handle = self.handle.clone();
        let data_vec = data.as_bytes().to_vec();

        let res = py.allow_threads(|| {
            handle.block_on(async {
                stream.write(&data_vec).await
            })
        });

        match res {
            Ok(n) => Ok(n),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())),
        }
    }

    fn close(&self, py: Python<'_>) -> PyResult<()> {
        let mut stream = self.stream.blocking_lock();
        let handle = self.handle.clone();
        py.allow_threads(|| {
            handle.block_on(async {
                let _ = stream.shutdown().await;
            })
        });
        Ok(())
    }
}

#[pymodule]
fn ssh_mesh_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyMeshNode>()?;
    m.add_class::<PyMeshStream>()?;
    Ok(())
}
