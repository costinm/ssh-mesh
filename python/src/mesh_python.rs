//! PyO3 bindings for the mesh node.
//!
//! This module provides Python bindings via PyO3. All core logic
//! is delegated to [`crate::mesh_common`]; this module handles only
//! PyO3-specific conversions (PyObject, PyBytes, GIL management)
//! and callback plumbing.
//!
//! See also:
//! - Python launcher: `dmesh/__main__.py`

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use ssh_mesh::{MeshListener, sshc::SshClientListener};
use std::sync::Arc;
use tokio::io::DuplexStream;
use tokio::runtime::Handle;

use crate::mesh_common::MeshHandle;

#[pyclass]
pub struct PyMeshNode {
    handle: Option<Box<MeshHandle>>,
    base_dir: String,
    callback: Option<PyObject>,
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
            })
            .await
            .unwrap_or_default();
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
                    let _ =
                        callback.call_method1(py, "on_stream", (client_id, host, port, py_stream));
                });
            })
            .await
            .unwrap_or_default();
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
                    let _ = callback.call_method1(
                        py,
                        "on_forwarded_tcpip",
                        (conn_id, host, port, py_stream),
                    );
                });
            })
            .await
            .unwrap_or_default();
        });
    }
}

#[pymethods]
impl PyMeshNode {
    #[new]
    fn new(base_dir: String) -> PyResult<Self> {
        let _ = tracing_subscriber::fmt::try_init();

        Ok(Self {
            handle: None,
            base_dir,
            callback: None,
        })
    }

    fn start(&mut self, py: Python<'_>, ssh_port: u16, http_port: u16) -> PyResult<()> {
        // Stop existing handle if any
        if let Some(handle) = self.handle.take() {
            crate::mesh_common::stop_mesh(*handle);
        }

        let handle =
            crate::mesh_common::start_mesh(&self.base_dir, ssh_port as i32, http_port as i32)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

        if let Some(ref callback) = self.callback {
            let mesh_listener = Arc::new(PyMeshListener {
                callback: callback.clone_ref(py),
                runtime: handle.runtime.handle().clone(),
            });
            handle.node.add_listener(mesh_listener);

            let client_listener = Arc::new(PySshClientListener {
                callback: callback.clone_ref(py),
                runtime: handle.runtime.handle().clone(),
            });
            handle.client_manager.add_listener(client_listener);
        }

        self.handle = Some(Box::new(handle));
        Ok(())
    }

    fn set_callback(&mut self, py: Python<'_>, callback: PyObject) {
        self.callback = Some(callback.clone_ref(py));
        if let Some(ref handle) = self.handle {
            let mesh_listener = Arc::new(PyMeshListener {
                callback: callback.clone_ref(py),
                runtime: handle.runtime.handle().clone(),
            });
            handle.node.add_listener(mesh_listener);

            let client_listener = Arc::new(PySshClientListener {
                callback: callback.clone_ref(py),
                runtime: handle.runtime.handle().clone(),
            });
            handle.client_manager.add_listener(client_listener);
        }
    }

    fn get_public_key(&self) -> String {
        match self.handle {
            Some(ref h) => crate::mesh_common::mesh_get_public_key(h),
            None => String::new(),
        }
    }

    fn connect(
        &self,
        py: Python<'_>,
        host: String,
        port: u16,
        user: String,
        server_key: String,
    ) -> PyResult<u64> {
        let handle = self
            .handle
            .as_ref()
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Node not started"))?;

        let res = py.allow_threads(|| {
            crate::mesh_common::mesh_connect(handle, &host, port, &user, &server_key)
        });

        res.map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    fn add_remote_forward(
        &self,
        py: Python<'_>,
        conn_id: u64,
        remote_port: u16,
        local_host: String,
        local_port: u16,
    ) -> PyResult<u32> {
        let handle = self
            .handle
            .as_ref()
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Node not started"))?;

        let res = py.allow_threads(|| {
            crate::mesh_common::mesh_add_remote_forward(
                handle,
                conn_id,
                remote_port,
                &local_host,
                local_port,
            )
        });

        res.map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    fn exec(&self, py: Python<'_>, conn_id: u64, command: String) -> PyResult<String> {
        let handle = self
            .handle
            .as_ref()
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Node not started"))?;

        let res = py.allow_threads(|| crate::mesh_common::mesh_exec(handle, conn_id, &command));

        res.map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    fn open_stream(
        &self,
        py: Python<'_>,
        conn_id: u64,
        host: String,
        port: u16,
    ) -> PyResult<PyMeshStream> {
        let handle = self
            .handle
            .as_ref()
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Node not started"))?;

        let res =
            py.allow_threads(|| crate::mesh_common::mesh_open_stream(handle, conn_id, &host, port));

        match res {
            Ok(stream_handle) => Ok(PyMeshStream {
                stream: Arc::new(tokio::sync::Mutex::new(stream_handle.stream)),
                handle: stream_handle.runtime_handle,
            }),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                e.to_string(),
            )),
        }
    }

    fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            crate::mesh_common::stop_mesh(*handle);
        }
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
        use tokio::io::AsyncReadExt;
        let stream = self.stream.clone();
        let handle = self.handle.clone();
        let mut buf = vec![0u8; size];

        let res = py.allow_threads(|| {
            handle.block_on(async {
                let mut s = stream.lock().await;
                s.read(&mut buf).await
            })
        });

        match res {
            Ok(n) => {
                let bytes = PyBytes::new_bound(py, &buf[..n]);
                Ok(bytes.into_any().unbind())
            }
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                e.to_string(),
            )),
        }
    }

    fn write(&self, py: Python<'_>, data: Bound<'_, PyBytes>) -> PyResult<usize> {
        use tokio::io::AsyncWriteExt;
        let stream = self.stream.clone();
        let handle = self.handle.clone();
        let data_vec = data.as_bytes().to_vec();

        let res = py.allow_threads(|| {
            handle.block_on(async {
                let mut s = stream.lock().await;
                s.write(&data_vec).await
            })
        });

        match res {
            Ok(n) => Ok(n),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                e.to_string(),
            )),
        }
    }

    fn close(&self, py: Python<'_>) -> PyResult<()> {
        use tokio::io::AsyncWriteExt;
        let stream = self.stream.clone();
        let handle = self.handle.clone();
        py.allow_threads(|| {
            handle.block_on(async {
                let mut s = stream.lock().await;
                let _ = s.shutdown().await;
            })
        });
        Ok(())
    }
}

#[pymodule]
fn dmesh_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyMeshNode>()?;
    m.add_class::<PyMeshStream>()?;
    Ok(())
}
