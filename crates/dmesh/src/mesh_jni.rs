use anyhow::{Context, Result};
use jni::{JavaVM, JNIEnv};
use jni::objects::{GlobalRef, JByteArray, JClass, JString};
use jni::sys::{jint, jlong, jobject};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use ssh_mesh::{MeshNode, MeshNodeConfig, run_ssh_server, MeshListener};
use ssh_mesh::sshc::SshClientListener;
use ssh_mesh::sshc::SshClientManager;

struct JniMeshListener {
    jvm: Arc<JavaVM>,
    callback: GlobalRef,
    runtime: tokio::runtime::Handle,
}

impl MeshListener for JniMeshListener {
    fn on_ssh_connection(&self, client_id: u64, user: &str) {
        let jvm = self.jvm.clone();
        let callback = self.callback.clone();
        let user_str = user.to_string();
        
        std::thread::spawn(move || {
            let mut env = match jvm.attach_current_thread() {
                Ok(e) => e,
                Err(e) => { log::error!("Failed to attach thread: {}", e); return; }
            };
            let j_user = env.new_string(user_str).unwrap();
            let _ = env.call_method(
                &callback,
                "onSshConnection",
                "(JLjava/lang/String;)V",
                &[(client_id as i64).into(), (&j_user).into()],
            );
        });
    }

    fn on_stream(&self, client_id: u64, host: &str, port: u16, stream: DuplexStream) {
        let jvm = self.jvm.clone();
        let callback = self.callback.clone();
        let host_str = host.to_string();
        let rt = self.runtime.clone();
        
        std::thread::spawn(move || {
            let mut env = match jvm.attach_current_thread() {
                Ok(e) => e,
                Err(e) => { log::error!("Failed to attach thread: {}", e); return; }
            };
            let j_host = env.new_string(host_str).unwrap();
            
            let stream_handle = MeshStreamHandle {
                stream,
                runtime_handle: rt,
            };
            
            let h = Box::into_raw(Box::new(stream_handle)) as jlong;

            let _ = env.call_method(
                &callback,
                "onStream",
                "(JLjava/lang/String;IJ)V",
                &[(client_id as i64).into(), (&j_host).into(), (port as i32).into(), h.into()],
            );
        });
    }
}

struct JniSshClientListener {
    jvm: Arc<JavaVM>,
    callback: GlobalRef,
    runtime: tokio::runtime::Handle,
}

impl SshClientListener for JniSshClientListener {
    fn on_forwarded_tcpip(&self, conn_id: u64, host: &str, port: u16, stream: DuplexStream) {
        let jvm = self.jvm.clone();
        let callback = self.callback.clone();
        let host_str = host.to_string();
        let rt = self.runtime.clone();
        
        std::thread::spawn(move || {
            let mut env = match jvm.attach_current_thread() {
                Ok(e) => e,
                Err(e) => { log::error!("Failed to attach thread: {}", e); return; }
            };
            let j_host = env.new_string(host_str).unwrap();
            
            let stream_handle = MeshStreamHandle {
                stream,
                runtime_handle: rt,
            };
            
            let h = Box::into_raw(Box::new(stream_handle)) as jlong;

            let _ = env.call_method(
                &callback,
                "onForwardedTcpip",
                "(JLjava/lang/String;IJ)V",
                &[(conn_id as i64).into(), (&j_host).into(), (port as i32).into(), h.into()],
            );
        });
    }
}

/// Opaque handle for a stream (channel).
pub struct MeshStreamHandle {
    pub stream: DuplexStream,
    pub runtime_handle: tokio::runtime::Handle,
}

/// Opaque handle for a Mesh node instance.
pub struct MeshHandle {
    pub node: Arc<MeshNode>,
    pub client_manager: Arc<SshClientManager>,
    pub runtime: Runtime,
    pub ssh_server_handle: Option<tokio::task::JoinHandle<()>>,
    pub http_server_handle: Option<tokio::task::JoinHandle<()>>,
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeSetCallback(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    callback: jni::objects::JObject,
) {
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let jvm = Arc::new(env.get_java_vm().unwrap());
    let callback_ref = env.new_global_ref(callback).unwrap();
    
    let mesh_listener = Arc::new(JniMeshListener {
        jvm: jvm.clone(),
        callback: callback_ref.clone(),
        runtime: handle.runtime.handle().clone(),
    });
    handle.node.add_listener(mesh_listener);

    let client_listener = Arc::new(JniSshClientListener {
        jvm,
        callback: callback_ref,
        runtime: handle.runtime.handle().clone(),
    });
    handle.client_manager.add_listener(client_listener);
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeStartMesh(
    mut env: JNIEnv,
    _class: JClass,
    base_dir: JString,
    ssh_port: jint,
    http_port: jint,
) -> jlong {
    let base_dir_str: String = match env.get_string(&base_dir) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };

    let base_path = PathBuf::from(base_dir_str);
    let _ = std::fs::create_dir_all(&base_path);

    let runtime = match Runtime::new() {
        Ok(r) => r,
        Err(_) => return 0,
    };

    let mut cfg = MeshNodeConfig::default();
    cfg.base_dir = Some(base_path.clone());
    cfg.ssh_port = if ssh_port > 0 { Some(ssh_port as u16) } else { Some(0) };
    cfg.http_port = if http_port > 0 { Some(http_port as u16) } else { None };

    let node = Arc::new(MeshNode::new(Some(base_path.clone()), Some(cfg)));
    
    let client_manager = Arc::new(SshClientManager::new(
        node.private_key().clone(),
        (*node.ca_keys).clone(),
        Some(base_path.join("config")),
        None,
    ));

    let node_clone = node.clone();
    let ssh_server_handle = runtime.spawn(async move {
        let config = node_clone.get_config();
        let port = node_clone.ssh_port();
        if let Err(e) = run_ssh_server(port, config, (*node_clone).clone()).await {
            log::error!("SSH server failed: {}", e);
        }
    });

    let mut http_server_handle = None;
    if let Some(h_port) = node.http_port() {
        let app_state = ssh_mesh::AppState {
            ssh_server: node.clone(),
            target_http_address: None,
            ssh_client_manager: client_manager.clone(),
        };
        let app = ssh_mesh::handlers::app(app_state);
        http_server_handle = Some(runtime.spawn(async move {
            let addr = format!("0.0.0.0:{}", h_port);
            match tokio::net::TcpListener::bind(&addr).await {
                Ok(listener) => {
                    if let Err(e) = axum::serve(listener, app.into_make_service()).await {
                        log::error!("HTTP server failed: {}", e);
                    }
                }
                Err(e) => log::error!("Failed to bind HTTP server to {}: {}", addr, e),
            }
        }));
    }

    let handle = MeshHandle {
        node,
        client_manager,
        runtime,
        ssh_server_handle: Some(ssh_server_handle),
        http_server_handle,
    };

    Box::into_raw(Box::new(handle)) as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeStop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        let handle = unsafe { Box::from_raw(handle as *mut MeshHandle) };
        if let Some(h) = handle.ssh_server_handle {
            h.abort();
        }
        if let Some(h) = handle.http_server_handle {
            h.abort();
        }
        handle.runtime.shutdown_background();
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeConnect(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    host: JString,
    port: jint,
    user: JString,
    server_key: JString,
) -> jlong {
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let host_str: String = env.get_string(&host).unwrap().into();
    let user_str: String = env.get_string(&user).unwrap().into();
    let key_str: String = env.get_string(&server_key).unwrap().into();

    let res = handle.runtime.block_on(async {
        handle.client_manager.connect(&host_str, port as u16, &user_str, &key_str).await
    });

    match res {
        Ok(id) => id as jlong,
        Err(e) => {
            log::error!("Connect failed: {}", e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeExec<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    handle: jlong,
    conn_id: jlong,
    command: JString<'a>,
) -> JString<'a> {
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let cmd_str: String = env.get_string(&command).unwrap().into();

    let res = handle.runtime.block_on(async {
        handle.client_manager.exec(conn_id as u64, &cmd_str).await
    });

    match res {
        Ok(exec_res) => env.new_string(exec_res.stdout).unwrap(),
        Err(e) => {
            log::error!("Exec failed: {}", e);
            env.new_string("").unwrap()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeGetPublicKey<'a>(
    env: JNIEnv<'a>,
    _class: JClass<'a>,
    handle: jlong,
) -> JString<'a> {
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let pk = handle.node.private_key().public_key();
    let pk_str = pk.to_openssh().unwrap_or_default();
    env.new_string(pk_str).unwrap()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeOpenStream(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    conn_id: jlong,
    host: JString,
    port: jint,
) -> jlong {
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let host_str: String = env.get_string(&host).unwrap().into();

    let res = handle.runtime.block_on(async {
        handle.client_manager.open_stream(conn_id as u64, &host_str, port as u16).await
    });

    match res {
        Ok(stream) => {
            let stream_handle = MeshStreamHandle {
                stream,
                runtime_handle: handle.runtime.handle().clone(),
            };
            Box::into_raw(Box::new(stream_handle)) as jlong
        }
        Err(e) => {
            log::error!("Open stream failed: {}", e);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeAddLocalForward(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    conn_id: jlong,
    local_port: jint,
    remote_host: JString,
    remote_port: jint,
) {
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let host_str: String = env.get_string(&remote_host).unwrap().into();

    let _ = handle.runtime.block_on(async {
        handle.client_manager.add_local_forward(conn_id as u64, local_port as u16, &host_str, remote_port as u16).await
    });
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeAddRemoteForward(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    conn_id: jlong,
    remote_port: jint,
    local_host: JString,
    local_port: jint,
) -> jint {
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let host_str: String = env.get_string(&local_host).unwrap().into();

    let res = handle.runtime.block_on(async {
        handle.client_manager.add_remote_forward(conn_id as u64, remote_port as u16, &host_str, local_port as u16).await
    });

    match res {
        Ok(port) => port as jint,
        Err(e) => {
            log::error!("Remote forward failed: {}", e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshStream_nativeStreamRead(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    buf: JByteArray,
) -> jint {
    let handle = unsafe { &mut *(handle as *mut MeshStreamHandle) };
    let mut data = vec![0u8; env.get_array_length(&buf).unwrap() as usize];
    
    let res = handle.runtime_handle.block_on(async {
        handle.stream.read(&mut data).await
    });

    match res {
        Ok(n) => {
            let byte_data: Vec<i8> = data[..n].iter().map(|&b| b as i8).collect();
            env.set_byte_array_region(&buf, 0, &byte_data).unwrap();
            n as jint
        }
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshStream_nativeStreamWrite(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    data: JByteArray,
) {
    let handle = unsafe { &mut *(handle as *mut MeshStreamHandle) };
    let bytes = env.convert_byte_array(&data).unwrap();
    
    let _ = handle.runtime_handle.block_on(async {
        handle.stream.write_all(&bytes).await
    });
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshStream_nativeStreamClose(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        let _ = unsafe { Box::from_raw(handle as *mut MeshStreamHandle) };
        // Dropping closes the stream
    }
}
