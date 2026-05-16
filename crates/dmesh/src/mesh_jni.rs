//! JNI bindings for the mesh node.
//!
//! This module provides Java/Android bindings via JNI. All core logic
//! is delegated to [`crate::mesh_common`]; this module handles only
//! JNI-specific marshalling (JString ↔ Rust String, jlong ↔ pointer casts)
//! and callback plumbing.
//!
//! See also:
//! - Rust binary: `src/main.rs`
//! - Python wrapper: `mesh_python.rs`
//! - Java launcher: `java/rust/src/main/java/.../Main.java`
//! - Java test: `java/rust/src/main/java/.../MainTest.java`

use jni::{JavaVM, JNIEnv};
use jni::objects::{GlobalRef, JByteArray, JClass, JString};
use jni::sys::{jint, jlong};
use std::sync::Arc;
use tokio::io::DuplexStream;
use ssh_mesh::MeshListener;
use ssh_mesh::sshc::SshClientListener;

use crate::mesh_common::{MeshHandle, MeshStreamHandle};

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

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeSetCallback(
    env: JNIEnv,
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

    match crate::mesh_common::start_mesh(&base_dir_str, ssh_port, http_port) {
        Ok(handle) => Box::into_raw(Box::new(handle)) as jlong,
        Err(e) => {
            log::error!("Failed to start mesh: {}", e);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeStop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        let handle = unsafe { Box::from_raw(handle as *mut MeshHandle) };
        crate::mesh_common::stop_mesh(*handle);
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

    match crate::mesh_common::mesh_connect(handle, &host_str, port as u16, &user_str, &key_str) {
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

    match crate::mesh_common::mesh_exec(handle, conn_id as u64, &cmd_str) {
        Ok(stdout) => env.new_string(stdout).unwrap(),
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
    let pk_str = crate::mesh_common::mesh_get_public_key(handle);
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

    match crate::mesh_common::mesh_open_stream(handle, conn_id as u64, &host_str, port as u16) {
        Ok(stream_handle) => Box::into_raw(Box::new(stream_handle)) as jlong,
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

    let _ = crate::mesh_common::mesh_add_local_forward(
        handle, conn_id as u64, local_port as u16, &host_str, remote_port as u16,
    );
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

    match crate::mesh_common::mesh_add_remote_forward(
        handle, conn_id as u64, remote_port as u16, &host_str, local_port as u16,
    ) {
        Ok(port) => port as jint,
        Err(e) => {
            log::error!("Remote forward failed: {}", e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshStream_nativeStreamRead(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    buf: JByteArray,
) -> jint {
    let handle = unsafe { &mut *(handle as *mut MeshStreamHandle) };
    let mut data = vec![0u8; env.get_array_length(&buf).unwrap() as usize];
    
    match crate::mesh_common::stream_read(handle, &mut data) {
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
    
    let _ = crate::mesh_common::stream_write(handle, &bytes);
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

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn Java_costinm_dmesh_MeshNode_nativeCreateTun(
    mut _env: JNIEnv,
    _class: JClass,
    fd: jint,
) -> jlong {
    log::info!("nativeCreateTun called with fd: {}", fd);
    
    // Create the MeshTun wrapper from the Android VPN file descriptor
    match unsafe { mesh_tun::MeshTun::from_fd(fd) } {
        Ok(_tun) => {
            // For now, we return a pointer/handle. Ideally we would box it and run it.
            // Returning the fd as a placeholder success
            fd as jlong
        }
        Err(e) => {
            log::error!("Failed to create MeshTun from fd: {}", e);
            -1
        }
    }
}
