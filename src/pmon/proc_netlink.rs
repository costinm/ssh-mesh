use nix::sys::socket::{bind, send, recv, NetlinkAddr};
use nix::unistd::getpid;
use std::os::unix::io::RawFd;
use std::ffi::c_void;
use std::mem::size_of;
use std::collections::HashMap;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}, Mutex};

use super::psi::{PressureType, PsiWatcher};
use super::proc::{ProcessInfo, read_process_info_from_proc};

// linux/connector.h
const CN_IDX_PROC: u32 = 0x1;
const CN_VAL_PROC: u32 = 0x1;

// linux/cn_proc.h
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ProcCnMcastOp {
    ProcCnMcastListen = 1,
    ProcCnMcastIgnore = 2,
}

#[allow(unused)]
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProcEventWhat {
    ProcEventNone = 0x0,
    ProcEventFork = 0x1,
    ProcEventExec = 0x2,
    ProcEventUid = 0x4,
    ProcEventGid = 0x40,
    ProcEventExit = 0x80000000,
    ProcEventComm = 0x200,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct Nlmsghdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct CnMsg {
    id: CbId,
    seq: u32,
    ack: u32,
    len: u16,
    flags: u16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct CbId {
    idx: u32,
    val: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
union ProcEventData {
    fork: ForkProcEvent,
    exec: ExecProcEvent,
    id: IdProcEvent,
    exit: ExitProcEvent,
    comm: CommProcEvent,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct ForkProcEvent {
    parent_pid: u32,
    parent_tgid: u32,
    child_pid: u32,
    child_tgid: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct ExecProcEvent {
    process_pid: u32,
    process_tgid: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct IdProcEvent {
    process_pid: u32,
    process_tgid: u32,
    r: RId,
    e: EId,
}

#[repr(C)]
#[derive(Copy, Clone)]
union RId {
    ruid: u32,
    rgid: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
union EId {
    euid: u32,
    egid: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct ExitProcEvent {
    process_pid: u32,
    process_tgid: u32,
    exit_code: u32,
    exit_signal: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct CommProcEvent {
    process_pid: u32,
    process_tgid: u32,
    comm: [u8; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ProcEvent {
    what: ProcEventWhat,
    cpu: u32,
    timestamp_ns: u64,
    event_data: ProcEventData,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct NlcnMsgMcast {
    nl_hdr: Nlmsghdr,
    cn_msg: CnMsg,
    cn_mcast: ProcCnMcastOp,
}

const NLCN_MSG_MCAST_INIT: NlcnMsgMcast = NlcnMsgMcast {
    nl_hdr: Nlmsghdr {
        nlmsg_len: 0,
        nlmsg_type: 0,
        nlmsg_flags: 0,
        nlmsg_seq: 0,
        nlmsg_pid: 0,
    },
    cn_msg: CnMsg {
        id: CbId { idx: 0, val: 0 },
        seq: 0,
        ack: 0,
        len: 0,
        flags: 0,
    },
    cn_mcast: ProcCnMcastOp::ProcCnMcastListen,
};

#[repr(C)]
struct NlcnMsgEvent {
    nl_hdr: Nlmsghdr,
    cn_msg: CnMsg,
    proc_ev: ProcEvent,
}

const NLCN_MSG_EVENT_INIT: NlcnMsgEvent = NlcnMsgEvent {
    nl_hdr: Nlmsghdr {
        nlmsg_len: 0,
        nlmsg_type: 0,
        nlmsg_flags: 0,
        nlmsg_seq: 0,
        nlmsg_pid: 0,
    },
    cn_msg: CnMsg {
        id: CbId { idx: 0, val: 0 },
        seq: 0,
        ack: 0,
        len: 0,
        flags: 0,
    },
    proc_ev: ProcEvent {
        what: ProcEventWhat::ProcEventNone,
        cpu: 0,
        timestamp_ns: 0,
        event_data: ProcEventData {
            fork: ForkProcEvent {
                parent_pid: 0,
                parent_tgid: 0,
                child_pid: 0,
                child_tgid: 0,
            },
        },
    },
};

/// Periodically check processes every 10 seconds to verify they still exist
/// and get current memory usage
fn periodic_process_checker(
    running: Arc<AtomicBool>,
    processes: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
    psi_watcher: Arc<PsiWatcher>,
    _callback: Arc<Mutex<Option<Box<dyn Fn(ProcessInfo) + Send + Sync>>>>,
) {
    while running.load(Ordering::SeqCst) {
        // Sleep for 10 seconds
        std::thread::sleep(std::time::Duration::from_secs(10));

        if !running.load(Ordering::SeqCst) {
            break;
        }

        // Clone the process list to minimize lock time
        let pids: Vec<u32> = {
            let proc_map = processes.lock().unwrap();
            proc_map.keys().cloned().collect()
        };

        // Check each process
        for pid in pids {
            // Check if process still exists by trying to read its info
            match read_process_info_from_proc(pid) {
                Ok(process_info) => {
                    // Process still exists, update its information
                    {
                        let mut proc_map = processes.lock().unwrap();
                        proc_map.insert(pid, process_info.clone());
                    }

                    // Invoke callback if exists
                    // if let Some(cb) = callback.lock().unwrap().as_ref() {
                    //     cb(process_info);
                    // }
                }
                Err(_) => {
                    // Process no longer exists, remove it
                    {
                        let mut proc_map = processes.lock().unwrap();
                        proc_map.remove(&pid);
                    }
                    psi_watcher.remove_pid(pid);
                }
            }
        }
    }
}

pub fn proc_nl_connect() -> Result<RawFd, nix::Error> {
    let nl_sock = unsafe {
        libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, libc::NETLINK_CONNECTOR)
    };
    if nl_sock < 0 {
        return Err(nix::Error::last());
    }
    let sa_nl = NetlinkAddr::new(getpid().as_raw() as u32, CN_IDX_PROC);
    bind(nl_sock, &sa_nl)?;
    Ok(nl_sock)
}

pub fn proc_set_ev_listen(nl_sock: RawFd, enable: bool) -> Result<(), nix::Error> {
    let mut nlcn_msg = NLCN_MSG_MCAST_INIT;
    nlcn_msg.nl_hdr.nlmsg_len = size_of::<NlcnMsgMcast>() as u32;
    nlcn_msg.nl_hdr.nlmsg_pid = getpid().as_raw() as u32;
    nlcn_msg.nl_hdr.nlmsg_type = 11; // NLMSG_DONE
    nlcn_msg.cn_msg.id.idx = CN_IDX_PROC;
    nlcn_msg.cn_msg.id.val = CN_VAL_PROC;
    nlcn_msg.cn_msg.len = size_of::<ProcCnMcastOp>() as u16;
    nlcn_msg.cn_mcast = if enable {
        ProcCnMcastOp::ProcCnMcastListen
    } else {
        ProcCnMcastOp::ProcCnMcastIgnore
    };
    let ptr: *const c_void = &nlcn_msg as *const _ as *const c_void;
    send(
        nl_sock,
        unsafe { std::slice::from_raw_parts(ptr as *const u8, size_of::<NlcnMsgMcast>()) },
        nix::sys::socket::MsgFlags::empty(),
    )?;
    Ok(())
}

pub fn proc_handle_ev(
    nl_sock: RawFd,
    callback: Arc<Mutex<Option<Box<dyn Fn(ProcessInfo) + Send + Sync>>>>,
    running: Arc<AtomicBool>,
    processes: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
    psi_watcher: Arc<PsiWatcher>,
) -> Result<(), nix::Error> {
    // Clone variables for the periodic checker thread
    let running_clone = running.clone();
    let processes_clone = processes.clone();
    let psi_watcher_clone = psi_watcher.clone();
    let callback_clone = callback.clone();

    // Start a periodic checker thread that runs every 10 seconds
    std::thread::spawn(move || {
        periodic_process_checker(running_clone, processes_clone, psi_watcher_clone, callback_clone);
    });
    let mut nlcn_msg = NLCN_MSG_EVENT_INIT;
    let nlcn_msg_ptr: *mut c_void = &mut nlcn_msg as *mut _ as *mut c_void;
    while running.load(Ordering::SeqCst) {
        let buf = unsafe {
            std::slice::from_raw_parts_mut(nlcn_msg_ptr as *mut u8, size_of::<NlcnMsgEvent>())
        };
        let rc = recv(nl_sock, buf, nix::sys::socket::MsgFlags::empty());
        if rc.is_err() {
            let err = rc.err().unwrap();
            if err == nix::Error::EINTR {
                continue;
            }
            // Return error when recv fails
            return Err(err);
        }
        // Process the event
        match nlcn_msg.proc_ev.what {
            ProcEventWhat::ProcEventNone => {}
            ProcEventWhat::ProcEventFork => {
                let data = unsafe { nlcn_msg.proc_ev.event_data.fork };
                // Use tokio to execute the read and update operations
                let processes_clone = processes.clone();
                let psi_watcher_clone = psi_watcher.clone();
                let callback_clone = callback.clone();

                tokio::spawn(async move {
                    // Update process information by reading from /proc
                    if let Ok(process_info) = read_process_info_from_proc(data.child_tgid) {
                        if data.parent_tgid == data.child_tgid {
                            println!("thread: parent pid={} -> child pid={} {} {}", data.parent_tgid, data.child_pid, data.child_tgid,
                                process_info.comm);
                        } else {
                            println!("fork: parent pid={} {} -> child pid={} {} tname/cmd ({}) {:?}",
                             data.parent_tgid, data.parent_pid,
                             data.child_pid, data.child_tgid,
                             process_info.comm, process_info.cmdline);

                            // Process still exists, update its information
                            {
                                let mut proc_map = processes_clone.lock().unwrap();
                                proc_map.insert(process_info.pid, process_info.clone());
                            }

                            psi_watcher_clone.add_pid(process_info.pid, PressureType::Memory);
                            psi_watcher_clone.add_pid(process_info.pid, PressureType::Cpu);
                            psi_watcher_clone.add_pid(process_info.pid, PressureType::Io);

                            if let Some(cb) = callback_clone.lock().unwrap().as_ref() {
                                cb(process_info);
                            }
                        }
                    }
                });
            }
            // Ignore Exec event as requested
            ProcEventWhat::ProcEventExec => {
                // Ignored as per requirements
            }
            // Ignore Uid event as requested
            ProcEventWhat::ProcEventUid => {
                // Ignored as per requirements
            }
            // Ignore Gid event as requested
            ProcEventWhat::ProcEventGid => {
                // Ignored as per requirements
            }
            ProcEventWhat::ProcEventExit => {
                let data = unsafe { nlcn_msg.proc_ev.event_data.exit };
                println!("exit: pid={}", data.process_tgid);
                processes.lock().unwrap().remove(&data.process_tgid);
                psi_watcher.remove_pid(data.process_tgid);
            }
            // Ignore Comm event as requested
            ProcEventWhat::ProcEventComm => {
                // Ignored as per requirements
            }
        }
        //println!("Processes: {}", processes.lock().unwrap().len());
    }
    // Only return Ok when the loop exits due to running being set to false
    Ok(())
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_start_populates_processes() {
        use crate::pmon::proc::ProcMon;

        let proc_mon = match ProcMon::new() {
            Ok(pm) => pm,
            Err(e) => {
                if let nix::Error::EADDRINUSE = e {
                    println!("Skipping test due to EADDRINUSE - another instance may be running");
                    return;
                }
                panic!("Failed to create ProcMon: {}", e);
            }
        };

        if let Err(e) = proc_mon.start(true, false) {
            panic!("Failed to start ProcMon: {}", e);
        }

        let processes = proc_mon.processes.lock().unwrap();
        assert!(
            processes.len() >= 5,
            "Expected at least 5 processes, found {}",
            processes.len()
        );

        let _ = proc_mon.stop();
    }
}
