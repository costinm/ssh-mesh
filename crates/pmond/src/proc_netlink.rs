use log::{debug, error, info};
use nix::sys::socket::{bind, recv, send, NetlinkAddr};
use nix::unistd::getpid;
use std::ffi::c_void;
use std::mem::size_of;
use std::os::unix::io::RawFd;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::mpsc;

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

#[derive(Debug, Clone)]
pub enum NetlinkEvent {
    Fork {
        parent_pid: u32,
        parent_tgid: u32,
        child_pid: u32,
        child_tgid: u32,
    },
    Exec {
        process_pid: u32,
        process_tgid: u32,
    },
    Exit {
        process_pid: u32,
        process_tgid: u32,
        exit_code: u32,
        exit_signal: u32,
    },
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

pub fn proc_nl_connect() -> Result<RawFd, nix::Error> {
    let nl_sock =
        unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, libc::NETLINK_CONNECTOR) };
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

pub fn run_netlink_listener(
    tx: mpsc::Sender<NetlinkEvent>,
    running: Arc<AtomicBool>,
) -> Result<(), nix::Error> {
    info!("Starting netlink listener");
    let nl_sock = proc_nl_connect()?;
    proc_set_ev_listen(nl_sock, true)?;

    let mut nlcn_msg = NLCN_MSG_EVENT_INIT;
    let nlcn_msg_ptr: *mut c_void = &mut nlcn_msg as *mut _ as *mut c_void;

    while running.load(Ordering::SeqCst) {
        let buf = unsafe {
            std::slice::from_raw_parts_mut(nlcn_msg_ptr as *mut u8, size_of::<NlcnMsgEvent>())
        };
        // This recv is blocking
        let rc = recv(nl_sock, buf, nix::sys::socket::MsgFlags::empty());
        if rc.is_err() {
            let err = rc.err().unwrap();
            if err == nix::Error::EINTR {
                continue;
            }
            error!("Netlink recv error: {}", err);
            unsafe { libc::close(nl_sock) };
            return Err(err);
        }

        // Process the event
        let event = match nlcn_msg.proc_ev.what {
            ProcEventWhat::ProcEventFork => {
                let data = unsafe { nlcn_msg.proc_ev.event_data.fork };
                Some(NetlinkEvent::Fork {
                    parent_pid: data.parent_pid,
                    parent_tgid: data.parent_tgid,
                    child_pid: data.child_pid,
                    child_tgid: data.child_tgid,
                })
            }
            ProcEventWhat::ProcEventExec => {
                let data = unsafe { nlcn_msg.proc_ev.event_data.exec };
                Some(NetlinkEvent::Exec {
                    process_pid: data.process_pid,
                    process_tgid: data.process_tgid,
                })
            }
            ProcEventWhat::ProcEventExit => {
                let data = unsafe { nlcn_msg.proc_ev.event_data.exit };
                Some(NetlinkEvent::Exit {
                    process_pid: data.process_pid,
                    process_tgid: data.process_tgid,
                    exit_code: data.exit_code,
                    exit_signal: data.exit_signal,
                })
            }
            _ => None,
        };

        if let Some(e) = event {
            // blocking_send is appropriate here because we are likely running in a dedicated thread
            // (or using spawn_blocking) and we don't want to async await inside this tight blocking loop
            // without converting the socket to async.
            if let Err(err) = tx.blocking_send(e) {
                error!("Failed to send netlink event: {}", err);
                break;
            }
        }
    }

    info!("Stopping netlink listener");
    proc_set_ev_listen(nl_sock, false).ok();
    unsafe { libc::close(nl_sock) };
    Ok(())
}

