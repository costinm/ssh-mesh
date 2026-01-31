use log::{error, info, trace};
use nix::sys::socket::{bind, recv, send, NetlinkAddr};
use nix::unistd::getpid;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::mpsc;

// linux/connector.h
const CN_IDX_PROC: u32 = 0x1;
const CN_VAL_PROC: u32 = 0x1;

// linux/netlink.h message types
const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

// linux/cn_proc.h
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ProcCnMcastOp {
    ProcCnMcastListen = 1,
    ProcCnMcastIgnore = 2,
}

const PROC_EVENT_FORK: u32 = 0x00000001;
const PROC_EVENT_EXEC: u32 = 0x00000002;
const PROC_EVENT_UID: u32 = 0x00000004;
const PROC_EVENT_EXIT: u32 = 0x80000000;
const PROC_EVENT_COMM: u32 = 0x00000200;

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
    Uid {
        process_pid: u32,
        process_tgid: u32,
        ruid: u32,
        euid: u32,
    },
    Comm {
        process_pid: u32,
        process_tgid: u32,
        comm: String,
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
    what: u32,
    cpu: u32,
    timestamp_ns: u64,
    event_data: ProcEventData,
}

// Note: NlcnMsgEvent and NLCN_MSG_EVENT_INIT were removed as we now use
// raw buffer parsing with proper alignment handling

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

pub fn proc_nl_connect() -> Result<OwnedFd, nix::Error> {
    let nl_sock =
        unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, libc::NETLINK_CONNECTOR) };
    if nl_sock < 0 {
        return Err(nix::Error::last());
    }
    // Wrap in OwnedFd immediately for RAII cleanup
    let owned_fd = unsafe { OwnedFd::from_raw_fd(nl_sock) };

    // Set a large receive buffer to prevent drops under high load
    let rcvbuf: libc::c_int = 1024 * 1024;
    unsafe {
        libc::setsockopt(
            owned_fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &rcvbuf as *const _ as *const libc::c_void,
            size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    let sa_nl = NetlinkAddr::new(getpid().as_raw() as u32, CN_IDX_PROC);
    bind(owned_fd.as_raw_fd(), &sa_nl)?;
    Ok(owned_fd)
}

pub fn proc_set_ev_listen(nl_sock: &OwnedFd, enable: bool) -> Result<(), nix::Error> {
    let mut nlcn_msg = NLCN_MSG_MCAST_INIT;
    nlcn_msg.nl_hdr.nlmsg_len = size_of::<NlcnMsgMcast>() as u32;
    nlcn_msg.nl_hdr.nlmsg_pid = getpid().as_raw() as u32;
    nlcn_msg.nl_hdr.nlmsg_type = NLMSG_DONE;
    nlcn_msg.cn_msg.id.idx = CN_IDX_PROC;
    nlcn_msg.cn_msg.id.val = CN_VAL_PROC;
    nlcn_msg.cn_msg.len = size_of::<ProcCnMcastOp>() as u16;
    nlcn_msg.cn_mcast = if enable {
        ProcCnMcastOp::ProcCnMcastListen
    } else {
        ProcCnMcastOp::ProcCnMcastIgnore
    };
    let buf = unsafe {
        std::slice::from_raw_parts(
            &nlcn_msg as *const _ as *const u8,
            size_of::<NlcnMsgMcast>(),
        )
    };
    send(
        nl_sock.as_raw_fd(),
        buf,
        nix::sys::socket::MsgFlags::empty(),
    )?;
    Ok(())
}

pub fn run_netlink_listener(
    tx: mpsc::Sender<crate::MonitoringEvent>,
    running: Arc<AtomicBool>,
) -> Result<(), nix::Error> {
    let nl_sock = proc_nl_connect()?;
    proc_set_ev_listen(&nl_sock, true)?;

    // Use a raw buffer like the C code does, then parse at correct offsets
    const RECV_BUF_SIZE: usize = 4096;
    let mut buf = [0u8; RECV_BUF_SIZE];

    while running.load(Ordering::SeqCst) {
        // This recv is blocking
        match recv(
            nl_sock.as_raw_fd(),
            &mut buf,
            nix::sys::socket::MsgFlags::empty(),
        ) {
            Err(nix::Error::EINTR) => continue,
            Err(err) => {
                error!("Netlink recv error: {}", err);
                return Err(err);
            }
            Ok(_) => {}
        }

        // Parse the netlink message header (use read_unaligned for safety)
        let nl_hdr = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const Nlmsghdr) };

        // Skip error or noop messages
        if nl_hdr.nlmsg_type == NLMSG_ERROR || nl_hdr.nlmsg_type == NLMSG_NOOP {
            continue;
        }

        // cn_msg starts after nlmsghdr (at NLMSG_DATA offset, which aligns to 4 bytes)
        let nlmsg_hdrlen = (size_of::<Nlmsghdr>() + 3) & !3; // NLMSG_ALIGN
        let cn_msg_ptr = unsafe { buf.as_ptr().add(nlmsg_hdrlen) as *const CnMsg };

        // proc_event starts right after the fixed cn_msg fields (id, seq, ack, len, flags)
        // cn_msg fixed size is 20 bytes (CbId=8 + seq=4 + ack=4 + len=2 + flags=2)
        let cn_msg_fixed_size = size_of::<CnMsg>();
        let proc_ev_ptr =
            unsafe { (cn_msg_ptr as *const u8).add(cn_msg_fixed_size) as *const ProcEvent };
        // Use read_unaligned because the buffer may not be 8-byte aligned (ProcEvent contains u64)
        let proc_ev = unsafe { std::ptr::read_unaligned(proc_ev_ptr) };

        let event = match proc_ev.what {
            PROC_EVENT_FORK => {
                let data = unsafe { proc_ev.event_data.fork };
                Some(NetlinkEvent::Fork {
                    parent_pid: data.parent_pid,
                    parent_tgid: data.parent_tgid,
                    child_pid: data.child_pid,
                    child_tgid: data.child_tgid,
                })
            }
            PROC_EVENT_EXEC => {
                let data = unsafe { proc_ev.event_data.exec };
                Some(NetlinkEvent::Exec {
                    process_pid: data.process_pid,
                    process_tgid: data.process_tgid,
                })
            }
            PROC_EVENT_EXIT => {
                let data = unsafe { proc_ev.event_data.exit };
                Some(NetlinkEvent::Exit {
                    process_pid: data.process_pid,
                    process_tgid: data.process_tgid,
                    exit_code: data.exit_code,
                    exit_signal: data.exit_signal,
                })
            }
            PROC_EVENT_UID => {
                let data = unsafe { proc_ev.event_data.id };
                Some(NetlinkEvent::Uid {
                    process_pid: data.process_pid,
                    process_tgid: data.process_tgid,
                    ruid: unsafe { data.r.ruid },
                    euid: unsafe { data.e.euid },
                })
            }
            PROC_EVENT_COMM => {
                let data = unsafe { proc_ev.event_data.comm };
                let comm = std::str::from_utf8(&data.comm)
                    .map(|s| s.trim_matches('\0').to_string())
                    .unwrap_or_default();
                Some(NetlinkEvent::Comm {
                    process_pid: data.process_pid,
                    process_tgid: data.process_tgid,
                    comm,
                })
            }
            _ => {
                trace!("Unknown netlink event type: 0x{:08x}", proc_ev.what);
                None
            }
        };

        if let Some(e) = event {
            // blocking_send is appropriate here because we are likely running in a dedicated thread
            // (or using spawn_blocking) and we don't want to async await inside this tight blocking loop
            // without converting the socket to async.
            if let Err(err) = tx.blocking_send(crate::MonitoringEvent::Netlink(e)) {
                error!("Failed to send netlink event: {}", err);
                break;
            }
        }
    }

    info!("Stopping netlink listener");
    proc_set_ev_listen(&nl_sock, false).ok();
    // nl_sock is automatically closed when OwnedFd is dropped
    Ok(())
}
