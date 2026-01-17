// NetLink echo server/client implementation
use std::time::Duration;
use clap::Parser;
use anyhow::Result;
use std::process;
use std::io;
use std::thread;
use libc;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// NetLink protocol number for user-space IPC
    #[arg(short, long, default_value_t = 31)] // NETLINK_USERSOCK = 31
    pub protocol: u32,

    /// Buffer size for read/write operations
    #[arg(short, long, default_value_t = 4096)]
    pub buffer_size: usize,

    /// Server PID (use 0 for broadcast)
    #[arg(short, long, default_value_t = 0)]
    pub server_pid: u32,

    /// Number of iterations for benchmarking
    #[arg(short, long, default_value_t = 100)]
    pub iterations: usize,

    /// Message size for benchmarking
    #[arg(short, long, default_value_t = 100)]
    pub message_size: usize,

    /// Run in benchmark mode
    #[arg(short, long, default_value_t = false)]
    pub benchmark: bool,
}

pub struct Netlink {
    sock_fd: i32,
}

impl Netlink {
    pub fn new(_server_pid: Option<u32>) -> Result<Self> {
        
        let sock_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK as i32,
                libc::SOCK_DGRAM as i32,
                libc::NETLINK_USERSOCK as i32, // args.protocol as i32,
            )
        };
        if sock_fd < 0 {
            return Err(anyhow::anyhow!(
                "Failed to create NetLink socket: {}",
                io::Error::last_os_error()
            ));
        }

        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = process::id() as u32;

        let bind_result = unsafe {
            libc::bind(
                sock_fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if bind_result < 0 {
            unsafe { libc::close(sock_fd); }
            return Err(anyhow::anyhow!(
                "Failed to bind NetLink socket: {}",
                io::Error::last_os_error()
            ));
        }

        Ok(Self { sock_fd })
    }

    pub fn client_send(&self, server_pid: u32, message: &str) -> Result<String> {
        let mut server_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        server_addr.nl_family = libc::AF_NETLINK as u16;
        server_addr.nl_pid = server_pid;

        let send_result = unsafe {
            libc::sendto(
                self.sock_fd,
                message.as_ptr() as *const libc::c_void,
                message.len(),
                0,
                &server_addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if send_result < 0 {
            return Err(anyhow::anyhow!(
                "Failed to send NetLink message: {}",
                io::Error::last_os_error()
            ));
        }

        let mut buf = vec![0u8; 1024];
        let mut sender_addr: libc::sockaddr = unsafe { std::mem::zeroed() };
        let mut addr_len = std::mem::size_of::<libc::sockaddr>() as libc::socklen_t;

        let n = unsafe {
            libc::recvfrom(
                self.sock_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut sender_addr as *mut libc::sockaddr,
                &mut addr_len,
            )
        };
        if n < 0 {
            return Err(anyhow::anyhow!(
                "Failed to receive NetLink message: {}",
                io::Error::last_os_error()
            ));
        }

        Ok(String::from_utf8_lossy(&buf[..n as usize]).to_string())
    }

    pub fn server_loop(&self, buffer_size: usize) -> Result<()> {
        let mut buf = vec![0u8; buffer_size];
        let mut sender_addr: libc::sockaddr = unsafe { std::mem::zeroed() };
        let mut addr_len = std::mem::size_of::<libc::sockaddr>() as libc::socklen_t;

        loop {
            let n = unsafe {
                libc::recvfrom(
                    self.sock_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    &mut sender_addr as *mut libc::sockaddr,
                    &mut addr_len,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                eprintln!("NetLink receive error: {}", err);
                continue;
            }
            if n == 0 {
                break;
            }
            let send_result = unsafe {
                libc::sendto(
                    self.sock_fd,
                    buf.as_ptr() as *const libc::c_void,
                    n as usize,
                    0,
                    &sender_addr as *const libc::sockaddr,
                    addr_len,
                )
            };
            if send_result < 0 {
                eprintln!(
                    "Failed to send NetLink response: {}",
                    io::Error::last_os_error()
                );
                continue;
            }
        }
        Ok(())
    }
}

// Wrapper for client
pub fn run_client(args: &Args) -> Result<()> {
    let netlink = Netlink::new( Some(args.server_pid))?;
    let response = netlink.client_send(args.server_pid, "Hello NetLink!")?;
    println!("Received: {}", response);
    Ok(())
}

// Wrapper for server
pub fn run_server(args: Args) -> Result<()> {
    let netlink = Netlink::new(None)?;
    netlink.server_loop(args.buffer_size)?;
    Ok(())
}

#[test]
pub fn test_netlink_communication() -> Result<()> {
    use nix::unistd::{fork, ForkResult};
    use nix::sys::wait::waitpid;

    println!("Testing NetLink communication...");

    // Netlink requires a single socket per process, using the PID of the current process.
    // We fork to have two processes with different PIDs.
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // Child process: Server
            let args = Args {
                protocol: 31,
                buffer_size: 1024,
                server_pid: 0,
                iterations: 1,
                message_size: 100,
                benchmark: false,
            };
            let netlink = Netlink::new( None)?;
            
            // Handle one message and exit
            let mut buf = vec![0u8; args.buffer_size];
            let mut sender_addr: libc::sockaddr = unsafe { std::mem::zeroed() };
            let mut addr_len = std::mem::size_of::<libc::sockaddr>() as libc::socklen_t;

            let n = unsafe {
                libc::recvfrom(
                    netlink.sock_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    &mut sender_addr as *mut libc::sockaddr,
                    &mut addr_len,
                )
            };
            if n > 0 {
                unsafe {
                    libc::sendto(
                        netlink.sock_fd,
                        buf.as_ptr() as *const libc::c_void,
                        n as usize,
                        0,
                        &sender_addr as *const libc::sockaddr,
                        addr_len,
                    );
                }
            }
            process::exit(0);
        }
        Ok(ForkResult::Parent { child }) => {
            // Parent process: Client
            thread::sleep(Duration::from_millis(100)); // Give child time to start and bind

            let args = Args {
                protocol: 31, 
                buffer_size: 1024,
                server_pid: child.as_raw() as u32,
                iterations: 1,
                message_size: 100,
                benchmark: false,
            };
            
            let netlink = Netlink::new( Some(args.server_pid))?;
            let test_message = "NetLink test message";
            let response = netlink.client_send(args.server_pid, test_message)?;

            if response != test_message {
                return Err(anyhow::anyhow!("Received wrong message content: expected {}, got {}", test_message, response));
            }

            println!("✅ NetLink communication test passed!");
            println!("   Successfully sent and received: {}", response);
            
            // Wait for child to exit
            waitpid(child, None)?;
        }
        Err(e) => return Err(anyhow::anyhow!("Fork failed: {}", e)),
    }

    Ok(())
}

