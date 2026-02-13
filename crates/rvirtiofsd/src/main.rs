use clap::Parser;
use rvirtiofsd::{create_passthrough_fs, FuseServer};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, error, info};
use vhost_user_backend::bitmap::BitmapMmapRegion;
use virtio_queue::{DescriptorChain, Queue, QueueOwnedT, QueueT};
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

type LoggedMemory = GuestMemoryMmap<BitmapMmapRegion>;

#[derive(Parser, Debug)]
#[command(
    name = "rvirtiofsd",
    about = "virtiofsd wrapper with UDS and stdin support"
)]
struct Args {
    /// Root directory to serve
    #[arg(required = true)]
    root: PathBuf,

    /// Unix Domain Socket path to listen on (standard vhost-user)
    #[arg(short, long)]
    listen: Option<PathBuf>,

    /// Tag for the virtiofs device (vhost-user only)
    #[arg(short, long, default_value = "virtiofs")]
    tag: String,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(&args.log_level)
        .with_writer(std::io::stderr)
        .init();

    let root = if args.root.exists() {
        args.root.canonicalize().unwrap_or(args.root)
    } else {
        args.root
    };

    info!("Starting rvirtiofsd serving {:?}", root);

    if let Some(path) = args.listen {
        let fs = create_passthrough_fs(root);
        run_vhost_user(fs, path, args.tag).await?;
    } else {
        info!("Serving FUSE over stdin/stdout");
        let fs = create_passthrough_fs(root);
        let server = Arc::new(FuseServer::new(fs));
        run_stdio_fuse(server).await?;
    }

    Ok(())
}

async fn run_vhost_user(
    fs: rvirtiofsd::FileSystem,
    path: PathBuf,
    tag: String,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting vhost-user on {:?}", path);

    use vhost::vhost_user::Listener;
    use vhost_user_backend::VhostUserDaemon;
    use virtiofsd::vhost_user::VhostUserFsBackendBuilder;

    let backend = VhostUserFsBackendBuilder::default()
        .set_tag(Some(tag))
        .build(fs)
        .map_err(|e| anyhow::anyhow!("Failed to build backend: {}", e))?;

    let mut daemon = VhostUserDaemon::new(
        "virtiofsd-backend".to_string(),
        Arc::new(backend),
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .map_err(|e| anyhow::anyhow!("Failed to create daemon: {}", e))?;

    let listener = Listener::new(&path, true)
        .map_err(|e| anyhow::anyhow!("Failed to create listener: {}", e))?;

    info!("Waiting for vhost-user socket connection on {:?}...", path);
    // VhostUserDaemon::start in 0.17.0 takes a Listener
    daemon
        .start(listener)
        .map_err(|e| anyhow::anyhow!("Failed to start daemon: {:?}", e))?;

    info!("Client connected, servicing requests");
    daemon
        .wait()
        .map_err(|e| anyhow::anyhow!("Daemon wait failed: {:?}", e))?;

    Ok(())
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
struct InHeader {
    len: u32,
    opcode: u32,
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    padding: u32,
}
unsafe impl ByteValued for InHeader {}

async fn run_stdio_fuse(
    server: Arc<FuseServer<rvirtiofsd::FileSystem>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    let mem_size = 1024 * 1024;
    let mem: LoggedMemory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), mem_size)]).unwrap();

    let desc_table_addr = GuestAddress(0);
    let buffer_addr = GuestAddress(1024);

    loop {
        let mut header_buf = [0u8; 40];
        if stdin.read_exact(&mut header_buf).is_err() {
            break;
        }

        let header: InHeader = *InHeader::from_slice(&header_buf).unwrap();
        debug!(
            "Received FUSE request: opcode={}, unique={}",
            header.opcode, header.unique
        );

        if header.len > mem_size as u32 - 1024 {
            error!("FUSE request too large: {}", header.len);
            continue;
        }

        let mut full_packet = vec![0u8; header.len as usize];
        full_packet[..40].copy_from_slice(&header_buf);
        if stdin.read_exact(&mut full_packet[40..]).is_err() {
            break;
        }

        mem.write_slice(&full_packet, buffer_addr).unwrap();

        let resp_addr = buffer_addr.checked_add(header.len as u64).unwrap();
        let resp_max_len = (mem_size as u64 - resp_addr.raw_value()) as u32;

        let desc_chain = create_fake_descriptor_chain(
            &mem,
            desc_table_addr,
            buffer_addr,
            header.len,
            resp_addr,
            resp_max_len,
        );

        let reader = virtiofsd::descriptor_utils::Reader::new(&mem, desc_chain.clone()).unwrap();
        let writer = virtiofsd::descriptor_utils::Writer::new(&mem, desc_chain).unwrap();

        match server.handle_message(reader, writer, None::<&mut ()>) {
            Ok(len) => {
                if len > 0 {
                    let mut resp = vec![0u8; len];
                    mem.read_slice(&mut resp, resp_addr).unwrap();
                    stdout.write_all(&resp)?;
                    stdout.flush()?;
                }
            }
            Err(e) => {
                error!("Error handling FUSE message: {}", e);
            }
        }
    }

    Ok(())
}

fn create_fake_descriptor_chain(
    memory: &LoggedMemory,
    desc_table_addr: GuestAddress,
    req_addr: GuestAddress,
    req_len: u32,
    resp_addr: GuestAddress,
    resp_max_len: u32,
) -> DescriptorChain<&LoggedMemory> {
    #[repr(C)]
    #[derive(Copy, Clone, Debug, Default)]
    struct VirtqDesc {
        addr: u64,
        len: u32,
        flags: u16,
        next: u16,
    }
    unsafe impl ByteValued for VirtqDesc {}

    let d1 = VirtqDesc {
        addr: req_addr.raw_value(),
        len: req_len,
        flags: 1, // VIRTQ_DESC_F_NEXT
        next: 1,
    };
    let d2 = VirtqDesc {
        addr: resp_addr.raw_value(),
        len: resp_max_len,
        flags: 2, // VIRTQ_DESC_F_WRITE
        next: 0,
    };

    memory.write_obj(d1, desc_table_addr).unwrap();
    memory
        .write_obj(d2, desc_table_addr.checked_add(16).unwrap())
        .unwrap();

    #[repr(C)]
    #[derive(Copy, Clone, Debug, Default)]
    struct VirtqAvail {
        flags: u16,
        idx: u16,
        ring: [u16; 1],
    }
    unsafe impl ByteValued for VirtqAvail {}

    let avail_addr = desc_table_addr.checked_add(32).unwrap();
    let avail = VirtqAvail {
        flags: 0,
        idx: 1,
        ring: [0],
    };
    memory.write_obj(avail, avail_addr).unwrap();

    let mut queue = Queue::new(128).unwrap();
    queue.try_set_desc_table_address(desc_table_addr).unwrap();
    queue.try_set_avail_ring_address(avail_addr).unwrap();
    queue.set_ready(true);

    queue.iter(memory).unwrap().next().unwrap()
}
