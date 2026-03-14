use perfetto_sdk::{
    heap_buffer::HeapBuffer,
    pb_msg::{PbMsg, PbMsgWriter},
    protos::config::{
        data_source_config::DataSourceConfig,
        trace_config::{BufferConfig, DataSource, TraceConfig},
        track_event::track_event_config::TrackEventConfig,
    },
    tracing_session::TracingSession,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

struct SendSyncSession(TracingSession);
unsafe impl Send for SendSyncSession {}
unsafe impl Sync for SendSyncSession {}

pub struct PerfettoPull {
    session: Arc<Mutex<SendSyncSession>>,
    running: Arc<AtomicBool>,
    reader_thread: Option<thread::JoinHandle<()>>,
}

impl PerfettoPull {
    pub fn new_system(socket: &str) -> Result<Self, Box<dyn std::error::Error>> {
        std::env::set_var("PERFETTO_CONSUMER_SOCK_NAME", socket);
        let session = TracingSession::system()?;
        Ok(Self {
            session: Arc::new(Mutex::new(SendSyncSession(session))),
            running: Arc::new(AtomicBool::new(false)),
            reader_thread: None,
        })
    }

    pub fn new_in_process() -> Result<Self, Box<dyn std::error::Error>> {
        let session = TracingSession::in_process()?;
        Ok(Self {
            session: Arc::new(Mutex::new(SendSyncSession(session))),
            running: Arc::new(AtomicBool::new(false)),
            reader_thread: None,
        })
    }

    pub fn start(&mut self) {
        let session_config = {
            let writer = PbMsgWriter::new();
            let hb = HeapBuffer::new(writer.stream_writer());
            let mut msg = PbMsg::new(&writer).unwrap();
            {
                let mut cfg = TraceConfig { msg: &mut msg };
                cfg.set_buffers(|buf_cfg: &mut BufferConfig| {
                    buf_cfg.set_size_kb(1024);
                });
                cfg.set_data_sources(|data_sources: &mut DataSource| {
                    data_sources.set_config(|ds_cfg: &mut DataSourceConfig| {
                        ds_cfg.set_name("track_event");
                        ds_cfg.set_track_event_config(|te_cfg: &mut TrackEventConfig| {
                            te_cfg.set_enabled_categories("default");
                            te_cfg.set_enabled_categories("tracing");
                        });
                    });
                });
            }
            msg.finalize();
            let cfg_size = writer.stream_writer().get_written_size();
            let mut cfg_buffer: Vec<u8> = vec![0u8; cfg_size];
            hb.copy_into(&mut cfg_buffer);
            cfg_buffer
        };

        {
            let mut session_lock = self.session.lock().unwrap();
            session_lock.0.setup(&session_config);
            session_lock.0.start_blocking();
        }

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let session_arc = self.session.clone();

        self.reader_thread = Some(thread::spawn(move || {
            let buffer = Arc::new(Mutex::new(Vec::new()));
            while running.load(Ordering::SeqCst) {
                {
                    let mut session_lock = session_arc.lock().unwrap();
                    let buffer_clone = Arc::clone(&buffer);
                    session_lock.0.read_trace_blocking(move |data, _has_more| {
                        let mut b = buffer_clone.lock().unwrap();
                        b.extend_from_slice(data);
                        Self::process_data(&mut b);
                    });
                }
                thread::sleep(Duration::from_millis(100));
            }

            // Final read
            {
                let mut session_lock = session_arc.lock().unwrap();
                let buffer_clone = Arc::clone(&buffer);
                session_lock.0.read_trace_blocking(move |data, _has_more| {
                    let mut b = buffer_clone.lock().unwrap();
                    b.extend_from_slice(data);
                    Self::process_data(&mut b);
                });
            }
        }));
    }

    pub fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.running.store(false, Ordering::SeqCst);

        if let Some(handle) = self.reader_thread.take() {
            let _ = handle.join();
        }

        let mut session_lock = self.session.lock().unwrap();
        // Flush must happen before stop — flushing after stop is a no-op
        session_lock.0.flush_blocking(Duration::from_millis(500));
        session_lock.0.stop_blocking();

        Ok(())
    }

    pub fn process_data(buffer: &mut Vec<u8>) {
        let mut offset = 0;
        while offset < buffer.len() {
            match decode_varint(&buffer[offset..]) {
                Some((tag, tag_len)) => {
                    let wire_type = tag & 0x07;
                    match wire_type {
                        0 => {
                            // Varint
                            if let Some((_, val_len)) = decode_varint(&buffer[offset + tag_len..]) {
                                offset += tag_len + val_len;
                            } else {
                                break;
                            }
                        }
                        1 => {
                            // 64-bit
                            if offset + tag_len + 8 <= buffer.len() {
                                offset += tag_len + 8;
                            } else {
                                break;
                            }
                        }
                        2 => {
                            // Length-delimited
                            if let Some((len, len_len)) = decode_varint(&buffer[offset + tag_len..])
                            {
                                let data_start = offset + tag_len + len_len;
                                let data_end = data_start + len as usize;
                                if data_end <= buffer.len() {
                                    if tag == 10 {
                                        // Field 1: TracePacket
                                        let packet_data = &buffer[data_start..data_end];
                                        Self::process_packet(packet_data);
                                    }
                                    offset = data_end;
                                } else {
                                    break; // Incomplete data
                                }
                            } else {
                                break; // Incomplete length
                            }
                        }
                        5 => {
                            // 32-bit
                            if offset + tag_len + 4 <= buffer.len() {
                                offset += tag_len + 4;
                            } else {
                                break;
                            }
                        }
                        _ => {
                            tracing::warn!(
                                "Invalid protobuf wire type {}, discarding buffer",
                                wire_type
                            );
                            offset = buffer.len();
                            break;
                        }
                    }
                }
                None => {
                    break; // Incomplete tag
                }
            }
        }

        if offset > 0 {
            buffer.drain(0..offset);
        }
    }

    fn process_packet(packet_data: &[u8]) {
        println!("raw: {:?}", packet_data);
    }
}

pub fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0;
    for (i, &b) in data.iter().enumerate() {
        if i >= 10 {
            return None; // Invalid varint
        }
        value |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_varint() {
        assert_eq!(decode_varint(&[0x0A]), Some((10, 1)));
        assert_eq!(decode_varint(&[0x96, 0x01]), Some((150, 2)));
        assert_eq!(decode_varint(&[0x80]), None); // Incomplete
        assert_eq!(decode_varint(&[]), None); // Empty
    }

    #[test]
    fn test_process_data_complete() {
        // Build a buffer with a complete TracePacket: tag=10, len=3, data=[1, 2, 3]
        let mut buffer = vec![10, 3, 1, 2, 3];
        PerfettoPull::process_data(&mut buffer);
        assert!(buffer.is_empty(), "Complete buffer should be cleared");
    }

    #[test]
    fn test_process_data_partial() {
        // Tag=10, len=3, but only 2 items of data provided
        let mut buffer = vec![10, 3, 1, 2];
        PerfettoPull::process_data(&mut buffer);
        assert_eq!(buffer.len(), 4, "Partial buffer should remain untouched");
    }

    #[test]
    fn test_process_data_multiple_and_partial() {
        // packet 1: tag=10, len=3, data
        let mut buffer = vec![10, 3, 1, 2, 3];
        // packet 2: tag=10, len=2, data
        buffer.extend_from_slice(&[10, 2, 4, 5]);
        // packet 3 (partial): tag=10, len=5, data incomplete
        buffer.extend_from_slice(&[10, 5, 6, 7]);

        PerfettoPull::process_data(&mut buffer);

        // 1st and 2nd should be processed, leaving only the 3rd partial packet
        assert_eq!(buffer, vec![10, 5, 6, 7], "Should leave only partial data");

        // Complete the 3rd packet
        buffer.extend_from_slice(&[8, 9, 10]);
        PerfettoPull::process_data(&mut buffer);

        assert!(buffer.is_empty(), "Completed data should be fully cleared");
    }
}
