use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::thread;

pub const MAX_FILE_SIZE_IN_BYTES: u64 = 100_000_000;

pub const BASE_FILE_PATH: &str = "";

lazy_static! {
    pub static ref FILE_WRITER_STREAMS: HashMap<String, Option<NonBlockingFileWriter>> = {
        let mut m = HashMap::new();
        let libp2p_logging_thread = NonBlockingFileWriter::new(Path::new("libp2p")).ok();
        let discv5_logging_thread = NonBlockingFileWriter::new(Path::new("discv5")).ok();
        m.insert("libp2p".to_string(), libp2p_logging_thread);
        m.insert("discv5".to_string(), discv5_logging_thread);
        m
    };
}

/// Layer that handles `INFO`, `WARN` and `ERROR` logs emitted per dependency and
/// writes them to a file. Dependencies are enabled via the `RUST_LOG` env flag.
pub struct LoggingLayer;

impl<S: tracing_core::Subscriber> tracing_subscriber::layer::Layer<S> for LoggingLayer {
    fn on_event(
        &self,
        event: &tracing_core::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let meta = event.metadata();

        let target = match meta.target().split_once("::") {
            Some((crate_name, _)) => crate_name,
            None => "unknown",
        };

        let Some(get_file_writer_stream) = FILE_WRITER_STREAMS.get(target) else {
            return;
        };

        let Some(file_writer) = get_file_writer_stream else {
            return;
        };

        let mut visitor = LogMessageExtractor { message: String::default()};

        event.record(&mut visitor);

        match *meta.level() {
            tracing_core::Level::INFO => {
                let _ = file_writer.write(visitor.message);
                ()
            }
            tracing_core::Level::WARN => {
                let _ = file_writer.write(visitor.message);
                ()
            }
            tracing_core::Level::ERROR => {
                let _ = file_writer.write(visitor.message);
                ()
            }
            _ => {}
        }
    }
}

pub struct NonBlockingFileWriter {
    sender: Sender<String>,
}

impl NonBlockingFileWriter {
    pub fn new(path: &std::path::Path) -> Result<Self, std::io::Error> {
        let (sender, receiver) = mpsc::channel();
        let path = path.to_path_buf();

        thread::spawn(move || {
            let mut file = match OpenOptions::new().create(true).append(true).open(&path) {
                Ok(file) => file,
                Err(e) => {
                    eprintln!("Failed to open file: {:?}", e);
                    return;
                }
            };

            for message in receiver {
                let should_clear_file = match NonBlockingFileWriter::get_file_size(&path) {
                    Ok(file_size) => file_size > MAX_FILE_SIZE_IN_BYTES,
                    Err(_) => false,
                };

                if should_clear_file {
                    let _ = NonBlockingFileWriter::clear_file(&path);
                }

                if let Err(e) = writeln!(file, "{}", message) {
                    eprintln!("Failed to write to file: {:?}", e);
                }
            }
        });

        Ok(NonBlockingFileWriter { sender })
    }

    pub fn write(&self, message: String) -> Result<(), std::io::Error> {
        self.sender
            .send(message)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn get_file_size(path: &PathBuf) -> std::io::Result<u64> {
        let metadata = fs::metadata(path)?;
        Ok(metadata.len())
    }

    fn clear_file(path: &PathBuf) -> std::io::Result<()> {
        File::create(path)?;
        Ok(())
    }
}

struct LogMessageExtractor {
    message: String,
}

impl tracing_core::field::Visit for LogMessageExtractor {
    fn record_debug(&mut self, field: &tracing_core::Field, value: &dyn std::fmt::Debug) {
        self.message= format!("{}\n{}={:?}", self.message, field.name(), value);
    }
}