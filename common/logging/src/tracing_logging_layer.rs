use std::collections::HashMap;
use std::fs::{self, create_dir_all, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc::{self, Sender};
use std::thread;

lazy_static! {
    pub static ref TRACING_LOGGING_DEPENDENCIES: Vec<String> =
        vec!["libp2p".to_string(), "discv5".to_string()];
}

/// Layer that handles `INFO`, `WARN` and `ERROR` logs emitted per dependency and
/// writes them to a file. Dependencies are enabled via the `RUST_LOG` env flag.
pub struct LoggingLayer {
    pub file_writer_streams: HashMap<String, NonBlockingFileWriter>,
}

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

        let Some(file_writer) = self.file_writer_streams.get(target) else {
            return;
        };

        let mut visitor = LogMessageExtractor {
            message: String::default(),
        };

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
    pub fn new(path: &std::path::Path, max_file_size: u64) -> Result<Self, std::io::Error> {
        let (sender, receiver) = mpsc::channel();
        let path = path.to_path_buf();

        thread::spawn(move || {
            if !path.exists() {
                let mut dir = path.clone();
                dir.pop();

                // Create the necessary directories for the correct service and network.
                if !dir.exists() {
                    let res = create_dir_all(dir);

                    // If the directories cannot be created, warn and disable the logger.
                    match res {
                        Ok(_) => (),
                        Err(e) => {
                            eprintln!("Failed to create dir: {:?}", e);
                            return;
                        }
                    }
                }
            }

            eprintln!("{:?}", path);
            let mut file = match OpenOptions::new().create(true).append(true).open(&path) {
                Ok(file) => file,
                Err(e) => {
                    eprintln!("Failed to open file: {:?}", e);
                    return;
                }
            };

            for message in receiver {
                let should_clear_file = match NonBlockingFileWriter::get_file_size(&path) {
                    Ok(file_size) => file_size > max_file_size,
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
    fn record_debug(&mut self, _: &tracing_core::Field, value: &dyn std::fmt::Debug) {
        self.message = format!("{:?}", value);
    }
}

pub fn create_tracing_logging_layer() {}
