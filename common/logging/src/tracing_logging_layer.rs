use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Sender, self};
use std::thread;
use std::io::Write;
use std::time::{SystemTime, Duration};

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

        let target = &[target];

        match *meta.level() {
            tracing_core::Level::INFO => {},
            tracing_core::Level::WARN => {},
            tracing_core::Level::ERROR => {},
            _ => {}
        }
    }
}

struct NonBlockingFileWriter {
    sender: Sender<String>,
    path: PathBuf,
}

impl NonBlockingFileWriter {
    fn new(path: &std::path::Path) -> Result<Self, std::io::Error> {
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

            let mut should_clear_file = false;

            for message in receiver {
                should_clear_file = match NonBlockingFileWriter::get_file_size(&path) {
                    Ok(file_size) => file_size > 0u64,
                    Err(_) => false,
                };

                if should_clear_file {
                    NonBlockingFileWriter::clear_file(&path);
                }

                if let Err(e) = writeln!(file, "{}", message) {
                    eprintln!("Failed to write to file: {:?}", e);
                }
            }
        });

        Ok(NonBlockingFileWriter { sender, path })

    }

    fn write(&self, message: String) -> Result<(), std::io::Error> {
        self.sender.send(message).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
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