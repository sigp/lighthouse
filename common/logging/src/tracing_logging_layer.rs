use chrono::prelude::Local;
use std::collections::HashMap;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::sync::mpsc::{self, Sender};
use std::thread;

lazy_static! {
    pub static ref TRACING_LOGGING_DEPENDENCIES: Vec<String> =
        vec!["libp2p_gossipsub".to_string(), "discv5".to_string()];
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

        let _ = file_writer.write(visitor.message);
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

                    match res {
                        Ok(_) => (),
                        Err(e) => {
                            eprintln!("Failed to create dir: {:?}", e);
                            return;
                        }
                    }
                }
            }

            let mut file = match OpenOptions::new().create(true).append(true).open(&path) {
                Ok(file) => file,
                Err(e) => {
                    eprintln!("Failed to open file: {:?}", e);
                    return;
                }
            };

            for message in receiver {
                let should_truncate_file = match NonBlockingFileWriter::get_file_size(&file) {
                    Ok(file_size) => file_size > max_file_size,
                    Err(_) => false,
                };

                if should_truncate_file {
                    let _ = NonBlockingFileWriter::truncate_file(&mut file, max_file_size / 2);
                }

                if let Err(e) = writeln!(file, "{}", message) {
                    eprintln!("Failed to write to file: {:?}", e);
                }
            }
        });

        Ok(NonBlockingFileWriter { sender })
    }

    pub fn write(&self, mut message: String) -> Result<(), std::io::Error> {
        message = format!("{} {}", self.timestamp_now(), message);
        self.sender
            .send(message)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    pub fn get_file_size(file: &File) -> std::io::Result<u64> {
        let metadata = file.metadata()?;
        Ok(metadata.len())
    }

    pub fn timestamp_now(&self) -> String {
        Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
    }

    fn truncate_file(file: &mut File, truncate_position: u64) -> std::io::Result<()> {
        file.set_len(truncate_position)?;
        file.seek(SeekFrom::End(0))?;
        Ok(())
    }
}

struct LogMessageExtractor {
    message: String,
}

impl tracing_core::field::Visit for LogMessageExtractor {
    fn record_debug(&mut self, _: &tracing_core::Field, value: &dyn std::fmt::Debug) {
        self.message = format!("{} {:?}", self.message, value);
    }
}

#[cfg(test)]
mod test {
    use crate::NonBlockingFileWriter;
    use std::{
        fs::{self},
        thread,
        time::Duration,
    };
    use tempfile::{Builder as TempDirBuilder, TempDir};

    const DUMMY_TEXT: &str = r#"
        Lorem ipsum dolor sit amet, 
        consectetur adipiscing elit, 
        sed do eiusmod tempor incididunt 
        ut labore et dolore magna aliqua. 
        Ut enim ad minim veniam, quis nostrud 
        exercitation ullamco laboris nisi ut 
        aliquip ex ea commodo consequat. 
        Duis aute irure dolor in reprehenderit 
        in voluptate velit esse cillum dolore eu 
        fugiat nulla pariatur. Excepteur sint occaecat 
        cupidatat non proident, sunt in culpa qui officia 
        deserunt mollit anim id est laborum.
    "#;

    const MAX_FILE_SIZE: u64 = 100;

    #[test]
    fn test_file_truncate() {
        let file_path = tempdir().path().join("foo.log");
        let non_blocking_file_writer =
            NonBlockingFileWriter::new(file_path.as_path(), MAX_FILE_SIZE).unwrap();

        non_blocking_file_writer
            .write(DUMMY_TEXT.to_string())
            .unwrap();
        thread::sleep(Duration::from_millis(100));
        let file = fs::File::open(&file_path).unwrap();
        let file_size = NonBlockingFileWriter::get_file_size(&file).unwrap();
        assert!(file_size > MAX_FILE_SIZE);

        non_blocking_file_writer.write("".to_string()).unwrap();
        thread::sleep(Duration::from_millis(100));
        let file = fs::File::open(&file_path).unwrap();
        let file_size = NonBlockingFileWriter::get_file_size(&file).unwrap();
        assert!(file_size <= MAX_FILE_SIZE);
    }

    fn tempdir() -> TempDir {
        TempDirBuilder::new()
            .prefix("non_blocking_file_writer_test")
            .tempdir()
            .expect("Cannot create a temporary directory")
    }
}
