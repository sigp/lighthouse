use std::fs;
use std::path::{Path, PathBuf};
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

// Delete the oldest file in a supplied directory
// as long as the directory contains file count >= min_file_count.
// Note that we ignore child directories.
fn delete_oldest_file(dir: &Path, min_file_count: u32) -> std::io::Result<()> {
    let mut oldest_write: Option<SystemTime> =  None;
    let mut file_to_delete: Option<PathBuf> = None;
    let mut file_count = 0u32;
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                // TODO raise an error
                return Ok(())
            } else {         
                let last_write = get_last_modified_date(&path)?;

                file_count += 1;

                let Some(write) = oldest_write else {
                    oldest_write = Some(last_write);
                    file_to_delete = Some(path);
                    continue
                };

                if last_write < write {
                    oldest_write = Some(last_write);
                    file_to_delete = Some(path);
                }
            }
        }
    }

    let Some(file) = file_to_delete else {
        // TODO 
        return Ok(());
    };

    if file_count >= min_file_count {
      
        // TODO delete file
    }

    Ok(())
}

fn get_last_modified_date(path: &std::path::Path) -> std::io::Result<SystemTime> {
    let metadata = fs::metadata(path)?;
    let last_modified = metadata.modified()?;
    Ok(last_modified)
}