use chrono::{naive::Days, prelude::*};
use slog::{debug, warn};
use std::io::Write;
use tracing::Subscriber;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

pub struct LoggingLayer {
    pub libp2p_non_blocking_writer: NonBlocking,
    pub libp2p_guard: WorkerGuard,
    pub discv5_non_blocking_writer: NonBlocking,
    pub discv5_guard: WorkerGuard,
}

impl<S> Layer<S> for LoggingLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<S>) {
        let meta = event.metadata();
        let log_level = meta.level();
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let target = match meta.target().split_once("::") {
            Some((crate_name, _)) => crate_name,
            None => "unknown",
        };

        let mut writer = match target {
            "libp2p_gossipsub" => self.libp2p_non_blocking_writer.clone(),
            "discv5" => self.discv5_non_blocking_writer.clone(),
            _ => return,
        };

        let mut visitor = LogMessageExtractor {
            message: String::default(),
        };

        event.record(&mut visitor);
        let message = format!("{} {} {}\n", timestamp, log_level, visitor.message);

        if let Err(e) = writer.write_all(message.as_bytes()) {
            eprintln!("Failed to write log: {}", e);
        }
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

/// Creates a long lived async task that routinely deletes old tracing log files
pub async fn cleanup_logging_task(path: std::path::PathBuf, log: slog::Logger) {
    loop {
        // Delay for 1 day and then prune old logs
        tokio::time::sleep(std::time::Duration::from_secs(60 * 60 * 24)).await;

        let Some(yesterday_date) = chrono::prelude::Local::now()
            .naive_local()
            .checked_sub_days(Days::new(1))
        else {
            warn!(log, "Could not calculate the current date");
            return;
        };

        // Search for old log files
        let dir = path.as_path();

        if dir.is_dir() {
            let Ok(files) = std::fs::read_dir(dir) else {
                warn!(log, "Could not read log directory contents"; "path" => ?dir);
                break;
            };

            for file in files {
                let Ok(dir_entry) = file else {
                    warn!(log, "Could not read file");
                    continue;
                };

                let Ok(file_name) = dir_entry.file_name().into_string() else {
                    warn!(log, "Could not read file"; "file" => ?dir_entry);
                    continue;
                };

                if file_name.starts_with("libp2p.log") | file_name.starts_with("discv5.log") {
                    let log_file_date = file_name.split('.').collect::<Vec<_>>();
                    if log_file_date.len() == 3 {
                        let Ok(log_file_date_type) =
                            NaiveDate::parse_from_str(log_file_date[2], "%Y-%m-%d")
                        else {
                            warn!(log, "Could not parse log file date"; "file" => file_name);
                            continue;
                        };

                        if log_file_date_type < yesterday_date.into() {
                            // Delete the file, its too old
                            debug!(log, "Removing old log file"; "file" => &file_name);
                            if let Err(e) = std::fs::remove_file(dir_entry.path()) {
                                warn!(log, "Failed to remove log file"; "file" => file_name, "error" => %e);
                            }
                        }
                    }
                }
            }
        }
    }
}
