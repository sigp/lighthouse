use chrono::Local;
use logroller::{LogRollerBuilder, Rotation, RotationSize};
use std::fmt::Write as FmtWrite;
use std::io::Write;
use std::path::PathBuf;
use tracing::Subscriber;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::{Layer, layer::Context};

pub struct Libp2pDiscv5TracingLayer {
    pub libp2p_non_blocking_writer: NonBlocking,
    _libp2p_guard: WorkerGuard,
    pub discv5_non_blocking_writer: NonBlocking,
    _discv5_guard: WorkerGuard,
}

impl<S> Layer<S> for Libp2pDiscv5TracingLayer
where
    S: Subscriber,
{
    fn event_enabled(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) -> bool {
        let target = event.metadata().target();
        target == "libp2p_gossipsub"
            || target.starts_with("libp2p_gossipsub::")
            || target == "discv5"
            || target.starts_with("discv5::")
    }

    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let target = meta.target();

        let mut writer = if target == "libp2p_gossipsub" || target.starts_with("libp2p_gossipsub::")
        {
            self.libp2p_non_blocking_writer.clone()
        } else if target == "discv5" || target.starts_with("discv5::") {
            self.discv5_non_blocking_writer.clone()
        } else {
            return;
        };

        let log_level = meta.level();
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");

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
        if !self.message.is_empty() {
            self.message.push(' ');
        }
        let _ = write!(&mut self.message, "{:?}", value);
    }
}

pub fn create_libp2p_discv5_tracing_layer(
    base_tracing_log_path: Option<PathBuf>,
    max_log_size: u64,
    file_mode: u32,
) -> Option<Libp2pDiscv5TracingLayer> {
    if let Some(mut tracing_log_path) = base_tracing_log_path {
        // Ensure that `tracing_log_path` only contains directories.
        for p in tracing_log_path.clone().iter() {
            tracing_log_path = tracing_log_path.join(p);
            if let Ok(metadata) = tracing_log_path.metadata()
                && !metadata.is_dir()
            {
                tracing_log_path.pop();
                break;
            }
        }

        let libp2p_writer =
            LogRollerBuilder::new(tracing_log_path.clone(), PathBuf::from("libp2p.log"))
                .rotation(Rotation::SizeBased(RotationSize::MB(max_log_size)))
                .max_keep_files(1)
                .file_mode(file_mode);

        let discv5_writer =
            LogRollerBuilder::new(tracing_log_path.clone(), PathBuf::from("discv5.log"))
                .rotation(Rotation::SizeBased(RotationSize::MB(max_log_size)))
                .max_keep_files(1)
                .file_mode(file_mode);

        let libp2p_writer = match libp2p_writer.build() {
            Ok(writer) => writer,
            Err(e) => {
                eprintln!("Failed to initialize libp2p rolling file appender: {e}");
                std::process::exit(1);
            }
        };

        let discv5_writer = match discv5_writer.build() {
            Ok(writer) => writer,
            Err(e) => {
                eprintln!("Failed to initialize discv5 rolling file appender: {e}");
                std::process::exit(1);
            }
        };

        let (libp2p_non_blocking_writer, _libp2p_guard) = NonBlocking::new(libp2p_writer);
        let (discv5_non_blocking_writer, _discv5_guard) = NonBlocking::new(discv5_writer);

        Some(Libp2pDiscv5TracingLayer {
            libp2p_non_blocking_writer,
            _libp2p_guard,
            discv5_non_blocking_writer,
            _discv5_guard,
        })
    } else {
        None
    }
}
