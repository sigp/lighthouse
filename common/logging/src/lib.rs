use chrono::Local;
use metrics::{inc_counter, try_create_int_counter, IntCounter, Result as MetricsResult};
use std::io::Write;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tracing::Subscriber;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

pub const MAX_MESSAGE_WIDTH: usize = 40;

pub mod macros;
mod sse_logging_components;
pub mod tracing_logging_layer;
mod tracing_metrics_layer;

pub use sse_logging_components::SSELoggingComponents;
pub use tracing_metrics_layer::MetricsLayer;

/// The minimum interval between log messages indicating that a queue is full.
const LOG_DEBOUNCE_INTERVAL: Duration = Duration::from_secs(30);

pub static INFOS_TOTAL: LazyLock<MetricsResult<IntCounter>> =
    LazyLock::new(|| try_create_int_counter("info_total", "Count of infos logged"));
pub static WARNS_TOTAL: LazyLock<MetricsResult<IntCounter>> =
    LazyLock::new(|| try_create_int_counter("warn_total", "Count of warns logged"));
pub static ERRORS_TOTAL: LazyLock<MetricsResult<IntCounter>> =
    LazyLock::new(|| try_create_int_counter("error_total", "Count of errors logged"));
pub static CRITS_TOTAL: LazyLock<MetricsResult<IntCounter>> =
    LazyLock::new(|| try_create_int_counter("crit_total", "Count of crits logged"));

/// Provides de-bounce functionality for logging.
#[derive(Default)]
pub struct TimeLatch(Option<Instant>);

impl TimeLatch {
    /// Only returns true once every `LOG_DEBOUNCE_INTERVAL`.
    pub fn elapsed(&mut self) -> bool {
        let now = Instant::now();

        let is_elapsed = self.0.map_or(false, |elapse_time| now > elapse_time);

        if is_elapsed || self.0.is_none() {
            self.0 = Some(now + LOG_DEBOUNCE_INTERVAL);
        }

        is_elapsed
    }
}

pub struct Libp2pDiscv5TracingLayer {
    pub libp2p_non_blocking_writer: NonBlocking,
    pub _libp2p_guard: WorkerGuard,
    pub discv5_non_blocking_writer: NonBlocking,
    pub _discv5_guard: WorkerGuard,
}

impl<S> Layer<S> for Libp2pDiscv5TracingLayer
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
            "gossipsub" => self.libp2p_non_blocking_writer.clone(),
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

pub fn create_libp2p_discv5_tracing_layer(
    base_tracing_log_path: Option<PathBuf>,
) -> Libp2pDiscv5TracingLayer {
    if let Some(mut tracing_log_path) = base_tracing_log_path {
        // Ensure that `tracing_log_path` only contains directories.
        for p in tracing_log_path.clone().iter() {
            tracing_log_path = tracing_log_path.join(p);
            if let Ok(metadata) = tracing_log_path.metadata() {
                if !metadata.is_dir() {
                    tracing_log_path.pop();
                    break;
                }
            }
        }
        let Ok(libp2p_writer) = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .max_log_files(2)
            .filename_prefix("libp2p")
            .filename_suffix("log")
            .build(tracing_log_path.clone())
        else {
            eprintln!("Failed to initialize libp2p rolling file appender");
            std::process::exit(1);
        };

        let Ok(discv5_writer) = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .max_log_files(2)
            .filename_prefix("discv5")
            .filename_suffix("log")
            .build(tracing_log_path)
        else {
            eprintln!("Failed to initialize discv5 rolling file appender");
            std::process::exit(1);
        };

        let (libp2p_non_blocking_writer, _libp2p_guard) = NonBlocking::new(libp2p_writer);
        let (discv5_non_blocking_writer, _discv5_guard) = NonBlocking::new(discv5_writer);

        let libp2p_discv5_tracing_layer = Libp2pDiscv5TracingLayer {
            libp2p_non_blocking_writer,
            _libp2p_guard,
            discv5_non_blocking_writer,
            _discv5_guard,
        };

        libp2p_discv5_tracing_layer
    } else {
        let (libp2p_non_blocking_writer, _libp2p_guard) = NonBlocking::new(std::io::sink());
        let (discv5_non_blocking_writer, _discv5_guard) = NonBlocking::new(std::io::sink());
        let libp2p_discv5_tracing_layer = Libp2pDiscv5TracingLayer {
            libp2p_non_blocking_writer,
            _libp2p_guard,
            discv5_non_blocking_writer,
            _discv5_guard,
        };

        libp2p_discv5_tracing_layer
    }
}
