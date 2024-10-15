use lighthouse_metrics::{
    inc_counter, try_create_int_counter, IntCounter, Result as MetricsResult,
};
use std::io::{Result, Write};
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tracing::Value;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
pub const MAX_MESSAGE_WIDTH: usize = 40;

pub mod macros;
mod sse_logging_components;
pub mod tracing_logging_layer;
mod tracing_metrics_layer;

pub use sse_logging_components::SSELoggingComponents;
pub use sse_logging_components::SSE_LOGGING_COMPONENTS;
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

pub fn create_tracing_layer(
    base_tracing_log_path: PathBuf,
) -> (NonBlocking, WorkerGuard, NonBlocking, WorkerGuard) {
    let mut tracing_log_path = PathBuf::new();

    // Ensure that `tracing_log_path` only contains directories.
    for p in base_tracing_log_path.iter() {
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
        panic!("Failed to initialize libp2p rolling file appender");
    };

    let Ok(discv5_writer) = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .max_log_files(2)
        .filename_prefix("discv5")
        .filename_suffix("log")
        .build(tracing_log_path)
    else {
        panic!("Failed to initialize discv5 rolling file appender");
    };

    let (libp2p_non_blocking_writer, _libp2p_guard) = NonBlocking::new(libp2p_writer);
    let (discv5_non_blocking_writer, _discv5_guard) = NonBlocking::new(discv5_writer);

    (
        libp2p_non_blocking_writer,
        _libp2p_guard,
        discv5_non_blocking_writer,
        _discv5_guard,
    )
}
