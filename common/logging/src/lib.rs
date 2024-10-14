use lighthouse_metrics::{
    inc_counter, try_create_int_counter, IntCounter, Result as MetricsResult,
};
use slog_term::Decorator;
use std::io::{Result, Write};
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tracing::Value;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
pub const MAX_MESSAGE_WIDTH: usize = 40;

pub mod async_record;
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

pub struct AlignedTermDecorator<D: Decorator> {
    wrapped: D,
    message_width: usize,
}

impl<D: Decorator> AlignedTermDecorator<D> {
    pub fn new(decorator: D, message_width: usize) -> Self {
        AlignedTermDecorator {
            wrapped: decorator,
            message_width,
        }
    }
}

impl<D: Decorator> Decorator for AlignedTermDecorator<D> {
    fn with_record<F>(
        &self,
        record: &slog::Record,
        _logger_values: &slog::OwnedKVList,
        f: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut dyn slog_term::RecordDecorator) -> std::io::Result<()>,
    {
        match record.level() {
            slog::Level::Info => inc_counter(&INFOS_TOTAL),
            slog::Level::Warning => inc_counter(&WARNS_TOTAL),
            slog::Level::Error => inc_counter(&ERRORS_TOTAL),
            slog::Level::Critical => inc_counter(&CRITS_TOTAL),
            _ => (),
        }

        self.wrapped.with_record(record, _logger_values, |deco| {
            f(&mut AlignedRecordDecorator::new(deco, self.message_width))
        })
    }
}

struct AlignedRecordDecorator<'a> {
    wrapped: &'a mut dyn slog_term::RecordDecorator,
    message_count: usize,
    message_active: bool,
    ignore_comma: bool,
    message_width: usize,
}

impl<'a> AlignedRecordDecorator<'a> {
    fn new(
        decorator: &'a mut dyn slog_term::RecordDecorator,
        message_width: usize,
    ) -> AlignedRecordDecorator<'a> {
        AlignedRecordDecorator {
            wrapped: decorator,
            message_count: 0,
            ignore_comma: false,
            message_active: false,
            message_width,
        }
    }

    fn filtered_write(&mut self, buf: &[u8]) -> Result<usize> {
        if self.ignore_comma {
            //don't write comma
            self.ignore_comma = false;
            Ok(buf.len())
        } else if self.message_active {
            self.wrapped.write(buf).inspect(|n| self.message_count += n)
        } else {
            self.wrapped.write(buf)
        }
    }
}

impl<'a> Write for AlignedRecordDecorator<'a> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.iter().any(u8::is_ascii_control) {
            let filtered = buf
                .iter()
                .cloned()
                .map(|c| if !is_ascii_control(&c) { c } else { b'_' })
                .collect::<Vec<u8>>();
            self.filtered_write(&filtered)
        } else {
            self.filtered_write(buf)
        }
    }

    fn flush(&mut self) -> Result<()> {
        self.wrapped.flush()
    }
}

impl<'a> slog_term::RecordDecorator for AlignedRecordDecorator<'a> {
    fn reset(&mut self) -> Result<()> {
        self.message_active = false;
        self.message_count = 0;
        self.ignore_comma = false;
        self.wrapped.reset()
    }

    fn start_whitespace(&mut self) -> Result<()> {
        self.wrapped.start_whitespace()
    }

    fn start_msg(&mut self) -> Result<()> {
        self.message_active = true;
        self.ignore_comma = false;
        self.wrapped.start_msg()
    }

    fn start_timestamp(&mut self) -> Result<()> {
        self.wrapped.start_timestamp()
    }

    fn start_level(&mut self) -> Result<()> {
        self.wrapped.start_level()
    }

    fn start_comma(&mut self) -> Result<()> {
        if self.message_active && self.message_count + 1 < self.message_width {
            self.ignore_comma = true;
        }
        self.wrapped.start_comma()
    }

    fn start_key(&mut self) -> Result<()> {
        if self.message_active && self.message_count + 1 < self.message_width {
            write!(
                self,
                "{}",
                " ".repeat(self.message_width - self.message_count)
            )?;
            self.message_active = false;
            self.message_count = 0;
            self.ignore_comma = false;
        }
        self.wrapped.start_key()
    }

    fn start_value(&mut self) -> Result<()> {
        self.wrapped.start_value()
    }

    fn start_separator(&mut self) -> Result<()> {
        self.wrapped.start_separator()
    }
}

/// Function to filter out ascii control codes.
///
/// This helps to keep log formatting consistent.
/// Whitespace and padding control codes are excluded.
fn is_ascii_control(character: &u8) -> bool {
    matches!(
        character,
        b'\x00'..=b'\x08' |
        b'\x0b'..=b'\x0c' |
        b'\x0e'..=b'\x1f' |
        b'\x7f' |
        b'\x81'..=b'\x9f'
    )
}

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
