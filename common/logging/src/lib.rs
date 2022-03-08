#[macro_use]
extern crate lazy_static;

use lighthouse_metrics::{
    inc_counter, try_create_int_counter, IntCounter, Result as MetricsResult,
};
use slog::Logger;
use slog_term::Decorator;
use std::io::{Result, Write};
use std::time::{Duration, Instant};

pub const MAX_MESSAGE_WIDTH: usize = 40;

/// The minimum interval between log messages indicating that a queue is full.
const LOG_DEBOUNCE_INTERVAL: Duration = Duration::from_secs(30);

lazy_static! {
    pub static ref INFOS_TOTAL: MetricsResult<IntCounter> =
        try_create_int_counter("info_total", "Count of infos logged");
    pub static ref WARNS_TOTAL: MetricsResult<IntCounter> =
        try_create_int_counter("warn_total", "Count of warns logged");
    pub static ref ERRORS_TOTAL: MetricsResult<IntCounter> =
        try_create_int_counter("error_total", "Count of errors logged");
    pub static ref CRITS_TOTAL: MetricsResult<IntCounter> =
        try_create_int_counter("crit_total", "Count of crits logged");
}

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
            self.wrapped.write(buf).map(|n| {
                self.message_count += n;
                n
            })
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

/// Return a logger suitable for test usage.
///
/// By default no logs will be printed, but they can be enabled via
/// the `test_logger` feature.  This feature can be enabled for any
/// dependent crate by passing `--features logging/test_logger`, e.g.
/// ```bash
/// cargo test -p beacon_chain --features logging/test_logger
/// ```
pub fn test_logger() -> Logger {
    use sloggers::Build;

    if cfg!(feature = "test_logger") {
        sloggers::terminal::TerminalLoggerBuilder::new()
            .level(sloggers::types::Severity::Debug)
            .build()
            .expect("Should build test_logger")
    } else {
        sloggers::null::NullLoggerBuilder
            .build()
            .expect("Should build null_logger")
    }
}
