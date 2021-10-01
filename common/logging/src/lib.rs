#[macro_use]
extern crate lazy_static;

use lighthouse_metrics::{
    inc_counter, try_create_int_counter, IntCounter, Result as MetricsResult,
};
use slog::Logger;
use slog_term::Decorator;
use std::io::{Result, Write};

pub const MAX_MESSAGE_WIDTH: usize = 40;

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
}

impl<'a> Write for AlignedRecordDecorator<'a> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
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

/// Return a logger suitable for test usage.
///
/// By default no logs will be printed, but they can be enabled via the `test_logger` feature.
/// For example in <rr>/beacon_node/beacon_chain/src/validator_pubkey_cache.rs the
/// `fn get_store()` returns a `BeaconStore<T>` and it requires a Logger:
/// ```ignore
/// mod test {
///     use super::*;
///     use crate::test_utils::{BeaconChainHarness, EphemeralHarnessType};
///     use logging::test_logger;
///
///     <snip>
///
///     fn get_store() -> BeaconStore<T> {
///         Arc::new(
///             HotColdDB::open_ephemeral(<_>::default(), E::default_spec(), test_logger()).unwrap(),
///         )
///     }
///
///     <snip>
/// }
/// ```
/// By importing `use logging::test_logger;` and then using it to create the logger
/// the developer can pass `--features 'logging/test_logger'` when testing the tests
/// and the logs are visible:
/// ```bash
/// wink@3900x:~/prgs/ethereum/myrepos/lighthouse (Add-test_logger-as-feature-to-logging)
/// $ cargo test -p beacon_chain validator_pubkey_cache::test::basic_operation --features 'logging/test_logger'
///     Finished test [unoptimized + debuginfo] target(s) in 0.19s
///      Running unittests (target/debug/deps/beacon_chain-975363824f1143bc)
///
/// running 1 test
/// Sep 19 18:39:15.637 INFO Beacon chain initialized, head_slot: 0, head_block: 0x2353…dcf4, head_state: 0xef4b…4615, module: beacon_chain::builder:649
/// Sep 19 18:39:15.638 INFO Saved beacon chain to disk, module: beacon_chain::beacon_chain:3608
/// Sep 19 18:39:17.277 INFO Beacon chain initialized, head_slot: 0, head_block: 0x2353…dcf4, head_state: 0xef4b…4615, module: beacon_chain::builder:649
/// Sep 19 18:39:17.277 INFO Saved beacon chain to disk, module: beacon_chain::beacon_chain:3608
/// Sep 19 18:39:18.884 INFO Beacon chain initialized, head_slot: 0, head_block: 0xdcdd…501f, head_state: 0x3055…032c, module: beacon_chain::builder:649
/// Sep 19 18:39:18.885 INFO Saved beacon chain to disk, module: beacon_chain::beacon_chain:3608
/// Sep 19 18:39:20.537 INFO Beacon chain initialized, head_slot: 0, head_block: 0xa739…1b22, head_state: 0xac1c…eab6, module: beacon_chain::builder:649
/// Sep 19 18:39:20.538 INFO Saved beacon chain to disk, module: beacon_chain::beacon_chain:3608
/// test validator_pubkey_cache::test::basic_operation ... ok
/// ```
/// If the `logging/test_logger` feature is not passed `test_logger()` will return a NullLogger
/// and no log information will be displayed:
/// ```bash
/// $ cargo test -p beacon_chain validator_pubkey_cache::test::basic_operation
///     Finished test [unoptimized + debuginfo] target(s) in 11.17s
///      Running unittests (target/debug/deps/beacon_chain-972b3a065a98b4a6)
///
/// running 1 test
/// test validator_pubkey_cache::test::basic_operation ... ok
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
