use logging::test_logger;
use slog::{o, Drain, Key, Level, Logger, OwnedKVList, Record, Serializer, KV};
use std::fmt::Arguments;

pub struct LogInterceptor {
    /// Unique identifier for this logger (e.g. the node name).
    id: String,
    /// Logging configuration.
    conf: LogConfig,
    /// Underlying logger to output logs to.
    underlying: Logger,
}

pub struct LogConfig {
    /// Log level at which to panic.
    pub panic_threshold: Option<Level>,
    /// Maximum re-org distance allowed (values greater will cause panics).
    pub max_reorg_length: Option<usize>,
    /// Forward logs to the underlying logger.
    pub forward_logs: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            panic_threshold: Some(Level::Error),
            max_reorg_length: Some(1),
            forward_logs: false,
        }
    }
}

impl LogInterceptor {
    pub fn new(id: String, conf: LogConfig) -> Self {
        Self {
            id,
            conf,
            underlying: test_logger(),
        }
    }

    pub fn into_logger(self) -> Logger {
        Logger::root(self.ignore_res(), o!())
    }
}

impl Drain for LogInterceptor {
    type Ok = ();
    type Err = ();

    fn log(&self, record: &Record, _: &OwnedKVList) -> Result<(), ()> {
        if self.conf.forward_logs {
            self.underlying.log(record);
        }

        // Check for messages above the threshold.
        if let Some(panic_threshold) = self.conf.panic_threshold {
            if record.level().is_at_least(panic_threshold) {
                panic!(
                    "{} logged a message above the panic threshold: {} {}, from {}:{}",
                    self.id,
                    record.level().as_short_str(),
                    record.msg(),
                    record.file(),
                    record.line(),
                );
            }
        }

        // Check for re-orgs longer than the re-org limit.
        if let (Some(reorg_limit), Level::Warning) = (self.conf.max_reorg_length, record.level()) {
            let message = format!("{}", record.msg());
            if message == "Beacon chain re-org" {
                let mut snooper = ReorgSnooper::default();
                record.kv().serialize(record, &mut snooper).unwrap();

                let (prev_head, new_head, distance) = snooper.unwrap();

                if distance > reorg_limit {
                    panic!(
                        "{} experienced a re-org of length {} (> {}) from {} to {}",
                        self.id, distance, reorg_limit, prev_head, new_head
                    );
                }
            }
        }

        Ok(())
    }
}

/// Serializer to snoop on a logged usize value.
#[derive(Default)]
pub struct ReorgSnooper {
    previous_head: Option<String>,
    new_head: Option<String>,
    reorg_distance: Option<usize>,
}

impl ReorgSnooper {
    fn unwrap(self) -> (String, String, usize) {
        (
            self.previous_head.unwrap(),
            self.new_head.unwrap(),
            self.reorg_distance.unwrap(),
        )
    }
}

impl Serializer for ReorgSnooper {
    fn emit_arguments(&mut self, key: Key, args: &Arguments) -> slog::Result {
        if key == "previous_head" {
            self.previous_head = Some(args.to_string());
        } else if key == "new_head" {
            self.new_head = Some(args.to_string());
        }
        Ok(())
    }

    fn emit_usize(&mut self, key: Key, value: usize) -> slog::Result {
        if key == "reorg_distance" {
            self.reorg_distance = Some(value);
        }
        Ok(())
    }
}
