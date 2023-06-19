//! This module provides an implementation of `slog::Drain` that optionally writes to a channel if
//! there are subscribers to a HTTP SSE stream.

use crate::async_record::AsyncRecord;
use slog::{Drain, OwnedKVList, Record};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use tokio::sync::broadcast::Sender;

/// Default log level for SSE Events.
// NOTE: Made this a constant. Debug level seems to be pretty intense. Can make this
// configurable later if needed.
const LOG_LEVEL: slog::Level = slog::Level::Info;

/// The components required in the HTTP API task to receive logged events.
#[derive(Clone)]
pub struct SSELoggingComponents {
    /// The channel to receive events from.
    pub sender: Arc<AssertUnwindSafe<Sender<AsyncRecord>>>,
}

impl SSELoggingComponents {
    /// Create a new SSE drain.
    pub fn new(channel_size: usize) -> Self {
        let (sender, _receiver) = tokio::sync::broadcast::channel(channel_size);

        let sender = Arc::new(AssertUnwindSafe(sender));
        SSELoggingComponents { sender }
    }
}

impl Drain for SSELoggingComponents {
    type Ok = ();
    type Err = &'static str;

    fn log(&self, record: &Record, logger_values: &OwnedKVList) -> Result<Self::Ok, Self::Err> {
        if record.level().is_at_least(LOG_LEVEL) {
            // Attempt to send the logs
            match self.sender.send(AsyncRecord::from(record, logger_values)) {
                Ok(_num_sent) => {} // Everything got sent
                Err(_err) => {}     // There are no subscribers, do nothing
            }
        }
        Ok(())
    }
}
