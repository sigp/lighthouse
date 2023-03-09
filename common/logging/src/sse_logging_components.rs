//! This module provides an implementation of `slog::Drain` that optionally writes to a channel if
//! there are subscribers to a HTTP SSE stream.

use crate::async_record::AsyncRecord;
use slog::{Drain, Level, OwnedKVList, Record, KV};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use tokio::sync::broadcast::{error::SendError, Receiver, Sender};

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
        // There are subscribers, attempt to send the logs
        match self.sender.send(AsyncRecord::from(record, logger_values)) {
            Ok(_num_sent) => {} // Everything got sent
            Err(_err) => {}     // There are no subscribers, do nothing
        }
        Ok(())
    }
}
