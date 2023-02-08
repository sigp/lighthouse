//! This module provides an implementation of `slog::Drain` that optionally writes to a channel if
//! there are subscribers to a HTTP SSE stream.

use crossbeam_channel::mpsc::{Sender, Receiver};
use slog_async::AsyncRecord;

/// The components required in the HTTP API task to receive logged events.
pub struct SSELoggingComponents {
    /// The channel to receive events from.
    pub receiver: Receiver<AsyncRecord>,
    /// Indicates if there are currently subscribers to the http API.
    pub subscribers: Arc<AtomicBool>,
}


/// An slog drain used to pass logs to the SSE event stream in the HTTP API.
pub struct SSEDrain {
    /// The channel to send events to.
    sender: mpsc::Sender<AsyncRecord>,
    /// Indicates if there are currently subscribers to the http API.
    pub subscribers: Arc<AtomicBool>,
}

impl SSEDrain {
    /// Create a new SSE drain.
    pub fn new(channel_size: usize) -> (Self, SSELoggingComponents)) {

        let (sender, receiver) = crossbeam_channel::bounded(channel_size);
        let subscribers = Arc::new(AtomicBool::new(false));

        let drain = SSEDrain {
            sender,
            subscribers,
        }
        (drain, SSELoggingComponents { receiver, subscribers })
    }
}

impl Drain for SSEDrain {
    type Ok = ();
    type Err = &'static str;

    fn log(&self, record: &Record, logger_values: &OwnedKVList) -> Result<Self::Ok, Self::Err> {
        if !subscribers.load(Ordering::Relaxed) {
            return Ok(()); // Drop the logs, there are no subscribers
        }

        // There are subscribers, attempt to send the logs
        match self
            .sender
            .try_send(AsyncRecord::from(record, logger_values))
        {
            Ok(()) => {}                               // Everything got sent
            Err(TrySendError::Full(_failed_log)) => {} // Ignore dropped logs

            Err(TrySendError::Disconnected(_failed_log)) => {
                return Err("Channel Disconnected");
            }
        }
        Ok(())
    }
}
