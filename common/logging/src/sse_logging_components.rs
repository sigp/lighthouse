//! This module provides an implementation of `slog::Drain` that optionally writes to a channel if
//! there are subscribers to a HTTP SSE stream.

use crate::async_record::AsyncRecord;
use once_cell::sync::Lazy;
use serde_json;
use serde_json::json;
use serde_json::Value;
use slog::{Drain, OwnedKVList, Record};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::broadcast::Sender;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Default log level for SSE Events.
// NOTE: Made this a constant. Debug level seems to be pretty intense. Can make this
// configurable later if needed.
const LOG_LEVEL: tracing::Level = tracing::Level::INFO;
pub static SSE_LOGGING_COMPONENTS: Lazy<Mutex<Option<SSELoggingComponents>>> =
    Lazy::new(|| Mutex::new(None));
/// The components required in the HTTP API task to receive logged events.
#[derive(Clone)]
pub struct SSELoggingComponents {
    /// The channel to receive events from.
    pub sender: Arc<Sender<Arc<Value>>>,
}

impl SSELoggingComponents {
    /// Create a new SSE drain.
    pub fn new(channel_size: usize) -> Self {
        let (sender, _receiver) = tokio::sync::broadcast::channel(channel_size);

        SSELoggingComponents {
            sender: Arc::new(sender),
        }
    }
}

impl<S: Subscriber> Layer<S> for SSELoggingComponents {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if *event.metadata().level() > LOG_LEVEL {
            return;
        }

        let mut visitor = TracingEventVisitor::new();
        event.record(&mut visitor);
        let log_entry = visitor.finish(event.metadata());

        let _ = self.sender.send(Arc::new(log_entry));
    }
}
struct TracingEventVisitor {
    fields: serde_json::Map<String, Value>,
}

impl TracingEventVisitor {
    fn new() -> Self {
        TracingEventVisitor {
            fields: serde_json::Map::new(),
        }
    }

    fn finish(self, metadata: &tracing::Metadata<'_>) -> Value {
        let mut log_entry = serde_json::Map::new();
        log_entry.insert("time".to_string(), json!(chrono::Local::now().to_rfc3339()));
        log_entry.insert("level".to_string(), json!(metadata.level().to_string()));
        log_entry.insert("target".to_string(), json!(metadata.target()));
        log_entry.insert("fields".to_string(), Value::Object(self.fields));
        Value::Object(log_entry)
    }
}

impl Visit for TracingEventVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields
            .insert(field.name().to_string(), json!(format!("{:?}", value)));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields.insert(field.name().to_string(), json!(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields.insert(field.name().to_string(), json!(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields.insert(field.name().to_string(), json!(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields.insert(field.name().to_string(), json!(value));
    }
}
