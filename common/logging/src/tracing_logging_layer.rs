use chrono::prelude::*;
use std::io::Write;
use tracing::Subscriber;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

pub struct LoggingLayer {
    pub libp2p_non_blocking_writer: NonBlocking,
    pub _libp2p_guard: WorkerGuard,
    pub discv5_non_blocking_writer: NonBlocking,
    pub _discv5_guard: WorkerGuard,
}

impl<S> Layer<S> for LoggingLayer
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
