use chrono::prelude::*;
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing::field::Field;
use tracing::span::Id;
use tracing::Subscriber;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

pub struct LoggingLayer {
    pub non_blocking_writer: NonBlocking,
    pub guard: WorkerGuard,
    pub disable_log_timestamp: bool,
    pub logfile_color: bool,
    span_fields: Arc<Mutex<HashMap<Id, SpanData>>>,
}

impl LoggingLayer {
    pub fn new(
        non_blocking_writer: NonBlocking,
        guard: WorkerGuard,
        disable_log_timestamp: bool,
        logfile_color: bool,
    ) -> Self {
        Self {
            non_blocking_writer,
            guard,
            disable_log_timestamp,
            logfile_color,
            span_fields: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<S> Layer<S> for LoggingLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &tracing::span::Attributes<'_>, id: &Id, _ctx: Context<S>) {
        let metadata = attrs.metadata();
        let span_name = metadata.name();

        let mut visitor = SpanFieldsExtractor::default();
        attrs.record(&mut visitor);

        let span_data = SpanData {
            name: span_name.to_string(),
            fields: visitor.fields,
        };

        let mut span_fields = match self.span_fields.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        span_fields.insert(id.clone(), span_data);
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<S>) {
        let meta = event.metadata();
        let log_level = meta.level();
        let timestamp = if !self.disable_log_timestamp {
            Local::now().format("%b %d %H:%M:%S%.3f").to_string()
        } else {
            String::new()
        };

        let mut writer = self.non_blocking_writer.clone();

        let mut visitor = LogMessageExtractor {
            message: String::new(),
            fields: Vec::new(),
            is_crit: false,
        };

        event.record(&mut visitor);

        let bold_start = "\x1b[1m";
        let bold_end = "\x1b[0m";

        let mut span_fields = Vec::new();
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope {
                let id = span.id();
                let span_fields_map = self.span_fields.lock().unwrap();
                if let Some(span_data) = span_fields_map.get(&id) {
                    span_fields.push((span_data.name.clone(), span_data.fields.clone()));
                }
            }
        }

        let mut formatted_spans = String::new();
        for (_, fields) in span_fields.iter().rev() {
            for (i, (field_name, field_value)) in fields.iter().enumerate() {
                if i > 0 {
                    formatted_spans.push(' ');
                }
                if self.logfile_color {
                    formatted_spans.push_str(&format!(
                        "{}{}{}={}",
                        bold_start, field_name, bold_end, field_value
                    ));
                } else {
                    formatted_spans.push_str(&format!("{}={}", field_name, field_value));
                }
            }
        }
        let level_str;

        if self.logfile_color {
            level_str = if visitor.is_crit {
                "\x1b[35mCRIT\x1b[0m"
            } else {
                match *log_level {
                    tracing::Level::ERROR => "\x1b[31mERROR\x1b[0m",
                    tracing::Level::WARN => "\x1b[33mWARN\x1b[0m",
                    tracing::Level::INFO => "\x1b[32mINFO\x1b[0m",
                    tracing::Level::DEBUG => "\x1b[34mDEBUG\x1b[0m",
                    tracing::Level::TRACE => "\x1b[35mTRACE\x1b[0m",
                }
            };
        } else {
            level_str = if visitor.is_crit {
                "CRIT"
            } else {
                match *log_level {
                    tracing::Level::ERROR => "ERROR",
                    tracing::Level::WARN => "WARN",
                    tracing::Level::INFO => "INFO",
                    tracing::Level::DEBUG => "DEBUG",
                    tracing::Level::TRACE => "TRACE",
                }
            };
        }

        let fixed_message_width = 44;

        let message_len = visitor.message.len();

        let message_content = if self.logfile_color {
            format!("{}{}{}", bold_start, visitor.message, bold_end)
        } else {
            visitor.message.clone()
        };

        let padded_message = if message_len < fixed_message_width {
            let extra_color_len = if self.logfile_color {
                bold_start.len() + bold_end.len()
            } else {
                0
            };

            format!(
                "{:<width$}",
                message_content,
                width = fixed_message_width + extra_color_len
            )
        } else {
            message_content.clone()
        };

        let mut formatted_fields = String::new();
        for (i, (field_name, field_value)) in visitor.fields.iter().enumerate() {
            if i > 0 {
                formatted_fields.push(' ');
            }

            if self.logfile_color {
                formatted_fields.push_str(&format!(
                    "{}{}{}={}",
                    bold_start, field_name, bold_end, field_value
                ));
            } else {
                formatted_fields.push_str(&format!("{}={}", field_name, field_value));
            }
        }

        let mut full_message = padded_message.clone();
        if !formatted_fields.is_empty() {
            full_message = format!("{}  {}", padded_message, formatted_fields);
        }

        let message = format!(
            "{} {} {}  {}\n",
            timestamp, level_str, full_message, formatted_spans
        );

        if let Err(e) = writer.write_all(message.as_bytes()) {
            eprintln!("Failed to write log: {}", e);
        }
    }
}

struct SpanData {
    name: String,
    fields: Vec<(String, String)>,
}

#[derive(Default)]
struct SpanFieldsExtractor {
    fields: Vec<(String, String)>,
}

impl tracing_core::field::Visit for SpanFieldsExtractor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields
            .push((field.name().to_string(), format!("\"{}\"", value)));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields
            .push((field.name().to_string(), format!("{:?}", value)));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }
}

struct LogMessageExtractor {
    message: String,
    fields: Vec<(String, String)>,
    is_crit: bool,
}

impl tracing_core::field::Visit for LogMessageExtractor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else if field.name() == "error_type" && value == "crit" {
            self.is_crit = true;
        } else {
            self.fields
                .push((field.name().to_string(), format!("\"{}\"", value)));
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        } else if field.name() == "error_type" && format!("{:?}", value) == "\"crit\"" {
            self.is_crit = true;
        } else {
            self.fields
                .push((field.name().to_string(), format!("{:?}", value)));
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }
}
