use chrono::prelude::*;
use serde_json::{Map, Value};
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
    pub log_color: bool,
    pub logfile_color: bool,
    pub log_format: Option<String>,
    pub logfile_format: Option<String>,
    pub extra_info: bool,
    pub dep_logs: bool,
    span_fields: Arc<Mutex<HashMap<Id, SpanData>>>,
}

impl LoggingLayer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        non_blocking_writer: NonBlocking,
        guard: WorkerGuard,
        disable_log_timestamp: bool,
        log_color: bool,
        logfile_color: bool,
        log_format: Option<String>,
        logfile_format: Option<String>,
        extra_info: bool,
        dep_logs: bool,
    ) -> Self {
        Self {
            non_blocking_writer,
            guard,
            disable_log_timestamp,
            log_color,
            logfile_color,
            log_format,
            logfile_format,
            extra_info,
            dep_logs,
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

        if !self.dep_logs {
            if let Some(file) = meta.file() {
                if file.contains("/.cargo/") {
                    return;
                }
            } else {
                return;
            }
        }

        let mut writer = self.non_blocking_writer.clone();

        let mut visitor = LogMessageExtractor {
            message: String::new(),
            fields: Vec::new(),
            is_crit: false,
        };
        event.record(&mut visitor);

        // Remove ascii control codes from message.
        // All following formatting and logs components are predetermined or known.
        if visitor.message.as_bytes().iter().any(u8::is_ascii_control) {
            let filtered = visitor
                .message
                .as_bytes()
                .iter()
                .map(|c| if is_ascii_control(c) { b'_' } else { *c })
                .collect::<Vec<u8>>();
            visitor.message = String::from_utf8(filtered).unwrap_or_default();
        };

        let module = meta.module_path().unwrap_or("<unknown_module>");
        let file = meta.file().unwrap_or("<unknown_file>");
        let line = match meta.line() {
            Some(line) => line.to_string(),
            None => "<unknown_line>".to_string(),
        };

        if module.contains("discv5") {
            visitor
                .fields
                .push(("service".to_string(), "\"discv5\"".to_string()));
        }

        let gray = "\x1b[90m";
        let reset = "\x1b[0m";
        let location = if self.extra_info {
            if self.logfile_color {
                format!("{}{}::{}:{}{}", gray, module, file, line, reset)
            } else {
                format!("{}::{}:{}", module, file, line)
            }
        } else {
            String::new()
        };

        let plain_level_str = if visitor.is_crit {
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

        let color_level_str = if visitor.is_crit {
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

        if self.dep_logs {
            if self.logfile_format.as_deref() == Some("JSON") {
                build_json_log_file(
                    &visitor,
                    plain_level_str,
                    meta,
                    &ctx,
                    &self.span_fields,
                    event,
                    &mut writer,
                );
            } else {
                build_log_text(
                    &visitor,
                    plain_level_str,
                    &timestamp,
                    &ctx,
                    &self.span_fields,
                    event,
                    &location,
                    color_level_str,
                    self.logfile_color,
                    &mut writer,
                );
            }
        } else if self.log_format.as_deref() == Some("JSON") {
            build_json_log_stdout(&visitor, plain_level_str, &timestamp, &mut writer);
        } else {
            build_log_text(
                &visitor,
                plain_level_str,
                &timestamp,
                &ctx,
                &self.span_fields,
                event,
                &location,
                color_level_str,
                self.log_color,
                &mut writer,
            );
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
            if self.message.is_empty() {
                self.message = value.to_string();
            } else {
                self.fields
                    .push(("msg_id".to_string(), format!("\"{}\"", value)));
            }
        } else if field.name() == "error_type" && value == "crit" {
            self.is_crit = true;
        } else {
            self.fields
                .push((field.name().to_string(), format!("\"{}\"", value)));
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            if self.message.is_empty() {
                self.message = format!("{:?}", value);
            } else {
                self.fields
                    .push(("msg_id".to_string(), format!("{:?}", value)));
            }
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

fn build_json_log_stdout(
    visitor: &LogMessageExtractor,
    plain_level_str: &str,
    timestamp: &str,
    writer: &mut impl Write,
) {
    let mut log_map = Map::new();
    log_map.insert("msg".to_string(), Value::String(visitor.message.clone()));
    log_map.insert(
        "level".to_string(),
        Value::String(plain_level_str.to_string()),
    );
    log_map.insert("ts".to_string(), Value::String(timestamp.to_string()));

    for (key, val) in visitor.fields.clone().into_iter() {
        let parsed_val = parse_field(&val);
        log_map.insert(key, parsed_val);
    }

    let json_obj = Value::Object(log_map);
    let output = format!("{}\n", json_obj);

    if let Err(e) = writer.write_all(output.as_bytes()) {
        eprintln!("Failed to write log: {}", e);
    }
}

fn build_json_log_file<'a, S>(
    visitor: &LogMessageExtractor,
    plain_level_str: &str,
    meta: &tracing::Metadata<'_>,
    ctx: &Context<'_, S>,
    span_fields: &Arc<Mutex<HashMap<Id, SpanData>>>,
    event: &tracing::Event<'_>,
    writer: &mut impl Write,
) where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    let utc_timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let mut log_map = Map::new();

    log_map.insert("msg".to_string(), Value::String(visitor.message.clone()));
    log_map.insert(
        "level".to_string(),
        Value::String(plain_level_str.to_string()),
    );
    log_map.insert("ts".to_string(), Value::String(utc_timestamp));

    let module_path = meta.module_path().unwrap_or("<unknown_module>");
    let line_number = meta
        .line()
        .map_or("<unknown_line>".to_string(), |l| l.to_string());
    let module_field = format!("{}:{}", module_path, line_number);
    log_map.insert("module".to_string(), Value::String(module_field));

    for (key, val) in visitor.fields.clone().into_iter() {
        let cleaned_value = if val.starts_with('\"') && val.ends_with('\"') && val.len() >= 2 {
            &val[1..val.len() - 1]
        } else {
            &val
        };
        let parsed_val =
            serde_json::from_str(cleaned_value).unwrap_or(Value::String(cleaned_value.to_string()));
        log_map.insert(key, parsed_val);
    }

    if let Some(scope) = ctx.event_scope(event) {
        let guard = span_fields.lock().ok();
        if let Some(span_map) = guard {
            for span in scope {
                let id = span.id();
                if let Some(span_data) = span_map.get(&id) {
                    for (key, val) in &span_data.fields {
                        let parsed_span_val = parse_field(val);
                        log_map.insert(key.clone(), parsed_span_val);
                    }
                }
            }
        }
    }

    let json_obj = Value::Object(log_map);
    let output = format!("{}\n", json_obj);

    if let Err(e) = writer.write_all(output.as_bytes()) {
        eprintln!("Failed to write log: {}", e);
    }
}

#[allow(clippy::too_many_arguments)]
fn build_log_text<'a, S>(
    visitor: &LogMessageExtractor,
    plain_level_str: &str,
    timestamp: &str,
    ctx: &Context<'_, S>,
    span_fields: &Arc<Mutex<HashMap<Id, SpanData>>>,
    event: &tracing::Event<'_>,
    location: &str,
    color_level_str: &str,
    use_color: bool,
    writer: &mut impl Write,
) where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    let bold_start = "\x1b[1m";
    let bold_end = "\x1b[0m";
    let mut collected_span_fields = Vec::new();

    if let Some(scope) = ctx.event_scope(event) {
        for span in scope {
            let id = span.id();
            let span_fields_map = span_fields.lock().unwrap();
            if let Some(span_data) = span_fields_map.get(&id) {
                collected_span_fields.push((span_data.name.clone(), span_data.fields.clone()));
            }
        }
    }

    let mut formatted_spans = String::new();
    for (_, fields) in collected_span_fields.iter().rev() {
        for (i, (field_name, field_value)) in fields.iter().enumerate() {
            if i > 0 && !visitor.fields.is_empty() {
                formatted_spans.push_str(", ");
            }
            if use_color {
                formatted_spans.push_str(&format!(
                    "{}{}{}: {}",
                    bold_start, field_name, bold_end, field_value
                ));
            } else {
                formatted_spans.push_str(&format!("{}: {}", field_name, field_value));
            }
        }
    }

    let level_str = if use_color {
        color_level_str
    } else {
        plain_level_str
    };

    let fixed_message_width = 44;
    let message_len = visitor.message.len();

    let message_content = if use_color {
        format!("{}{}{}", bold_start, visitor.message, bold_end)
    } else {
        visitor.message.clone()
    };

    let padded_message = if message_len < fixed_message_width {
        let extra_color_len = if use_color {
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
            formatted_fields.push_str(", ");
        }
        if use_color {
            formatted_fields.push_str(&format!(
                "{}{}{}: {}",
                bold_start, field_name, bold_end, field_value
            ));
        } else {
            formatted_fields.push_str(&format!("{}: {}", field_name, field_value));
        }
        if i == visitor.fields.len() - 1 && !collected_span_fields.is_empty() {
            formatted_fields.push(',');
        }
    }

    let full_message = if !formatted_fields.is_empty() {
        format!("{}  {}", padded_message, formatted_fields)
    } else {
        padded_message.to_string()
    };

    let message = if !location.is_empty() {
        format!(
            "{} {} {} {} {}\n",
            timestamp, level_str, location, full_message, formatted_spans
        )
    } else {
        format!(
            "{} {} {} {}\n",
            timestamp, level_str, full_message, formatted_spans
        )
    };

    if let Err(e) = writer.write_all(message.as_bytes()) {
        eprintln!("Failed to write log: {}", e);
    }
}

fn parse_field(val: &str) -> Value {
    let cleaned = if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
        &val[1..val.len() - 1]
    } else {
        val
    };
    serde_json::from_str(cleaned).unwrap_or(Value::String(cleaned.to_string()))
}
