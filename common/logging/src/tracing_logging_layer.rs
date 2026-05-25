use crate::utils::is_ascii_control;
use std::collections::HashSet;

use chrono::prelude::*;
use serde_json::{Map, Value};
use std::io::Write;
use tracing::Subscriber;
use tracing::field::Field;
use tracing::span::Id;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

const FIXED_MESSAGE_WIDTH: usize = 44;
const ALIGNED_LEVEL_WIDTH: usize = 5;

pub struct LoggingLayer {
    pub non_blocking_writer: NonBlocking,
    _guard: WorkerGuard,
    pub disable_log_timestamp: bool,
    pub log_color: bool,
    pub log_format: Option<String>,
    pub extra_info: bool,
}

impl LoggingLayer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        non_blocking_writer: NonBlocking,
        _guard: WorkerGuard,
        disable_log_timestamp: bool,
        log_color: bool,
        log_format: Option<String>,
        extra_info: bool,
    ) -> Self {
        Self {
            non_blocking_writer,
            _guard,
            disable_log_timestamp,
            log_color,
            log_format,
            extra_info,
        }
    }
}

impl<S> Layer<S> for LoggingLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &tracing::span::Attributes<'_>, id: &Id, ctx: Context<S>) {
        let mut visitor = FieldVisitor::new();
        attrs.record(&mut visitor);

        if let Some(span) = ctx.span(id) {
            let mut extensions = span.extensions_mut();

            let span_data = SpanData {
                name: attrs.metadata().name().to_string(),
                fields: visitor.fields,
            };

            extensions.replace(span_data);
        }
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

        let mut visitor = FieldVisitor::new();

        event.record(&mut visitor);

        let mut span_data = Vec::new();
        if let Some(mut scope) = ctx.event_scope(event)
            && let Some(span) = scope.next()
            && let Some(data) = span.extensions().get::<SpanData>()
        {
            span_data.extend(data.fields.clone());
        }

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

        let gray = "\x1b[90m";
        let reset = "\x1b[0m";
        let location = if self.extra_info {
            if self.log_color {
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

        if self.log_format.as_deref() == Some("JSON") {
            build_log_json(&visitor, plain_level_str, meta, &span_data, &mut writer);
        } else {
            build_log_text(
                &visitor,
                plain_level_str,
                &timestamp,
                &span_data,
                &location,
                color_level_str,
                self.log_color,
                &mut writer,
            );
        }
    }
}

#[derive(Clone, Debug)]
pub struct SpanData {
    pub name: String,
    pub fields: Vec<(String, String)>,
}

struct FieldVisitor {
    message: String,
    fields: Vec<(String, String)>,
    is_crit: bool,
}

impl FieldVisitor {
    fn new() -> Self {
        FieldVisitor {
            message: String::new(),
            fields: Vec::new(),
            is_crit: false,
        }
    }
}

impl tracing_core::field::Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "message" => {
                if self.message.is_empty() {
                    self.message = value.to_string();
                } else {
                    self.fields
                        .push(("msg_id".to_string(), format!("\"{}\"", value)));
                }
            }
            "error_type" if value == "crit" => {
                self.is_crit = true;
            }
            _ => {
                self.fields
                    .push((field.name().to_string(), format!("\"{}\"", value)));
            }
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let string_value = format!("{:?}", value);
        match field.name() {
            "message" => {
                if self.message.is_empty() {
                    self.message = string_value;
                } else {
                    self.fields.push(("msg_id".to_string(), string_value));
                }
            }
            "error_type" if string_value == "\"crit\"" => {
                self.is_crit = true;
            }
            _ => {
                self.fields.push((field.name().to_string(), string_value));
            }
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

fn build_log_json(
    visitor: &FieldVisitor,
    plain_level_str: &str,
    meta: &tracing::Metadata<'_>,
    span_fields: &[(String, String)],
    writer: &mut impl Write,
) {
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

    // Avoid adding duplicate fields; prefer event fields when duplicates exist.
    for (key, val) in span_fields {
        let parsed_span_val = parse_field(val);
        log_map.insert(key.clone(), parsed_span_val);
    }

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

    let json_obj = Value::Object(log_map);
    let output = format!("{}\n", json_obj);

    if let Err(e) = writer.write_all(output.as_bytes()) {
        eprintln!("Failed to write log: {}", e);
    }
}

#[allow(clippy::too_many_arguments)]
fn build_log_text(
    visitor: &FieldVisitor,
    plain_level_str: &str,
    timestamp: &str,
    span_fields: &[(String, String)],
    location: &str,
    color_level_str: &str,
    use_color: bool,
    writer: &mut impl Write,
) {
    let bold_start = "\x1b[1m";
    let bold_end = "\x1b[0m";

    let pad = if plain_level_str.len() < ALIGNED_LEVEL_WIDTH {
        " "
    } else {
        ""
    };

    let level_str = if use_color {
        format!("{}{}", color_level_str, pad)
    } else {
        format!("{}{}", plain_level_str, pad)
    };

    let message_len = visitor.message.len();

    let message_content = if use_color {
        format!("{}{}{}", bold_start, visitor.message, bold_end)
    } else {
        visitor.message.clone()
    };

    let padded_message = if message_len < FIXED_MESSAGE_WIDTH {
        let extra_color_len = if use_color {
            bold_start.len() + bold_end.len()
        } else {
            0
        };
        format!(
            "{:<width$}",
            message_content,
            width = FIXED_MESSAGE_WIDTH + extra_color_len
        )
    } else {
        message_content.clone()
    };

    // Avoid adding duplicate fields; prefer event fields when duplicates exist.
    let mut added_field_names = HashSet::new();
    let formatted_fields = visitor
        .fields
        .iter()
        .chain(span_fields.iter())
        .filter_map(|(field_name, field_value)| {
            if added_field_names.insert(field_name) {
                let formatted_field = if use_color {
                    format!("{}{}{}: {}", bold_start, field_name, bold_end, field_value)
                } else {
                    format!("{}: {}", field_name, field_value)
                };
                Some(formatted_field)
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join(", ");

    let full_message = if !formatted_fields.is_empty() {
        format!("{}  {}", padded_message, formatted_fields)
    } else {
        padded_message.to_string()
    };

    let message = if !location.is_empty() {
        format!(
            "{} {} {} {}\n",
            timestamp, level_str, location, full_message
        )
    } else {
        format!("{} {} {}\n", timestamp, level_str, full_message)
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

#[cfg(test)]
mod tests {
    use crate::tracing_logging_layer::{FieldVisitor, build_log_text};
    use std::io::Write;

    struct Buffer {
        data: Vec<u8>,
    }

    impl Buffer {
        fn new() -> Self {
            Buffer { data: Vec::new() }
        }

        fn into_string(self) -> String {
            String::from_utf8(self.data).unwrap()
        }
    }

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.data.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_build_log_text_single_log_field() {
        let log_fields = vec![("field_name".to_string(), "field_value".to_string())];
        let span_fields = vec![];
        let expected = "Jan 1 08:00:00.000 INFO  test message                                  field_name: field_value\n";
        test_build_log_text(log_fields, span_fields, expected);
    }

    #[test]
    fn test_build_log_text_multiple_log_fields() {
        let log_fields = vec![
            ("field_name1".to_string(), "field_value1".to_string()),
            ("field_name2".to_string(), "field_value2".to_string()),
        ];
        let span_fields = vec![];
        let expected = "Jan 1 08:00:00.000 INFO  test message                                  field_name1: field_value1, field_name2: field_value2\n";
        test_build_log_text(log_fields, span_fields, expected);
    }

    #[test]
    fn test_build_log_text_log_field_and_span() {
        let log_fields = vec![("field_name".to_string(), "field_value".to_string())];
        let span_fields = vec![(
            "span_field_name".to_string(),
            "span_field_value".to_string(),
        )];
        let expected = "Jan 1 08:00:00.000 INFO  test message                                  field_name: field_value, span_field_name: span_field_value\n";
        test_build_log_text(log_fields, span_fields, expected);
    }

    #[test]
    fn test_build_log_text_single_span() {
        let log_fields = vec![];
        let span_fields = vec![(
            "span_field_name".to_string(),
            "span_field_value".to_string(),
        )];
        let expected = "Jan 1 08:00:00.000 INFO  test message                                  span_field_name: span_field_value\n";
        test_build_log_text(log_fields, span_fields, expected);
    }

    #[test]
    fn test_build_log_text_multiple_spans() {
        let log_fields = vec![];
        let span_fields = vec![
            (
                "span_field_name1".to_string(),
                "span_field_value1".to_string(),
            ),
            (
                "span_field_name2".to_string(),
                "span_field_value2".to_string(),
            ),
        ];
        let expected = "Jan 1 08:00:00.000 INFO  test message                                  span_field_name1: span_field_value1, span_field_name2: span_field_value2\n";
        test_build_log_text(log_fields, span_fields, expected);
    }

    #[test]
    fn test_build_log_text_multiple_span_fields() {
        let log_fields = vec![];
        let span_fields = vec![
            (
                "span_field_name1-1".to_string(),
                "span_field_value1-1".to_string(),
            ),
            (
                "span_field_name1-2".to_string(),
                "span_field_value1-2".to_string(),
            ),
        ];
        let expected = "Jan 1 08:00:00.000 INFO  test message                                  span_field_name1-1: span_field_value1-1, span_field_name1-2: span_field_value1-2\n";
        test_build_log_text(log_fields, span_fields, expected);
    }

    #[test]
    fn test_build_log_text_no_duplicate_log_span_fields() {
        let log_fields = vec![
            ("field_name_1".to_string(), "field_value_1".to_string()),
            ("field_name_2".to_string(), "field_value_2".to_string()),
        ];
        let span_fields = vec![
            ("field_name_1".to_string(), "field_value_1".to_string()),
            ("field_name_3".to_string(), "field_value_3".to_string()),
        ];
        let expected = "Jan 1 08:00:00.000 INFO  test message                                  field_name_1: field_value_1, field_name_2: field_value_2, field_name_3: field_value_3\n";
        test_build_log_text(log_fields, span_fields, expected);
    }

    #[test]
    fn test_build_log_text_duplicate_fields_prefer_log_fields() {
        let log_fields = vec![
            ("field_name_1".to_string(), "field_value_1_log".to_string()),
            ("field_name_2".to_string(), "field_value_2".to_string()),
        ];
        let span_fields = vec![
            ("field_name_1".to_string(), "field_value_1_span".to_string()),
            ("field_name_3".to_string(), "field_value_3".to_string()),
        ];
        let expected = "Jan 1 08:00:00.000 INFO  test message                                  field_name_1: field_value_1_log, field_name_2: field_value_2, field_name_3: field_value_3\n";
        test_build_log_text(log_fields, span_fields, expected);
    }

    fn test_build_log_text(
        log_fields: Vec<(String, String)>,
        span_fields: Vec<(String, String)>,
        expected: &str,
    ) {
        let visitor = FieldVisitor {
            message: "test message".to_string(),
            fields: log_fields,
            is_crit: false,
        };
        let plain_level_str = "INFO";
        let timestamp = "Jan 1 08:00:00.000";
        let location = "";
        let color_level_str = "\x1b[32mINFO\x1b[0m";
        let use_color = false;
        let mut writer = Buffer::new();

        build_log_text(
            &visitor,
            plain_level_str,
            timestamp,
            &span_fields,
            location,
            color_level_str,
            use_color,
            &mut writer,
        );

        assert_eq!(expected, &writer.into_string());
    }
}
