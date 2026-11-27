use crate::{Config, EVENT_NAMES, Health, Record};
use opentelemetry_proto::tonic::{
    collector::logs::v1::{ExportLogsServiceRequest, logs_service_client::LogsServiceClient},
    common::v1::{AnyValue, ArrayValue, InstrumentationScope, KeyValue, KeyValueList, any_value},
    logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
    resource::v1::Resource,
};
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{Notify, mpsc};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

pub(crate) fn client(config: &Config) -> Result<LogsServiceClient<Channel>, String> {
    let mut endpoint = Endpoint::from_shared(config.endpoint.clone())
        .map_err(|e| format!("invalid PQ OTLP endpoint: {e}"))?
        .connect_timeout(config.export_timeout)
        .timeout(config.export_timeout);
    if crate::validate_endpoint(&config.endpoint)?.scheme() == "https" {
        endpoint = endpoint
            .tls_config(ClientTlsConfig::new().with_native_roots())
            .map_err(|e| format!("PQ OTLP TLS configuration: {e}"))?;
    }
    Ok(LogsServiceClient::new(endpoint.connect_lazy()))
}

fn value(value: &Value) -> AnyValue {
    let inner = match value {
        Value::String(s) => any_value::Value::StringValue(s.clone()),
        Value::Bool(v) => any_value::Value::BoolValue(*v),
        Value::Number(n) => any_value::Value::IntValue(n.as_i64().unwrap_or_default()),
        Value::Array(values) => any_value::Value::ArrayValue(ArrayValue {
            values: values.iter().map(self::value).collect(),
        }),
        Value::Object(values) => any_value::Value::KvlistValue(KeyValueList {
            values: values
                .iter()
                .map(|(k, v)| KeyValue {
                    key: k.clone(),
                    value: Some(self::value(v)),
                })
                .collect(),
        }),
        // Null is rejected by the bounded admission check.
        Value::Null => return AnyValue { value: None },
    };
    AnyValue { value: Some(inner) }
}

fn string_attribute(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.into())),
        }),
    }
}

pub(crate) fn request(records: &[&Record]) -> ExportLogsServiceRequest {
    let Some(first) = records.first() else {
        return ExportLogsServiceRequest::default();
    };
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![
                    string_attribute("pq.node_id", &first.node_id),
                    string_attribute("pq.process_id", &first.process_id),
                ],
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                scope: Some(InstrumentationScope {
                    name: "lighthouse.pq_measurement".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    ..Default::default()
                }),
                log_records: records
                    .iter()
                    .map(|r| LogRecord {
                        time_unix_nano: r.timestamp_unix_ns.parse().unwrap_or_default(),
                        event_name: r.event_name.clone(),
                        attributes: vec![
                            string_attribute("pq.event_name", &r.event_name),
                            string_attribute("pq.schema_version", &r.schema_version),
                            KeyValue {
                                key: "pq.event_seq".into(),
                                value: Some(AnyValue {
                                    value: Some(any_value::Value::IntValue(
                                        i64::try_from(r.event_seq).unwrap_or(i64::MAX),
                                    )),
                                }),
                            },
                            string_attribute("pq.context_id", &r.context_id),
                            string_attribute("pq.mode", r.mode.as_str()),
                        ],
                        body: Some(value(&r.data)),
                        // ObservedTimestamp belongs to the collector, not to export serialization.
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

async fn export(
    client: &mut LogsServiceClient<Channel>,
    config: &Config,
    records: &[&Record],
) -> Result<u64, ()> {
    let response = tokio::time::timeout(config.export_timeout, client.export(request(records)))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    let rejected = response
        .into_inner()
        .partial_success
        .map(|p| p.rejected_log_records)
        .unwrap_or_default();
    // A collector cannot reject more records than submitted, or a negative number.
    let rejected = u64::try_from(rejected).map_err(|_| ())?;
    if rejected > records.len() as u64 {
        return Err(());
    }
    Ok(rejected)
}

async fn flush(
    client: &mut LogsServiceClient<Channel>,
    config: &Config,
    context: &Record,
    batch: &mut Vec<Record>,
    health: &Health,
) -> bool {
    // A tiny, immutable context is replayed with the same identity before every batch. This
    // makes downstream references recoverable after collector reconnects without a context ACK
    // protocol. It is generated once; retries do not increment logical generated counters.
    let context_ready = matches!(export(client, config, &[context]).await, Ok(0));
    if !context_ready {
        health.export_error();
    }
    let mut groups: [Vec<Record>; 10] = std::array::from_fn(|_| Vec::new());
    for record in batch.drain(..) {
        if let Some(index) = EVENT_NAMES
            .iter()
            .position(|name| *name == record.event_name)
            && let Some(group) = groups.get_mut(index)
        {
            group.push(record);
        }
    }
    let mut available = context_ready;
    for (index, group) in groups
        .iter()
        .enumerate()
        .filter(|(_, group)| !group.is_empty())
    {
        if !available {
            health.dropped(index, group.len() as u64);
            continue;
        }
        // Homogeneous requests let OTLP's partial rejection count map to an exact event family.
        // Partial successes are not retried: OTLP does not identify rejected record identities.
        let refs: Vec<_> = group.iter().collect();
        match export(client, config, &refs).await {
            Ok(rejected) => {
                if rejected > 0 {
                    health.export_error();
                    health.dropped(index, rejected);
                }
            }
            Err(()) => {
                health.export_error();
                health.dropped(index, group.len() as u64);
                available = false;
            }
        }
    }
    context_ready
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run(
    mut client: LogsServiceClient<Channel>,
    config: Config,
    mut receiver: mpsc::Receiver<Record>,
    context: Record,
    health: Arc<Health>,
    stop: Arc<Notify>,
    finished: Arc<Notify>,
    done: Arc<AtomicBool>,
) {
    let mut batch = Vec::with_capacity(config.batch_size);
    let mut context_delivered = false;
    let mut interval = tokio::time::interval(config.flush_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = stop.notified() => { receiver.close(); break; }
            record = receiver.recv() => match record {
                Some(record) => {
                    batch.push(record);
                    if batch.len() >= config.batch_size { context_delivered |= flush(&mut client, &config, &context, &mut batch, &health).await; }
                }
                None => break,
            },
            _ = interval.tick() => { context_delivered |= flush(&mut client, &config, &context, &mut batch, &health).await; }
        }
    }
    while let Some(record) = receiver.recv().await {
        batch.push(record);
        if batch.len() >= config.batch_size {
            context_delivered |= flush(&mut client, &config, &context, &mut batch, &health).await;
        }
    }
    if !batch.is_empty() {
        context_delivered |= flush(&mut client, &config, &context, &mut batch, &health).await;
    }
    if !context_delivered {
        health.dropped(0, 1);
    }
    done.store(true, Ordering::Release);
    finished.notify_waiters();
}
