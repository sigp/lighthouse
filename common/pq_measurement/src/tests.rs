use super::*;
use opentelemetry_proto::tonic::{
    collector::logs::v1::{
        ExportLogsPartialSuccess, ExportLogsServiceRequest, ExportLogsServiceResponse,
        logs_service_server::{LogsService, LogsServiceServer},
    },
    common::v1::{AnyValue, KeyValue, any_value},
};
use serde_json::json;
use std::sync::Mutex;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

fn examples() -> Vec<Record> {
    serde_json::from_str(include_str!("../tests/fixtures/examples.json")).unwrap()
}
fn config(endpoint: &str) -> Config {
    let mut c = Config::new(
        endpoint,
        "test-node",
        "test-context",
        examples()[0].data.clone(),
    )
    .unwrap();
    c.export_timeout = Duration::from_millis(100);
    c.flush_interval = Duration::from_millis(20);
    c
}
fn family(r: &Recorder, name: &str) -> FamilyCounters {
    r.snapshot()
        .families
        .into_iter()
        .find(|(n, _)| *n == name)
        .unwrap()
        .1
}

fn json_value(value: &AnyValue) -> Value {
    match value.value.as_ref().unwrap() {
        any_value::Value::StringValue(s) => json!(s),
        any_value::Value::BoolValue(b) => json!(b),
        any_value::Value::IntValue(n) => json!(n),
        any_value::Value::DoubleValue(n) => json!(n),
        any_value::Value::ArrayValue(a) => Value::Array(a.values.iter().map(json_value).collect()),
        any_value::Value::KvlistValue(k) => Value::Object(
            k.values
                .iter()
                .map(|p| (p.key.clone(), json_value(p.value.as_ref().unwrap())))
                .collect(),
        ),
        any_value::Value::BytesValue(_) => panic!("no bytes in canonical measurement JSON"),
    }
}
fn attribute(attrs: &[KeyValue], name: &str) -> Value {
    json_value(
        attrs
            .iter()
            .find(|a| a.key == name)
            .unwrap()
            .value
            .as_ref()
            .unwrap(),
    )
}
fn reconstruct(request: &ExportLogsServiceRequest) -> Vec<Value> {
    request.resource_logs.iter().flat_map(|resource| {
        let attrs = &resource.resource.as_ref().unwrap().attributes;
        resource.scope_logs.iter().flat_map(move |scope| scope.log_records.iter().map(move |record| {
            assert!(record.trace_id.is_empty());
            assert!(record.span_id.is_empty());
            assert_eq!(attribute(&record.attributes, "pq.event_name"), json!(record.event_name));
            json!({"schema_version":attribute(&record.attributes,"pq.schema_version"),
                "event_name":record.event_name,"node_id":attribute(attrs,"pq.node_id"),"process_id":attribute(attrs,"pq.process_id"),
                "event_seq":attribute(&record.attributes,"pq.event_seq"),"context_id":attribute(&record.attributes,"pq.context_id"),
                "mode":attribute(&record.attributes,"pq.mode"),"timestamp_unix_ns":record.time_unix_nano.to_string(),
                "data":json_value(record.body.as_ref().unwrap())})
        }))
    }).collect()
}

#[test]
fn canonical_examples_round_trip_exactly() {
    for record in examples() {
        assert!(valid_body(&record.data, 65536));
        assert_eq!(
            reconstruct(&transport::request(&[&record])),
            vec![serde_json::to_value(&record).unwrap()]
        );
    }
}

#[test]
fn endpoint_configuration_is_explicit() {
    for good in [
        "http://localhost:4317",
        "https://collector.example:443/",
        "http://[::1]:4317",
        "http://localhost:80",
    ] {
        assert!(validate_endpoint(good).is_ok(), "{good}");
    }
    for bad in [
        "",
        "localhost:4317",
        "http://localhost",
        "ftp://localhost:4317",
        "https://u:p@localhost:4317",
        "http://localhost:4317/logs",
        "http://localhost:4317?x=y",
        "http://localhost:4317#fragment",
        "http://localhost:0",
        " http://localhost:4317",
        "http://:4317",
    ] {
        assert!(validate_endpoint(bad).is_err(), "{bad}");
    }
}

#[test]
fn explicit_node_identity_validation() {
    assert_eq!(client::node_id(Some("bn-vc-1")).unwrap(), "bn-vc-1");
    assert!(client::node_id(Some("")).is_err());
    assert!(client::node_id(Some("   ")).is_err());
    assert!(client::node_id(Some(&"x".repeat(257))).is_err());
}

/// Run separately so global enablement in the lifecycle test cannot affect the off baseline.
#[tokio::test]
#[ignore = "manual hook-path microbenchmark; excludes backend/export work"]
async fn measure_hook_path_overhead() {
    use std::hint::black_box;
    assert!(global().is_none());
    let iterations = 1_000_000_u32;
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(global());
    }
    let disabled_ns = start.elapsed().as_nanos() as f64 / f64::from(iterations);
    let mut cfg = config("http://127.0.0.1:1");
    cfg.queue_capacity = 16_384;
    let recorder = Recorder::start(cfg).unwrap();
    let start = Instant::now();
    for _ in 0..16_384 {
        let received = recorder.point();
        black_box(recorder.emit("pq.aggregate_received",&received,Mode::Production,json!({
            "message":{"topic":"/eth2/01234567/beacon_aggregate_and_proof/ssz_snappy","gossip_id":"0x0123456789012345678901234567890123456789"},
            "attempt":recorder.reference(),"received":received,"sizes":{"ssz_bytes":10000}
        })));
    }
    let admitted_ns = start.elapsed().as_nanos() as f64 / 16_384_f64;
    assert_eq!(family(&recorder, "pq.aggregate_received").dropped, 0);
    let start = Instant::now();
    for _ in 0..16_384 {
        let received = recorder.point();
        black_box(recorder.emit("pq.aggregate_received",&received,Mode::Production,json!({
            "message":{"topic":"/eth2/01234567/beacon_aggregate_and_proof/ssz_snappy","gossip_id":"0x0123456789012345678901234567890123456789"},
            "attempt":recorder.reference(),"received":received,"sizes":{"ssz_bytes":10000}
        })));
    }
    let dropped_ns = start.elapsed().as_nanos() as f64 / 16_384_f64;
    assert_eq!(family(&recorder, "pq.aggregate_received").dropped, 16_384);
    eprintln!(
        "PQ hook-path microbenchmark: disabled global lookup {disabled_ns:.1} ns; enabled point+JSON+ID+successful queue {admitted_ns:.1} ns; same path with full-queue drop {dropped_ns:.1} ns. Current-thread worker did not run: excludes serialization, network, native proof work, and full-node contention."
    );
}

#[test]
fn clocks_never_subtract_across_processes_or_backwards() {
    let a = Point {
        process_id: "a".into(),
        mono_ns: "100".into(),
        unix_ns: "300".into(),
    };
    let mut b = Point {
        process_id: "a".into(),
        mono_ns: "200".into(),
        unix_ns: "50".into(),
    };
    assert_eq!(b.elapsed_ns_since(&a), Some(100)); // Wall time jumped backwards.
    assert_eq!(a.elapsed_ns_since(&b), None);
    b.process_id = "restarted".into();
    assert_eq!(b.elapsed_ns_since(&a), None);
}

#[tokio::test]
async fn bounded_queue_is_nonblocking_and_accounts_every_logical_record() {
    let mut c = config("http://127.0.0.1:1");
    c.queue_capacity = 2;
    let recorder = Recorder::start(c).unwrap();
    let start = Instant::now();
    for _ in 0..10_000 {
        recorder.emit(
            "pq.aggregate_received",
            &recorder.point(),
            Mode::Production,
            json!({"test":"bounded"}),
        );
    }
    // The current-thread runtime has not yielded, so exactly two records can be queued.
    assert_eq!(recorder.snapshot().queue_depth, 2);
    assert_eq!(family(&recorder, "pq.aggregate_received").generated, 10_000);
    assert_eq!(family(&recorder, "pq.aggregate_received").dropped, 9_998);
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(recorder.shutdown(Duration::from_secs(2)).await);
    assert_eq!(family(&recorder, "pq.aggregate_received").dropped, 10_000);
    assert!(recorder.snapshot().export_errors > 0);
}

#[tokio::test]
async fn identities_restart_and_invalid_records_leave_sequence_gaps() {
    let a = Recorder::start(config("http://127.0.0.1:1")).unwrap();
    let b = Recorder::start(config("http://127.0.0.1:1")).unwrap();
    assert_ne!(a.process_id(), b.process_id());
    assert_ne!(a.reference(), a.reference());
    let before = a.next_seq.load(Ordering::Relaxed);
    assert!(!a.emit(
        "pq.aggregate_received",
        &a.point(),
        Mode::Production,
        json!({"null":null})
    ));
    assert_eq!(a.next_seq.load(Ordering::Relaxed), before + 1);
    assert!(!a.emit(
        "pq.aggregate_received",
        &a.point(),
        Mode::Production,
        json!({"overflow":u64::MAX})
    ));
    assert!(!a.emit(
        "pq.aggregate_received",
        &a.point(),
        Mode::Production,
        json!({"float":1.5})
    ));
    assert!(!a.emit(
        "pq.aggregate_received",
        &b.point(),
        Mode::Production,
        json!({})
    ));
    assert_eq!(family(&a, "pq.aggregate_received").dropped, 4);
    a.record_summary_eviction("pq.aggregate_received");
    assert_eq!(family(&a, "pq.aggregate_received").summary_evictions, 1);
    assert!(a.shutdown(Duration::from_secs(2)).await);
    assert!(b.shutdown(Duration::from_secs(2)).await);
}

#[derive(Default)]
struct Collector {
    requests: Mutex<Vec<ExportLogsServiceRequest>>,
    fail: AtomicBool,
    reject_receipts: AtomicBool,
}

struct CollectorService(Arc<Collector>);

#[tonic::async_trait]
impl LogsService for CollectorService {
    async fn export(
        &self,
        request: Request<ExportLogsServiceRequest>,
    ) -> Result<Response<ExportLogsServiceResponse>, Status> {
        let request = request.into_inner();
        let receipt = request
            .resource_logs
            .iter()
            .flat_map(|r| &r.scope_logs)
            .flat_map(|s| &s.log_records)
            .any(|r| r.event_name == "pq.aggregate_received");
        self.0.requests.lock().unwrap().push(request);
        if self.0.fail.load(Ordering::Relaxed) {
            return Err(Status::unavailable("injected outage"));
        }
        Ok(Response::new(ExportLogsServiceResponse {
            partial_success: (receipt && self.0.reject_receipts.load(Ordering::Relaxed)).then(
                || ExportLogsPartialSuccess {
                    rejected_log_records: 1,
                    error_message: "injected one-record rejection".into(),
                },
            ),
        }))
    }
}

async fn collector() -> (String, Arc<Collector>, tokio::sync::oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let service = Arc::new(Collector::default());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let clone = service.clone();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(LogsServiceServer::new(CollectorService(clone)))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    (endpoint, service, stop)
}

#[tokio::test]
async fn grpc_export_survives_outage_preserves_identity_and_structured_data() {
    let (endpoint, collector, stop) = collector().await;
    collector.fail.store(true, Ordering::Relaxed);
    let recorder = Recorder::start(config(&endpoint)).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(recorder.snapshot().export_errors > 0);
    collector.fail.store(false, Ordering::Relaxed);
    let received = recorder.point();
    let attempt = recorder.reference();
    let data = json!({"message":{"topic":"/eth2/test/beacon_aggregate_and_proof/ssz_snappy","gossip_id":"0x0123"},"attempt":attempt,"received":received,"sizes":{"ssz_bytes":1048576}});
    assert!(recorder.emit(
        "pq.aggregate_received",
        &received,
        Mode::Production,
        data.clone()
    ));
    assert!(recorder.shutdown(Duration::from_secs(2)).await);
    let records: Vec<_> = collector
        .requests
        .lock()
        .unwrap()
        .iter()
        .flat_map(reconstruct)
        .collect();
    let contexts: Vec<_> = records
        .iter()
        .filter(|r| r["event_name"] == "pq.context")
        .collect();
    assert!(contexts.len() >= 2);
    assert!(contexts.windows(2).all(|p| p[0] == p[1]));
    assert_eq!(family(&recorder, "pq.context").generated, 1);
    let receipt = records
        .iter()
        .find(|r| r["event_name"] == "pq.aggregate_received")
        .unwrap();
    assert_eq!(receipt["data"], data);
    assert_eq!(receipt["timestamp_unix_ns"], json!(received.unix_ns));
    assert_eq!(receipt["process_id"], json!(recorder.process_id()));
    assert_eq!(family(&recorder, "pq.aggregate_received").dropped, 0);
    // Opt-in capture permits external validation of actual exporter output against draft3.
    if let Ok(path) = std::env::var("PQ_MEASUREMENT_TEST_CAPTURE") {
        std::fs::write(path, serde_json::to_vec_pretty(&records).unwrap()).unwrap();
    }
    let _ = stop.send(());
}

#[tokio::test]
async fn partial_rejection_is_counted_by_family_without_retry() {
    let (endpoint, collector, stop) = collector().await;
    collector.reject_receipts.store(true, Ordering::Relaxed);
    let recorder = Recorder::start(config(&endpoint)).unwrap();
    for _ in 0..3 {
        recorder.emit(
            "pq.aggregate_received",
            &recorder.point(),
            Mode::Production,
            json!({"receipt":true}),
        );
    }
    assert!(recorder.shutdown(Duration::from_secs(2)).await);
    assert_eq!(family(&recorder, "pq.aggregate_received").generated, 3);
    assert_eq!(family(&recorder, "pq.aggregate_received").dropped, 1);
    let records: Vec<_> = collector
        .requests
        .lock()
        .unwrap()
        .iter()
        .flat_map(reconstruct)
        .collect();
    assert_eq!(
        records
            .iter()
            .filter(|r| r["event_name"] == "pq.aggregate_received")
            .count(),
        3
    );
    let _ = stop.send(());
}

#[tokio::test]
async fn global_hook_lifecycles_export_real_canonical_records() {
    let (endpoint, collector, stop) = collector().await;
    client::start(
        &endpoint,
        "test-node",
        "bn",
        "test-network",
        format!("0x{}", "11".repeat(32)),
        1_790_000_000,
        Duration::from_secs(12),
        "test-client-commit",
        Some(("test-prover", Some(8))),
    )
    .unwrap();
    let recorder = global().unwrap().clone();
    crate::gossip::exercise_test_lifecycle();
    let (handoff_owner, handoff_operation) = crate::handoff::exercise_test_ownership();

    let proposal_key = duty::proposal_key(100);
    let deadline = recorder.point().unix_ns.parse::<u64>().unwrap() + 1_000_000_000;
    let owner = duty::schedule(
        proposal_key.clone(),
        json!({"kind":"proposal","slot":100,"proposal_unix_ns":deadline.to_string()}),
        Some(1),
    )
    .unwrap();
    let workload = json!({"kind":"merge","purpose":"proposal_preparation","proposal_slot":100,"vote_slots":[98],"sequence":owner.0});
    let plan = proof::Plan::new(Mode::Production, workload.clone(), Some(owner.clone())).unwrap();
    plan.messages([([1; 32], 98)]);
    let mut call = proof::Call::start(2, 0, &[[1; 32]]).unwrap();
    call.backend_finished();
    call.returned(100);
    // The first output becomes an intermediate input; the second output is installed.
    let mut call = proof::Call::start(2, 1, &[[1; 32]]).unwrap();
    call.backend_finished();
    call.returned(110);
    let selected = plan.ready("proposal").unwrap();
    drop(plan);
    let selection = recorder.point();
    duty::details(
        &proposal_key,
        json!({"selection_time":selection,"parent_root":format!("0x{}","11".repeat(32)),"selected_operations":[selected],"reused_messages":[]}),
    );
    duty::published(
        100,
        None,
        &[],
        &recorder.reference(),
        &selection,
        &recorder.point(),
        true,
    );

    let failed_key = duty::proposal_key(101);
    let failed_owner = duty::schedule(
        failed_key.clone(),
        json!({"kind":"proposal","slot":101,"proposal_unix_ns":deadline.to_string()}),
        Some(2),
    )
    .unwrap();
    let mut failure_workload = workload.clone();
    failure_workload["proposal_slot"] = json!(101);
    failure_workload["sequence"] = json!(failed_owner.0);
    let plan = proof::Plan::new(Mode::Production, failure_workload, Some(failed_owner)).unwrap();
    let mut call = proof::Call::start(2, 0, &[[1; 32]]).unwrap();
    call.backend_finished();
    drop(call);
    drop(plan);
    duty::complete(&failed_key, "failed", "backend_error", false);

    let committee_key = duty::committee_key(102, 0, 0);
    let committee_owner=duty::schedule(committee_key.clone(),json!({"kind":"committee","slot":102,"collection_unix_ns":deadline.to_string(),"broadcast_unix_ns":(deadline+1_500_000_000).to_string(),"committee_index":0,"committee_members":512,"committees_per_slot":16}),Some(3)).unwrap();
    let plan=proof::Plan::new(Mode::Production,json!({"kind":"committee","purpose":"committee_duty","vote_slot":102,"committee_index":0,"committee_members":512,"committees_per_slot":16,"signatures":128}),Some(committee_owner)).unwrap();
    let mut call = proof::Call::start(0, 128, &[[2; 32]]).unwrap();
    call.backend_finished();
    call.returned(100);
    plan.ready("committee");
    drop(plan);
    duty::details(
        &committee_key,
        json!({"collection_closed":recorder.point(),"available_signers":150,"selected_signers":128}),
    );
    duty::complete(&committee_key, "suppressed", "already_covered", false);

    // No invented duty for shared cached work, including a hybrid proof + raw-signature call.
    let plan=proof::Plan::new(Mode::Production,json!({"kind":"merge","purpose":"reusable_preparation","vote_slots":[103],"sequence":recorder.reference()}),None).unwrap();
    let mut call = proof::Call::start(1, 1, &[[3; 32]]).unwrap();
    call.backend_finished();
    call.returned(90);
    plan.ready("reusable");
    drop(plan);

    // A reorg may change committee membership without changing schedule/geometry.
    let replacement_key = duty::proposal_key(105);
    let replacement_schedule =
        json!({"kind":"proposal","slot":105,"proposal_unix_ns":deadline.to_string()});
    let first = duty::schedule(
        replacement_key.clone(),
        replacement_schedule.clone(),
        Some(5),
    )
    .unwrap();
    duty::complete(&replacement_key, "superseded", "reorg", false);
    let replacement =
        duty::schedule(replacement_key.clone(), replacement_schedule, Some(5)).unwrap();
    assert_eq!(first.0, replacement.0);
    assert_eq!(replacement.1, first.1 + 1);
    assert_eq!(duty::get(&replacement_key), Some(replacement));
    duty::complete(&replacement_key, "cancelled", "reorg", false);

    let submitted_key = duty::proposal_key(106);
    let submitted_owner = duty::schedule(
        submitted_key.clone(),
        json!({"kind":"proposal","slot":106,"proposal_unix_ns":deadline.to_string()}),
        Some(6),
    )
    .unwrap();
    duty::submitted(&submitted_key);
    duty::complete(&submitted_key, "failed", "other", false);
    assert_eq!(duty::get(&submitted_key), Some(submitted_owner));
    let published_at = recorder.point();
    duty::proposal_published(106, &published_at, &recorder.point(), true);
    assert!(duty::get(&submitted_key).is_none());

    // A completed blocking call is only ready once the waiting consumer accepts it.
    for accept in [true, false] {
        let plan=proof::Plan::new(Mode::Production,json!({"kind":"merge","purpose":"reusable_preparation","vote_slots":[104],"sequence":recorder.reference()}),None).unwrap();
        let mut call = proof::Call::start(2, 0, &[[4; 32]]).unwrap();
        call.starting();
        call.backend_finished();
        call.returned(100);
        let completion = plan.take_completion().unwrap();
        drop(plan);
        if accept {
            completion.ready("reusable");
        } else {
            drop(completion);
        }
    }

    assert!(recorder.shutdown(Duration::from_secs(5)).await);
    let records: Vec<_> = collector
        .requests
        .lock()
        .unwrap()
        .iter()
        .flat_map(reconstruct)
        .collect();
    assert_eq!(
        records
            .iter()
            .filter(|r| r["event_name"] == "pq.aggregate_received")
            .count(),
        6
    );
    assert_eq!(
        records
            .iter()
            .filter(|r| r["event_name"] == "pq.aggregate_processed")
            .count(),
        8
    );
    let completed: Vec<_> = records
        .iter()
        .filter(|r| r["event_name"] == "pq.operation_completed")
        .collect();
    assert_eq!(completed.len(), 8);
    let handed_off = completed
        .iter()
        .find(|event| event["data"]["operation"] == json!(handoff_operation))
        .unwrap();
    assert_eq!(handed_off["data"]["duty"], json!(handoff_owner));
    let duty_terminals: Vec<_> = records
        .iter()
        .filter(|event| {
            event["event_name"] == "pq.duty_completed"
                && event["data"]["duty"] == json!(handoff_owner)
        })
        .collect();
    assert_eq!(duty_terminals.len(), 1);
    assert_eq!(duty_terminals[0]["data"]["outcome"], json!("published"));
    let discarded = completed
        .iter()
        .find(|r| r["data"]["outcome"] == "discarded_late")
        .unwrap();
    assert_eq!(discarded["data"]["ready"], json!({"missing":"not_reached"}));
    assert!(discarded["data"]["backend_finished"]["mono_ns"].is_string());
    assert_eq!(
        completed
            .iter()
            .filter(|r| r["data"]["outcome"] == "failed")
            .count(),
        1
    );
    for completion in completed {
        let admission = records
            .iter()
            .find(|r| {
                r["event_name"] == "pq.operation_admitted"
                    && r["data"]["operation"] == completion["data"]["operation"]
            })
            .unwrap();
        assert_eq!(admission["data"]["queued"], completion["data"]["queued"]);
        assert_eq!(
            admission["data"]["workload"],
            completion["data"]["workload"]
        );
    }
    assert!(
        recorder
            .snapshot()
            .families
            .iter()
            .all(|(_, f)| f.dropped == 0)
    );
    if let Ok(path) = std::env::var("PQ_MEASUREMENT_HOOK_CAPTURE") {
        std::fs::write(path, serde_json::to_vec_pretty(&records).unwrap()).unwrap();
    }
    let _ = stop.send(());
}

#[test]
fn traffic_buckets_are_half_open_and_distinguish_zero_missing_and_duplicates() {
    use traffic::*;
    let start = Point {
        process_id: uuid::Uuid::new_v4().to_string(),
        unix_ns: "1800000000000000000".into(),
        mono_ns: "1000000000".into(),
    };
    let rx = Scope {
        code_location: "test:pre_dedup_decoder".into(),
        payload_encoding: Encoding::Compressed,
        copy_basis: CopyBasis::AllReceivedCopies,
    };
    let mut window = Window::new(
        "aggregate-topic".into(),
        start.clone(),
        rx,
        Scope::unavailable("test:no_tx_copy_hook"),
    )
    .unwrap();
    assert!(window.observe(Direction::Rx, &start, 500));
    assert!(window.observe(Direction::Rx, &start, 500)); // A duplicate is still another received copy.
    let mut next = start.clone();
    next.mono_ns = "1100000000".into();
    assert!(window.observe(Direction::Rx, &next, 100));
    next.mono_ns = "2000000000".into();
    assert!(!window.observe(Direction::Rx, &next, 100));
    window.mark_not_observed(Direction::Rx, 3);
    let data = window.data();
    assert_eq!(data["buckets"].as_array().unwrap().len(), 10);
    assert_eq!(
        data["buckets"][0]["rx"],
        json!({"payload_bytes":1000,"message_copies":2})
    );
    assert_eq!(data["buckets"][1]["rx"]["message_copies"], json!(1));
    assert_eq!(data["buckets"][2]["rx"]["message_copies"], json!(0));
    assert_eq!(data["buckets"][3]["rx"], json!({"missing":"not_observed"}));
    assert_eq!(data["buckets"][0]["tx"], json!({"missing":"not_exposed"}));
}
