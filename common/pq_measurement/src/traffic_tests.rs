use super::*;
use crate::{FamilyCounters, Health, Record};
use std::time::Instant;
use tokio::sync::{Notify, mpsc};

const TOPIC: &str = "/eth2/01234567/beacon_aggregate_and_proof/ssz_snappy";
const START: u64 = 123_456;
const UTC: u64 = 1_800_000_000_000_000_000;

fn topic(name: &str) -> Topic {
    Topic {
        name: name.into(),
        rx_scope: Scope {
            code_location: "decoder test".into(),
            payload_encoding: Encoding::Compressed,
            copy_basis: CopyBasis::AllReceivedCopies,
        },
        tx_scope: Scope {
            code_location: "peer queue test".into(),
            payload_encoding: Encoding::Compressed,
            copy_basis: CopyBasis::PerRecipient,
        },
    }
}
fn recorder(capacity: usize) -> (Arc<Recorder>, mpsc::Receiver<Record>) {
    let (sender, receiver) = mpsc::channel(capacity);
    (
        Arc::new(Recorder {
            process_id: "00000000-0000-4000-8000-000000000001".into(),
            node_id: "traffic-test".into(),
            context_id: "context".into(),
            origin: Instant::now(),
            next_seq: AtomicU64::new(1),
            next_ref: AtomicU64::new(0),
            max_record_bytes: 65536,
            sender,
            health: Arc::new(Health::default()),
            stopped: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(Notify::new()),
            finished: Arc::new(Notify::new()),
            done: Arc::new(AtomicBool::new(false)),
        }),
        receiver,
    )
}
fn collector(capacity: usize) -> (Arc<Collector>, mpsc::Receiver<Record>) {
    let (recorder, receiver) = recorder(capacity);
    let mut collector = Collector::new(recorder, vec![topic(TOPIC)], Limits::default()).unwrap();
    Arc::get_mut(&mut collector).unwrap().anchor = Anchor {
        process_id: "00000000-0000-4000-8000-000000000001".into(),
        mono_ns: START,
        unix_ns: UTC,
    };
    (collector, receiver)
}
fn records(receiver: &mut mpsc::Receiver<Record>) -> Vec<Record> {
    let mut result = vec![];
    while let Ok(record) = receiver.try_recv() {
        result.push(record);
    }
    result
}
fn health(collector: &Collector) -> FamilyCounters {
    collector
        .recorder
        .snapshot()
        .families
        .into_iter()
        .find(|(name, _)| *name == "pq.aggregate_traffic")
        .unwrap()
        .1
}

#[test]
fn callbacks_use_half_open_buckets_and_count_empty_payloads() {
    let (collector, mut rx) = collector(20);
    for (offset, bytes) in [
        (0, 5),
        (BUCKET_NS - 1, 7),
        (BUCKET_NS, 11),
        (WINDOW_NS - 1, 13),
        (WINDOW_NS, 0),
    ] {
        collector.observe_at(Direction::Rx, 0, bytes, START + offset);
    }
    assert!(
        records(&mut rx).is_empty(),
        "callbacks must not construct/export events"
    );
    collector.flush_at(START + WINDOW_NS);
    let first = records(&mut rx);
    assert_eq!(first.len(), 1);
    assert_eq!(
        first[0].data["buckets"][0]["rx"],
        json!({"payload_bytes":12,"message_copies":2})
    );
    assert_eq!(first[0].data["buckets"][1]["rx"]["payload_bytes"], 11);
    assert_eq!(first[0].data["buckets"][9]["rx"]["payload_bytes"], 13);
    collector.flush_at(START + 2 * WINDOW_NS);
    let second = records(&mut rx);
    assert_eq!(
        second[0].data["buckets"][0]["rx"],
        json!({"payload_bytes":0,"message_copies":1})
    );
}

#[test]
fn delayed_timer_preserves_callback_window_and_emits_idle_zeroes() {
    let (collector, mut rx) = collector(20);
    collector.observe_at(Direction::Rx, 0, 33, START + 10);
    collector.observe_at(Direction::Tx, 0, 44, START + 2 * WINDOW_NS + 5 * BUCKET_NS);
    collector.flush_at(START + 2 * WINDOW_NS + 6 * BUCKET_NS);
    let first = records(&mut rx);
    assert_eq!(first.len(), 2);
    assert_eq!(first[0].data["buckets"][0]["rx"]["payload_bytes"], 33);
    assert!(
        first[1].data["buckets"].as_array().unwrap().iter().all(
            |bucket| bucket["rx"]["message_copies"] == 0 && bucket["tx"]["message_copies"] == 0
        )
    );
    collector.flush_at(START + 3 * WINDOW_NS);
    let last = records(&mut rx);
    assert_eq!(last[0].data["buckets"][5]["tx"]["payload_bytes"], 44);
    assert_eq!(last[0].timestamp_unix_ns, (UTC + 3 * WINDOW_NS).to_string());
    assert_eq!(
        last[0].data["window_start"]["mono_ns"],
        (START + 2 * WINDOW_NS).to_string()
    );
}

#[test]
fn fixed_anchor_labels_do_not_follow_later_wall_clock_readings() {
    let (collector, mut rx) = collector(20);
    collector.flush_at(START + WINDOW_NS);
    // A later paired clock can step in either direction. Neither capture is passed to the
    // traffic driver: assignment and labels use only this process's original monotonic anchor.
    for wall in [UTC - WINDOW_NS * 100, UTC + WINDOW_NS * 100] {
        let stepped = Point {
            process_id: collector.anchor.process_id.clone(),
            mono_ns: (START + 2 * WINDOW_NS).to_string(),
            unix_ns: wall.to_string(),
        };
        assert_ne!(
            stepped.unix_ns,
            collector.anchor.boundary(2).unwrap().unix_ns
        );
    }
    collector.flush_at(START + 2 * WINDOW_NS);
    for (index, record) in records(&mut rx).iter().enumerate() {
        let start = &record.data["window_start"];
        assert_eq!(
            start["unix_ns"].as_str().unwrap().parse::<u64>().unwrap()
                - start["mono_ns"].as_str().unwrap().parse::<u64>().unwrap(),
            UTC - START
        );
        assert_eq!(
            record.timestamp_unix_ns,
            (UTC + (index as u64 + 1) * WINDOW_NS).to_string()
        );
    }
    assert!(
        Anchor {
            process_id: "x".into(),
            mono_ns: u64::MAX,
            unix_ns: UTC
        }
        .boundary(1)
        .is_none()
    );
}

#[test]
fn catch_up_and_completed_ring_are_bounded_and_evictions_are_exact() {
    let mut state = Driver::new(8, 3);
    assert_eq!(state.advance(WINDOW_NS), 0);
    assert_eq!(state.advance(9 * WINDOW_NS), 3);
    assert_eq!(state.completed.len(), 8);
    // One billion seconds is deliberately infeasible to iterate over in this test.
    assert_eq!(
        state.advance(1_000_000_000 * WINDOW_NS),
        (8 + 1_000_000_000 - 9 - 8) * 3
    );
    assert_eq!(state.completed.len(), 8);
    assert_eq!(state.completed.front().unwrap().index, 999_999_992);
    assert_eq!(state.current.index, 1_000_000_000);
    let (collector, mut rx) = collector(20);
    collector.flush_at(START + 12 * WINDOW_NS);
    assert_eq!(records(&mut rx).len(), 8);
    assert_eq!(health(&collector).summary_evictions, 4);
}

#[test]
fn contention_marks_retained_direction_unknown_not_partial() {
    let (collector, mut rx) = collector(20);
    collector.observe_at(Direction::Rx, 0, 10, START + 1);
    collector.observe_at(Direction::Tx, 0, 20, START + 2);
    let guard = collector.state.lock().unwrap();
    collector.observe_at(Direction::Rx, 0, 30, START + 3);
    drop(guard);
    collector.flush_at(START + WINDOW_NS);
    let output = records(&mut rx);
    assert!(
        output[0].data["buckets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|bucket| bucket["rx"] == json!({"missing":"not_observed"}))
    );
    assert_eq!(output[0].data["buckets"][0]["tx"]["payload_bytes"], 20);
    assert_eq!(health(&collector).summary_evictions, 1);
}

#[test]
fn overflow_invalidates_affected_bucket_and_unsupported_remains_distinct() {
    let (mut collector, mut rx) = collector(20);
    Arc::get_mut(&mut collector).unwrap().topics[0].tx_scope =
        Scope::unavailable("unavailable test hook");
    collector.observe_at(Direction::Rx, 0, MAX_COUNT, START);
    collector.observe_at(Direction::Rx, 0, 1, START + 1);
    collector.observe_at(Direction::Rx, 0, 100, START + 2);
    collector.flush_at(START + WINDOW_NS);
    let output = records(&mut rx);
    assert_eq!(
        output[0].data["buckets"][0]["rx"],
        json!({"missing":"not_observed"})
    );
    assert_eq!(output[0].data["buckets"][1]["rx"]["message_copies"], 0);
    assert_eq!(
        output[0].data["buckets"][0]["tx"],
        json!({"missing":"not_exposed"})
    );
    assert_eq!(health(&collector).summary_evictions, 1);
}

#[test]
fn shutdown_only_flushes_completed_windows_and_is_idempotent() {
    let (collector, mut rx) = collector(20);
    collector.observe_at(Direction::Rx, 0, 10, START + WINDOW_NS + 1);
    collector.shutdown_at(START + WINDOW_NS + BUCKET_NS);
    let output = records(&mut rx);
    assert_eq!(output.len(), 1);
    assert_eq!(output[0].timestamp_unix_ns, (UTC + WINDOW_NS).to_string());
    collector.shutdown_at(START + 5 * WINDOW_NS);
    collector.tick();
    collector.observe(Direction::Rx, TOPIC, 50);
    assert!(records(&mut rx).is_empty());
    assert_eq!(
        collector.state.lock().unwrap().current.topics[0].rx[0].payload_bytes,
        10
    );
}

#[test]
fn allowlist_limits_duplicates_scopes_and_export_pressure_are_explicit() {
    let (r, _rx) = recorder(20);
    assert!(Collector::new(r.clone(), vec![], Limits::default()).is_err());
    assert!(
        Collector::new(
            r.clone(),
            vec![topic(TOPIC), topic(TOPIC)],
            Limits::default()
        )
        .is_err()
    );
    assert!(
        Collector::new(
            r.clone(),
            (0..33).map(|i| topic(&format!("topic{i}"))).collect(),
            Limits::default()
        )
        .is_err()
    );
    let mut invalid = topic(TOPIC);
    invalid.rx_scope.copy_basis = CopyBasis::PerRecipient;
    assert!(Collector::new(r, vec![invalid], Limits::default()).is_err());
    let (collector, mut rx) = collector(1);
    collector.observe(Direction::Rx, "not-allowlisted", 100);
    collector.flush_at(START + 3 * WINDOW_NS);
    assert_eq!(records(&mut rx).len(), 1);
    assert_eq!(health(&collector).generated, 3);
    assert_eq!(health(&collector).dropped, 2);
}

#[test]
fn emitted_traffic_capture_for_canonical_schema_validation() {
    let (collector, mut rx) = collector(30);
    collector.observe_at(Direction::Rx, 0, 0, START);
    collector.observe_at(Direction::Tx, 0, 144, START + BUCKET_NS);
    collector.flush_at(START + WINDOW_NS);
    collector.observe_at(Direction::Rx, 0, MAX_COUNT + 1, START + WINDOW_NS);
    collector.flush_at(START + 2 * WINDOW_NS);
    let output = records(&mut rx);
    assert_eq!(output.len(), 2);
    if let Ok(path) = std::env::var("PQ_TRAFFIC_TEST_CAPTURE") {
        std::fs::write(path, serde_json::to_vec_pretty(&output).unwrap()).unwrap();
    }
}
