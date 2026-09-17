use decentralized_checkpoint_sync_client::{PolicyError, RequestLimits, SyncPolicy, UpdateRange};
use std::time::{Duration, Instant};

type PolicyChange = fn(&mut SyncPolicy);

fn policy() -> SyncPolicy {
    SyncPolicy {
        max_finalized_lag_slots: 64,
        max_updates_per_request: 8,
        request_limits: RequestLimits::new(Duration::from_secs(5), 1_024).unwrap(),
        sync_timeout: Duration::from_secs(60),
        max_requests: 32,
        max_updates: 256,
        max_total_response_bytes: 32_768,
        max_no_progress_requests: 4,
        max_retries: 2,
        initial_retry_delay: Duration::from_millis(100),
        max_retry_delay: Duration::from_secs(2),
    }
}

#[test]
fn update_ranges_have_checked_exclusive_ends() {
    let range = UpdateRange::new(9, 128).unwrap();
    assert_eq!(range.start_period(), 9);
    assert_eq!(range.count(), 128);
    assert_eq!(range.end_period(), 137);
    assert_eq!(
        UpdateRange::new(u64::MAX - 1, 1).unwrap().end_period(),
        u64::MAX
    );
    for (start_period, count) in [(u64::MAX, 1), (u64::MAX - 127, 128)] {
        assert_eq!(
            UpdateRange::new(start_period, count),
            Err(PolicyError::RangeOverflow {
                start_period,
                count
            })
        );
    }
}

#[test]
fn update_ranges_reject_zero_and_excessive_counts() {
    assert_eq!(
        UpdateRange::new(0, 0),
        Err(PolicyError::ZeroLimit("update count"))
    );
    for count in [129, u64::MAX] {
        assert_eq!(
            UpdateRange::new(0, count),
            Err(PolicyError::TooManyUpdates {
                count,
                maximum: 128
            })
        );
    }
    assert!(UpdateRange::new(0, 1).is_ok());
}

#[test]
fn request_limits_reject_zero_and_unrepresentable_timeouts() {
    assert_eq!(
        RequestLimits::new(Duration::ZERO, 1),
        Err(PolicyError::ZeroLimit("request timeout"))
    );
    assert_eq!(
        RequestLimits::new(Duration::from_secs(1), 0),
        Err(PolicyError::ZeroLimit("response byte limit"))
    );
    assert_eq!(
        RequestLimits::new(Duration::MAX, 1),
        Err(PolicyError::DeadlineOverflow)
    );
    let limits = RequestLimits::new(Duration::from_nanos(1), 1).unwrap();
    assert_eq!(limits.timeout(), Duration::from_nanos(1));
    assert_eq!(limits.max_response_bytes(), 1);
}

#[test]
fn valid_policy_has_an_explicit_deadline_and_allows_disabled_retries() {
    let mut policy = policy();
    policy.max_retries = 0;
    policy.max_finalized_lag_slots = 0;
    policy.validate().unwrap();
    let start = Instant::now();
    assert_eq!(
        policy.deadline(start).unwrap().duration_since(start),
        policy.sync_timeout
    );
}

#[test]
fn policy_rejects_each_zero_budget() {
    let cases: [(&str, PolicyChange); 8] = [
        ("update count", |p| p.max_updates_per_request = 0),
        ("sync timeout", |p| p.sync_timeout = Duration::ZERO),
        ("initial retry delay", |p| {
            p.initial_retry_delay = Duration::ZERO
        }),
        ("maximum retry delay", |p| {
            p.max_retry_delay = Duration::ZERO
        }),
        ("request limit", |p| p.max_requests = 0),
        ("update limit", |p| p.max_updates = 0),
        ("total response byte limit", |p| {
            p.max_total_response_bytes = 0
        }),
        ("no-progress request limit", |p| {
            p.max_no_progress_requests = 0
        }),
    ];
    for (name, change) in cases {
        let mut policy = policy();
        change(&mut policy);
        assert_eq!(policy.validate(), Err(PolicyError::ZeroLimit(name)));
    }
}

#[test]
fn policy_rejects_inconsistent_per_request_and_global_budgets() {
    let cases: [PolicyChange; 6] = [
        |p| p.sync_timeout = Duration::from_secs(4),
        |p| p.initial_retry_delay = Duration::from_secs(3),
        |p| p.max_retry_delay = Duration::from_secs(61),
        |p| p.max_updates = 7,
        |p| p.max_total_response_bytes = 1_023,
        |p| p.max_no_progress_requests = 33,
    ];
    for change in cases {
        let mut policy = policy();
        change(&mut policy);
        assert!(matches!(
            policy.validate(),
            Err(PolicyError::InconsistentLimits { .. })
        ));
    }
}

#[test]
fn policy_rejects_protocol_count_and_deadline_overflow() {
    let mut policy = policy();
    policy.max_updates_per_request = 129;
    assert_eq!(
        policy.validate(),
        Err(PolicyError::TooManyUpdates {
            count: 129,
            maximum: 128
        })
    );
    policy.max_updates_per_request = 8;
    policy.sync_timeout = Duration::MAX;
    assert_eq!(policy.validate(), Err(PolicyError::DeadlineOverflow));
    assert_eq!(
        policy.deadline(Instant::now()),
        Err(PolicyError::DeadlineOverflow)
    );
}
