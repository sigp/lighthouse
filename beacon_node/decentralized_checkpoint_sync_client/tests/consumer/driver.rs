use super::{data, require_send, step};
use crate::common::{E, Fixture, Request, Response, ScriptedSource, Step, policy};
use decentralized_checkpoint_sync::LightClientSyncError;
use decentralized_checkpoint_sync_client::{
    ConsumerError, RequestLimits, SourceError, SourceErrorKind, SyncBudget, SyncError, SyncOutcome,
    SyncPolicy, SyncUsage, UpdateRange, sync_verified_finalized_header,
};
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;
use types::{EthSpec, Hash256, LightClientBootstrap, Slot};

async fn sync(
    source: &mut ScriptedSource,
    fixture: &Fixture,
    policy: &SyncPolicy,
) -> Result<SyncOutcome<E>, SyncError> {
    require_send(sync_verified_finalized_header(
        source,
        fixture.trusted_root,
        Arc::new(fixture.spec.clone()),
        fixture.genesis_validators_root,
        &fixture.clock,
        policy,
    ))
    .await
}

fn bootstrap(fixture: &Fixture) -> Step {
    step(
        Request::Bootstrap(fixture.trusted_root),
        Response::Bootstrap(Box::new(data(fixture.bootstrap.clone()))),
    )
}

fn failure(request: Request, kind: SourceErrorKind) -> Step {
    Step {
        request,
        result: Err(SourceError {
            kind,
            bytes_received: 27,
            source: Some(Box::new(std::io::Error::other("scripted failure"))),
        }),
    }
}

#[tokio::test]
async fn fresh_bootstrap_or_verified_progress_can_use_the_last_budget_allowance() {
    let fixture = Fixture::new();
    let period_slots =
        E::slots_per_epoch() * fixture.spec.epochs_per_sync_committee_period.as_u64();
    // A current-period store needs finality directly, not an unnecessary next-committee fetch.
    for (fresh_bootstrap, current_period) in [(true, 0), (false, 0), (false, 1)] {
        fixture.clock.set_slot(current_period * period_slots + 4);
        let mut policy = policy();
        policy.max_finalized_lag_slots = if fresh_bootstrap { 3 } else { 2 };
        let updates = if fresh_bootstrap {
            0
        } else {
            current_period + 1
        };
        let requests = updates + 1;
        policy.max_requests = requests;
        policy.max_no_progress_requests = requests;
        policy.max_updates = updates.max(1);
        policy.max_updates_per_request = policy.max_updates;
        policy.max_total_response_bytes = 128 * requests;
        policy.request_limits =
            RequestLimits::new(Duration::from_secs(5), policy.max_total_response_bytes).unwrap();
        let mut steps = vec![bootstrap(&fixture)];
        if current_period != 0 {
            // Deliberately short: one authenticated committee suffices for period-1 finality.
            steps.push(step(
                Request::Updates(UpdateRange::new(0, 2).unwrap()),
                Response::Updates(vec![data(fixture.update.clone())]),
            ));
        }
        if !fresh_bootstrap {
            steps.push(step(
                Request::Finality,
                Response::Finality(Box::new(data(
                    fixture.finality_for_period(current_period, E::sync_committee_size()),
                ))),
            ));
        }
        let mut source = ScriptedSource::new(steps);
        let outcome = sync(&mut source, &fixture, &policy).await.unwrap();
        assert_eq!(
            outcome.header.slot(),
            Slot::new(if fresh_bootstrap {
                1
            } else {
                current_period * period_slots + 2
            })
        );
        assert_eq!(
            outcome.usage,
            SyncUsage {
                requests,
                updates,
                response_bytes: 128 * requests
            }
        );
        for (index, (_, limits)) in source.requests.iter().enumerate() {
            assert_eq!(limits.max_response_bytes(), 128 * (requests - index as u64));
        }
        source.assert_finished();
    }
}

#[tokio::test]
async fn exhausted_budgets_stop_before_another_request() {
    let fixture = Fixture::new();
    fixture.clock.set_slot(
        2 * E::slots_per_epoch() * fixture.spec.epochs_per_sync_committee_period.as_u64() + 4,
    );
    let next_period = fixture.update_for_period(1, E::sync_committee_size());
    for resource in [
        SyncBudget::Requests,
        SyncBudget::Updates,
        SyncBudget::ResponseBytes,
    ] {
        let mut policy = policy();
        policy.max_finalized_lag_slots = 2;
        let mut steps = vec![bootstrap(&fixture)];
        let limit = match resource {
            SyncBudget::Requests => {
                policy.max_requests = 1;
                policy.max_no_progress_requests = 1;
                1
            }
            SyncBudget::Updates => {
                policy.max_updates = 2;
                policy.max_updates_per_request = 2;
                steps.push(step(
                    Request::Updates(UpdateRange::new(0, 2).unwrap()),
                    Response::Updates(vec![data(fixture.update.clone())]),
                ));
                // The remaining allowance, not the original page cap, bounds the next range.
                steps.push(step(
                    Request::Updates(UpdateRange::new(1, 1).unwrap()),
                    Response::Updates(vec![data(next_period.clone())]),
                ));
                2
            }
            SyncBudget::ResponseBytes => {
                policy.max_total_response_bytes = 128;
                policy.request_limits = RequestLimits::new(Duration::from_secs(5), 128).unwrap();
                128
            }
        };
        let mut source = ScriptedSource::new(steps);
        let error = sync(&mut source, &fixture, &policy).await.unwrap_err();
        assert!(
            matches!(error, SyncError::BudgetExceeded { resource: actual, limit: actual_limit }
            if actual == resource && actual_limit == limit),
            "{error:?}"
        );
        source.assert_finished();
    }
}

#[tokio::test]
async fn transient_retry_preserves_the_store_and_accounts_failed_response_bytes() {
    let fixture = Fixture::new();
    fixture.clock.set_slot(
        E::slots_per_epoch() * fixture.spec.epochs_per_sync_committee_period.as_u64() + 4,
    );
    let mut policy = policy();
    policy.max_finalized_lag_slots = 2;
    policy.max_no_progress_requests = 2;
    policy.initial_retry_delay = Duration::from_millis(1);
    policy.max_retry_delay = policy.initial_retry_delay;
    policy.max_updates = 2;
    policy.max_updates_per_request = 2;
    policy.max_total_response_bytes = 411;
    policy.request_limits = RequestLimits::new(Duration::from_secs(5), 411).unwrap();
    let range = UpdateRange::new(0, 2).unwrap();
    let mut source = ScriptedSource::new([
        bootstrap(&fixture),
        failure(
            Request::Updates(range),
            SourceErrorKind::Transient { retry_after: None },
        ),
        step(
            Request::Updates(range),
            Response::Updates(vec![data(fixture.update.clone())]),
        ),
        step(
            Request::Finality,
            Response::Finality(Box::new(data(
                fixture.finality_for_period(1, E::sync_committee_size()),
            ))),
        ),
    ]);
    let outcome = sync(&mut source, &fixture, &policy).await.unwrap();
    assert_eq!(
        outcome.usage,
        SyncUsage {
            requests: 4,
            updates: 2,
            response_bytes: 411
        }
    );
    assert_eq!(
        source
            .requests
            .iter()
            .map(|(_, limits)| limits.max_response_bytes())
            .collect::<Vec<_>>(),
        vec![411, 283, 256, 128]
    );
    source.assert_finished();
}

#[tokio::test]
async fn unavailable_invalid_and_verification_errors_are_not_retried() {
    let fixture = Fixture::new();
    for kind in [
        SourceErrorKind::Unavailable,
        SourceErrorKind::InvalidData,
        SourceErrorKind::Configuration,
        SourceErrorKind::LocalFailure,
    ] {
        let mut source = ScriptedSource::new([failure(
            Request::Bootstrap(fixture.trusted_root),
            kind.clone(),
        )]);
        let error = sync(&mut source, &fixture, &policy()).await.unwrap_err();
        let SyncError::Consumer(ConsumerError::Source(error)) = error else {
            panic!("expected terminal source error: {error:?}");
        };
        assert_eq!(error.kind, kind);
        assert_eq!(error.bytes_received, 27);
        assert_eq!(error.source.unwrap().to_string(), "scripted failure");
        source.assert_finished();
    }
    let mut invalid = fixture.bootstrap.clone();
    let LightClientBootstrap::Altair(inner) = &mut invalid else {
        unreachable!()
    };
    inner.current_sync_committee_branch[0] = Hash256::repeat_byte(99);
    let mut source = ScriptedSource::new([step(
        Request::Bootstrap(fixture.trusted_root),
        Response::Bootstrap(Box::new(data(invalid))),
    )]);
    assert!(matches!(
        sync(&mut source, &fixture, &policy()).await,
        Err(SyncError::Consumer(ConsumerError::Verification(
            LightClientSyncError::InvalidCurrentSyncCommitteeProof
        )))
    ));
    source.assert_finished();
}

#[tokio::test]
async fn empty_or_minority_responses_do_not_reset_no_progress() {
    let fixture = Fixture::new();
    fixture.clock.set_slot(
        E::slots_per_epoch() * fixture.spec.epochs_per_sync_committee_period.as_u64() + 4,
    );
    let minority = data(fixture.update_for_period(0, 1));
    for page in [vec![], vec![minority]] {
        let mut policy = policy();
        policy.max_finalized_lag_slots = 2;
        policy.max_no_progress_requests = 2;
        let range = UpdateRange::new(0, 2).unwrap();
        let mut source = ScriptedSource::new([
            bootstrap(&fixture),
            step(Request::Updates(range), Response::Updates(page.clone())),
            step(Request::Updates(range), Response::Updates(page)),
        ]);
        assert!(matches!(
            sync(&mut source, &fixture, &policy).await,
            Err(SyncError::NoProgress { requests: 2 })
        ));
        source.assert_finished();
    }
}

#[tokio::test(start_paused = true)]
async fn backoff_is_exponential_capped_and_retry_after_is_a_lower_bound() {
    let fixture = Fixture::new();
    let mut policy = policy();
    policy.max_retries = 3;
    policy.max_no_progress_requests = 8;
    policy.max_retry_delay = Duration::from_millis(300);
    let mut source = ScriptedSource::new(
        [Some(Duration::from_millis(250)), None, None, None]
            .into_iter()
            .map(|retry_after| {
                failure(
                    Request::Bootstrap(fixture.trusted_root),
                    SourceErrorKind::Transient { retry_after },
                )
            }),
    );
    let started = Instant::now();
    let error = sync(&mut source, &fixture, &policy).await.unwrap_err();
    assert!(
        matches!(error, SyncError::RetriesExhausted { attempts: 4, .. }),
        "{error:?}"
    );
    assert_eq!(started.elapsed(), Duration::from_millis(750));
    source.assert_finished();
}

#[tokio::test(start_paused = true)]
async fn retry_after_cap_and_total_deadline_bound_retry_waits() {
    let fixture = Fixture::new();
    for retry_after in [Some(Duration::from_secs(3)), None] {
        let mut policy = policy();
        policy.sync_timeout = Duration::from_secs(3);
        policy.request_limits = RequestLimits::new(Duration::from_secs(3), 1024).unwrap();
        policy.initial_retry_delay = Duration::from_secs(2);
        let attempts = if retry_after.is_some() { 1 } else { 2 };
        let mut source = ScriptedSource::new((0..attempts).map(|_| {
            failure(
                Request::Bootstrap(fixture.trusted_root),
                SourceErrorKind::Transient { retry_after },
            )
        }));
        let error = sync(&mut source, &fixture, &policy).await.unwrap_err();
        if retry_after.is_some() {
            assert!(
                matches!(error, SyncError::RetryDelayExceeded { requested, maximum }
                if requested == Duration::from_secs(3) && maximum == Duration::from_secs(2))
            );
        } else {
            assert!(matches!(error, SyncError::DeadlineExceeded), "{error:?}");
            assert!(source.requests.last().unwrap().1.timeout() <= Duration::from_secs(1));
        }
        source.assert_finished();
    }
}

#[tokio::test(start_paused = true)]
async fn timed_out_io_is_bounded_and_charges_its_unobservable_byte_allowance() {
    let fixture = Fixture::new();
    let mut policy = policy();
    policy.request_limits = RequestLimits::new(Duration::from_secs(1), 128).unwrap();
    policy.max_total_response_bytes = 256;
    policy.max_retries = 1;
    let mut source = ScriptedSource::new([bootstrap(&fixture), bootstrap(&fixture)]);
    source.request_delay = Duration::from_secs(10);
    let started = Instant::now();
    let error = sync(&mut source, &fixture, &policy).await.unwrap_err();
    let SyncError::RetriesExhausted {
        attempts,
        source: error,
    } = error
    else {
        panic!("expected timed-out attempts: {error:?}");
    };
    assert_eq!(attempts, 2);
    assert_eq!(error.bytes_received, 128);
    assert!(matches!(error.kind, SourceErrorKind::Transient { .. }));
    assert_eq!(started.elapsed(), Duration::from_millis(2_100));
    source.assert_finished();
}

#[tokio::test]
async fn ready_response_after_request_deadline_is_not_accepted() {
    let fixture = Fixture::new();
    let mut policy = policy();
    policy.request_limits = RequestLimits::new(Duration::from_millis(5), 128).unwrap();
    policy.max_retries = 0;
    let mut source = ScriptedSource::new([bootstrap(&fixture)]);
    // A deliberately non-cooperative source prevents the timer from winning the first poll.
    source.on_request = Some(Box::new(|| std::thread::sleep(Duration::from_millis(20))));
    let error = sync(&mut source, &fixture, &policy).await.unwrap_err();
    let SyncError::RetriesExhausted {
        attempts,
        source: error,
    } = error
    else {
        panic!("expected expired request, not authenticated bootstrap: {error:?}");
    };
    assert_eq!(attempts, 1);
    assert_eq!(error.bytes_received, 128);
    assert!(matches!(error.kind, SourceErrorKind::Transient { .. }));
    source.assert_finished();
}

#[tokio::test(start_paused = true)]
async fn dropping_driver_cancels_pending_io_and_retry_waits() {
    let fixture = Fixture::new();
    for pending_io in [true, false] {
        let mut source = ScriptedSource::new([if pending_io {
            bootstrap(&fixture)
        } else {
            failure(
                Request::Bootstrap(fixture.trusted_root),
                SourceErrorKind::Transient { retry_after: None },
            )
        }]);
        if pending_io {
            source.request_delay = Duration::from_secs(10);
        }
        let policy = policy();
        {
            let future = sync(&mut source, &fixture, &policy);
            tokio::pin!(future);
            tokio::select! {
                result = &mut future => panic!("driver ended before cancellation: {result:?}"),
                () = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
        }
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(source.requests.len(), 1);
        source.assert_finished();
    }
}

#[tokio::test(start_paused = true)]
async fn clock_high_water_mark_survives_transient_failures() {
    let fixture = Fixture::new();
    let mut source = ScriptedSource::new([
        failure(
            Request::Bootstrap(fixture.trusted_root),
            SourceErrorKind::Transient { retry_after: None },
        ),
        bootstrap(&fixture),
    ]);
    let clock = fixture.clock.clone();
    let mut requests = 0;
    source.on_request = Some(Box::new(move || {
        requests += 1;
        clock.set_slot(if requests == 1 { 5 } else { 4 });
    }));
    assert!(matches!(sync(&mut source, &fixture, &policy()).await,
        Err(SyncError::Consumer(ConsumerError::ClockWentBackwards { previous, current }))
        if previous == Slot::new(5) && current == Slot::new(4)
    ));
    source.assert_finished();
}
