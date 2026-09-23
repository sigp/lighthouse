use super::{data, require_send, step};
use crate::common::{E, Fixture, Request, Response, ScriptedSource, policy};
use decentralized_checkpoint_sync::{
    LightClientStoreSchema, LightClientSyncError, beacon_header,
    process_light_client_store_force_update,
};
use decentralized_checkpoint_sync_client::{
    ConsumerError, PolicyError, UpdateRange, bootstrap_light_client_store, process_finality_update,
    process_next_update_range, recent_checkpoint_header,
};
use std::{sync::Arc, time::Duration};
use types::{Epoch, EthSpec, ForkName, Hash256, LightClientFinalityUpdate, Slot, SyncAggregate};

#[tokio::test]
async fn bootstrap_range_and_finality_produce_a_recent_authenticated_checkpoint() {
    let fixture = Fixture::new();
    let spec = Arc::new(fixture.spec.clone());
    let period_slots = E::slots_per_epoch() * spec.epochs_per_sync_committee_period.as_u64();
    fixture.clock.set_slot(period_slots + 4);
    let mut policy = policy();
    policy.max_finalized_lag_slots = 2;
    let range = UpdateRange::new(0, 2).unwrap();
    let finality = fixture.finality_for_period(1, E::sync_committee_size());
    let mut source = ScriptedSource::new([
        step(
            Request::Bootstrap(fixture.trusted_root),
            Response::Bootstrap(Box::new(data(fixture.bootstrap.clone()))),
        ),
        step(
            Request::Updates(range),
            Response::Updates(vec![data(fixture.update.clone())]),
        ),
        step(
            Request::Finality,
            Response::Finality(Box::new(data(finality))),
        ),
    ]);
    let bootstrapped = bootstrap_light_client_store(
        &mut source,
        fixture.trusted_root,
        spec.clone(),
        &fixture.clock,
        &policy,
    )
    .await
    .unwrap();
    let range_result = process_next_update_range(
        &mut source,
        bootstrapped.store,
        spec.clone(),
        fixture.genesis_validators_root,
        &fixture.clock,
        &policy,
    )
    .await
    .unwrap();
    assert!(range_result.store.next_sync_committee().is_some());
    assert!(
        recent_checkpoint_header(&range_result.store, &fixture.clock, &spec, &policy)
            .unwrap()
            .is_none()
    );
    let result = require_send(process_finality_update(
        &mut source,
        range_result.store,
        spec.clone(),
        fixture.genesis_validators_root,
        &fixture.clock,
        &policy,
    ))
    .await
    .unwrap();
    assert_eq!(result.bytes_received, 128);
    let checkpoint = recent_checkpoint_header(&result.store, &fixture.clock, &spec, &policy)
        .unwrap()
        .unwrap();
    assert_eq!(&checkpoint, result.store.verified_checkpoint_header());
    assert_eq!(checkpoint.slot(), Slot::new(period_slots + 2));
    assert_eq!(checkpoint.beacon_state_root(), Hash256::repeat_byte(43));
    assert_eq!(
        source.requests,
        vec![
            (
                Request::Bootstrap(fixture.trusted_root),
                policy.request_limits
            ),
            (Request::Updates(range), policy.request_limits),
            (Request::Finality, policy.request_limits),
        ]
    );
    source.assert_finished();
    // Freshness is sampled when selecting a checkpoint, not cached at request start.
    fixture.clock.set_slot(period_slots + 5);
    assert!(
        recent_checkpoint_header(&result.store, &fixture.clock, &spec, &policy)
            .unwrap()
            .is_none()
    );
}

#[test]
fn freshness_threshold_is_inclusive_and_zero_lag_is_valid() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let mut policy = policy();
    for (current_slot, max_lag, recent) in
        [(1, 0, true), (2, 0, false), (4, 3, true), (4, 2, false)]
    {
        fixture.clock.set_slot(current_slot);
        policy.max_finalized_lag_slots = max_lag;
        let checkpoint =
            recent_checkpoint_header(&store, &fixture.clock, &fixture.spec, &policy).unwrap();
        assert_eq!(
            checkpoint.as_ref(),
            recent.then_some(store.verified_checkpoint_header())
        );
    }
}

#[tokio::test]
async fn minority_finality_advances_optimistic_state_but_not_checkpoint_eligibility() {
    let fixture = Fixture::new();
    let spec = Arc::new(fixture.spec.clone());
    let mut policy = policy();
    policy.max_finalized_lag_slots = 2;
    let mut source = ScriptedSource::new([step(
        Request::Finality,
        Response::Finality(Box::new(data(fixture.finality_for_period(0, 1)))),
    )]);
    let result = process_finality_update(
        &mut source,
        fixture.store(),
        spec.clone(),
        fixture.genesis_validators_root,
        &fixture.clock,
        &policy,
    )
    .await
    .unwrap();
    assert_eq!(
        beacon_header(result.store.optimistic_header()).slot,
        Slot::new(3)
    );
    assert_eq!(
        result
            .store
            .verified_checkpoint_header()
            .beacon_block_root(),
        fixture.trusted_root
    );
    assert!(
        recent_checkpoint_header(&result.store, &fixture.clock, &spec, &policy)
            .unwrap()
            .is_none()
    );
    source.assert_finished();
}

#[tokio::test]
async fn forced_committee_cannot_authenticate_a_later_supermajority_checkpoint() {
    let fixture = Fixture::new();
    let spec = Arc::new(fixture.spec.clone());
    let period_slots = E::slots_per_epoch() * spec.epochs_per_sync_committee_period.as_u64();
    fixture.clock.set_slot(period_slots + 4);
    let mut policy = policy();
    policy.max_finalized_lag_slots = 2;
    let mut source = ScriptedSource::new([
        step(
            Request::Updates(UpdateRange::new(0, 2).unwrap()),
            Response::Updates(vec![data(fixture.update_for_period(0, 1))]),
        ),
        step(
            Request::Finality,
            Response::Finality(Box::new(data(
                fixture.finality_for_period(1, E::sync_committee_size()),
            ))),
        ),
    ]);
    let mut store = process_next_update_range(
        &mut source,
        fixture.store(),
        spec.clone(),
        fixture.genesis_validators_root,
        &fixture.clock,
        &policy,
    )
    .await
    .unwrap()
    .store;
    // Only the real core can create this state. The consumer must not treat spec finality as trust.
    process_light_client_store_force_update(&mut store, Slot::new(period_slots + 4), &spec)
        .unwrap();
    assert_eq!(
        beacon_header(store.spec_finalized_header()).slot,
        Slot::new(2)
    );
    assert!(store.next_sync_committee().is_some());
    let result = process_finality_update(
        &mut source,
        store,
        spec.clone(),
        fixture.genesis_validators_root,
        &fixture.clock,
        &policy,
    )
    .await
    .unwrap();
    assert_eq!(
        beacon_header(result.store.spec_finalized_header()).slot,
        Slot::new(period_slots + 2)
    );
    assert_eq!(
        result
            .store
            .verified_checkpoint_header()
            .beacon_block_root(),
        fixture.trusted_root
    );
    assert!(
        recent_checkpoint_header(&result.store, &fixture.clock, &spec, &policy)
            .unwrap()
            .is_none()
    );
    source.assert_finished();
}

#[tokio::test]
async fn invalid_finality_propagates_core_errors_without_returning_a_store() {
    let fixture = Fixture::new();
    let mut spec = fixture.spec.clone();
    spec.capella_fork_epoch = Some(Epoch::new(1));
    let spec = Arc::new(spec);
    fixture.clock.set_slot(8);
    for fault in [
        "signature",
        "proof",
        "metadata",
        "unsupported",
        "irrelevant",
    ] {
        let mut wire = data(fixture.finality.clone());
        let LightClientFinalityUpdate::Altair(inner) = &mut wire.data else {
            unreachable!()
        };
        let expected = match fault {
            "signature" => {
                inner.sync_aggregate.sync_committee_signature =
                    SyncAggregate::<E>::new().sync_committee_signature;
                LightClientSyncError::InvalidSyncCommitteeSignature
            }
            "proof" => {
                inner.finality_branch[0] = Hash256::repeat_byte(99);
                LightClientSyncError::InvalidFinalityProof
            }
            "metadata" => {
                wire.data_fork = ForkName::Capella;
                LightClientSyncError::HeaderVariantMismatch {
                    expected: ForkName::Capella,
                    actual: ForkName::Altair,
                }
            }
            "unsupported" => {
                wire.data_fork = ForkName::Gloas;
                LightClientSyncError::UnsupportedFork(ForkName::Gloas)
            }
            "irrelevant" => {
                // Reject stale relevance before crypto; this is not a successful stale update.
                inner.attested_header.beacon.slot = Slot::new(1);
                inner.finalized_header.beacon.slot = Slot::new(1);
                LightClientSyncError::IrrelevantUpdate
            }
            _ => unreachable!(),
        };
        let mut source =
            ScriptedSource::new([step(Request::Finality, Response::Finality(Box::new(wire)))]);
        let error = process_finality_update(
            &mut source,
            fixture.store(),
            spec.clone(),
            fixture.genesis_validators_root,
            &fixture.clock,
            &policy(),
        )
        .await
        .unwrap_err();
        let ConsumerError::Verification(actual) = error else {
            panic!("{fault}: {error:?}")
        };
        assert_eq!(actual, expected, "{fault}");
        source.assert_finished();
    }
}

#[tokio::test]
async fn invalid_local_context_prevents_selection_and_finality_requests() {
    let fixture = Fixture::new();
    for fault in ["policy", "clock", "fork", "future_store"] {
        fixture.clock.set_slot(4);
        let mut spec = fixture.spec.clone();
        let mut policy = policy();
        match fault {
            "policy" => policy.max_requests = 0,
            "clock" => fixture.clock.set_current_time(Duration::ZERO),
            "fork" => spec.gloas_fork_epoch = Some(Epoch::new(0)),
            "future_store" => fixture.clock.set_slot(0),
            _ => unreachable!(),
        }
        let mut source = ScriptedSource::new([]);
        let store = fixture.store();
        let selection_error =
            recent_checkpoint_header(&store, &fixture.clock, &spec, &policy).unwrap_err();
        let process_error = process_finality_update(
            &mut source,
            store,
            Arc::new(spec),
            fixture.genesis_validators_root,
            &fixture.clock,
            &policy,
        )
        .await
        .unwrap_err();
        for error in [selection_error, process_error] {
            assert!(
                matches!(
                    (fault, &error),
                    (
                        "policy",
                        ConsumerError::Policy(PolicyError::ZeroLimit("request limit"))
                    ) | ("clock", ConsumerError::ClockUnavailable)
                        | (
                            "fork",
                            ConsumerError::Verification(LightClientSyncError::UnsupportedFork(
                                ForkName::Gloas
                            ))
                        )
                        | ("future_store", ConsumerError::FutureStore { .. })
                ),
                "{fault}: {error:?}"
            );
        }
        assert!(source.requests.is_empty());
    }
}

#[tokio::test]
async fn finality_rechecks_the_local_clock_and_fork_after_fetching() {
    let fixture = Fixture::new();
    let mut policy = policy();
    policy.max_finalized_lag_slots = 2;
    for end in [Some(3), None, Some(8)] {
        fixture.clock.set_slot(4);
        let mut spec = fixture.spec.clone();
        spec.capella_fork_epoch = Some(Epoch::new(1));
        let mut source = ScriptedSource::new([step(
            Request::Finality,
            Response::Finality(Box::new(data(fixture.finality.clone()))),
        )]);
        let clock = fixture.clock.clone();
        source.on_request = Some(Box::new(move || match end {
            Some(slot) => clock.set_slot(slot),
            None => clock.set_current_time(Duration::ZERO),
        }));
        let spec = Arc::new(spec);
        let result = process_finality_update(
            &mut source,
            fixture.store(),
            spec.clone(),
            fixture.genesis_validators_root,
            &fixture.clock,
            &policy,
        )
        .await;
        match end {
            Some(8) => {
                let result = result.unwrap();
                assert_eq!(result.store.store_schema(), LightClientStoreSchema::Capella);
                assert_eq!(
                    result.store.verified_checkpoint_header().slot(),
                    Slot::new(2)
                );
                assert_eq!(
                    result.store.verified_checkpoint_header().fork(),
                    ForkName::Altair
                );
                // Valid, relevant old data still processes successfully, without meeting freshness.
                assert!(
                    recent_checkpoint_header(&result.store, &fixture.clock, &spec, &policy)
                        .unwrap()
                        .is_none()
                );
            }
            Some(3) => assert!(
                matches!(result, Err(ConsumerError::ClockWentBackwards { previous, current })
                if previous == Slot::new(4) && current == Slot::new(3))
            ),
            None => assert!(matches!(result, Err(ConsumerError::ClockUnavailable))),
            _ => unreachable!(),
        }
        source.assert_finished();
    }
}
