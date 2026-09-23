use super::{data, require_send, step};
use crate::common::{E, Fixture, Request, Response, ScriptedSource, policy};
use decentralized_checkpoint_sync::{
    LightClientStoreSchema, LightClientSyncError, upgrade_light_client_update,
};
use decentralized_checkpoint_sync_client::{
    ConsumerError, LightClientData, PolicyError, UpdateRange, UpdateRangeError,
    bootstrap_light_client_store, next_update_range, process_next_update_range,
};
use slot_clock::SlotClock;
use std::sync::Arc;
use types::{Epoch, EthSpec, ForkName, LightClientUpdate, Slot, SyncAggregate};

#[tokio::test]
async fn full_and_short_pages_continue_from_processed_committees() {
    let fixture = Fixture::new();
    let spec = Arc::new(fixture.spec.clone());
    let period_slots = E::slots_per_epoch() * spec.epochs_per_sync_committee_period.as_u64();
    fixture.clock.set_slot(2 * period_slots + 4);
    let updates = [
        fixture.update.clone(),
        fixture.update_for_period(1, E::sync_committee_size()),
        fixture.update_for_period(2, E::sync_committee_size()),
    ];
    let mut policy = policy();
    policy.max_updates_per_request = 2;
    for first_page_len in [1, 2] {
        let mut source = ScriptedSource::new([
            step(
                Request::Bootstrap(fixture.trusted_root),
                Response::Bootstrap(Box::new(data(fixture.bootstrap.clone()))),
            ),
            step(
                Request::Updates(UpdateRange::new(0, 2).unwrap()),
                Response::Updates(
                    updates[..first_page_len]
                        .iter()
                        .cloned()
                        .map(data)
                        .collect(),
                ),
            ),
            step(
                Request::Updates(
                    UpdateRange::new(first_page_len as u64, (3 - first_page_len) as u64).unwrap(),
                ),
                Response::Updates(
                    updates[first_page_len..]
                        .iter()
                        .cloned()
                        .map(data)
                        .collect(),
                ),
            ),
        ]);
        let mut store = bootstrap_light_client_store(
            &mut source,
            fixture.trusted_root,
            spec.clone(),
            &fixture.clock,
            &policy,
        )
        .await
        .unwrap()
        .store;
        for count in [first_page_len, 3 - first_page_len] {
            let result = require_send(process_next_update_range(
                &mut source,
                store,
                spec.clone(),
                fixture.genesis_validators_root,
                &fixture.clock,
                &policy,
            ))
            .await
            .unwrap();
            assert_eq!(result.updates_processed, count as u64);
            assert_eq!(result.bytes_received, 128);
            store = result.store;
        }
        assert_eq!(
            store.verified_checkpoint_header().slot(),
            Slot::new(2 * period_slots + 2)
        );
        assert_eq!(
            store.current_sync_committee(),
            updates[1].next_sync_committee().as_ref()
        );
        assert_eq!(
            store.next_sync_committee(),
            Some(updates[2].next_sync_committee().as_ref())
        );
        // No future-period request. This is not a claim that the finality target has been met.
        let result = process_next_update_range(
            &mut source,
            store,
            spec.clone(),
            fixture.genesis_validators_root,
            &fixture.clock,
            &policy,
        )
        .await
        .unwrap();
        assert_eq!(result.range, None);
        assert_eq!((result.updates_processed, result.bytes_received), (0, 0));
        source.assert_finished();
    }
}

#[tokio::test]
async fn empty_and_minority_pages_do_not_skip_the_missing_committee() {
    let fixture = Fixture::new();
    let spec = Arc::new(fixture.spec.clone());
    fixture
        .clock
        .set_slot(2 * E::slots_per_epoch() * spec.epochs_per_sync_committee_period.as_u64());
    let range = UpdateRange::new(0, 3).unwrap();
    let minority = fixture.update_for_period(0, 1);
    for page in [vec![], vec![data(minority)]] {
        let count = page.len();
        let mut source =
            ScriptedSource::new([step(Request::Updates(range), Response::Updates(page))]);
        let result = process_next_update_range(
            &mut source,
            fixture.store(),
            spec.clone(),
            fixture.genesis_validators_root,
            &fixture.clock,
            &policy(),
        )
        .await
        .unwrap();
        assert_eq!(result.range, Some(range));
        assert_eq!(result.updates_processed, count as u64);
        assert_eq!(
            result
                .store
                .verified_checkpoint_header()
                .beacon_block_root(),
            fixture.trusted_root
        );
        assert!(result.store.next_sync_committee().is_none());
        assert_eq!(result.store.best_valid_update().is_some(), count != 0);
        assert_eq!(
            next_update_range(&result.store, fixture.clock.now().unwrap(), &spec, 8).unwrap(),
            Some(range)
        );
        source.assert_finished();
    }
}

#[tokio::test]
async fn malformed_page_geometry_is_rejected_before_processing() {
    let fixture = Fixture::new();
    let spec = Arc::new(fixture.spec.clone());
    let period_slots = E::slots_per_epoch() * spec.epochs_per_sync_committee_period.as_u64();
    fixture.clock.set_slot(2 * period_slots + 4);
    let range = UpdateRange::new(0, 3).unwrap();
    let cases: &[(&[u64], UpdateRangeError)] = &[
        (
            &[0, 0, 0, 0],
            UpdateRangeError::TooManyUpdates {
                actual: 4,
                maximum: 3,
            },
        ),
        (
            &[3],
            UpdateRangeError::OutsideRange {
                period: 3,
                start: 0,
                end: 3,
            },
        ),
        (
            &[1],
            UpdateRangeError::MissingStartPeriod {
                expected: 0,
                actual: 1,
            },
        ),
        (
            &[0, 0],
            UpdateRangeError::NonConsecutivePeriods {
                expected: 1,
                actual: 0,
            },
        ),
        (
            &[0, 2],
            UpdateRangeError::NonConsecutivePeriods {
                expected: 1,
                actual: 2,
            },
        ),
        (
            &[0, 1, 0],
            UpdateRangeError::NonConsecutivePeriods {
                expected: 2,
                actual: 0,
            },
        ),
    ];
    for (periods, expected) in cases {
        let page = periods
            .iter()
            .map(|period| {
                let mut update = fixture.update.clone();
                let LightClientUpdate::Altair(inner) = &mut update else {
                    unreachable!()
                };
                // Deliberately do not re-sign: the envelope must fail before any crypto work.
                inner.attested_header.beacon.slot = Slot::new(period * period_slots + 3);
                data(update)
            })
            .collect();
        let mut source =
            ScriptedSource::new([step(Request::Updates(range), Response::Updates(page))]);
        let error = process_next_update_range(
            &mut source,
            fixture.store(),
            spec.clone(),
            fixture.genesis_validators_root,
            &fixture.clock,
            &policy(),
        )
        .await
        .unwrap_err();
        let ConsumerError::Range(actual) = error else {
            panic!("{periods:?}: {error:?}")
        };
        assert_eq!(&actual, expected);
        source.assert_finished();
    }
}

#[tokio::test]
async fn invalid_suffix_never_publishes_a_partially_processed_page() {
    let fixture = Fixture::new();
    let spec = Arc::new(fixture.spec.clone());
    fixture
        .clock
        .set_slot(E::slots_per_epoch() * spec.epochs_per_sync_committee_period.as_u64() + 4);
    let next = fixture.update_for_period(1, E::sync_committee_size());
    let minority = fixture.update_for_period(0, 1);
    for fault in ["signature", "unsupported", "missing_committee"] {
        let mut first = data(fixture.update.clone());
        let mut second = data(next.clone());
        let expected = match fault {
            "signature" => {
                let LightClientUpdate::Altair(inner) = &mut second.data else {
                    unreachable!()
                };
                inner.sync_aggregate.sync_committee_signature =
                    SyncAggregate::<E>::new().sync_committee_signature;
                LightClientSyncError::InvalidSyncCommitteeSignature
            }
            "unsupported" => {
                second.data_fork = ForkName::Gloas;
                LightClientSyncError::UnsupportedFork(ForkName::Gloas)
            }
            "missing_committee" => {
                first.data = minority.clone();
                LightClientSyncError::InvalidSignaturePeriod {
                    store_period: 0,
                    signature_period: 1,
                }
            }
            _ => unreachable!(),
        };
        let mut source = ScriptedSource::new([step(
            Request::Updates(UpdateRange::new(0, 2).unwrap()),
            Response::Updates(vec![first, second]),
        )]);
        let error = process_next_update_range(
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
async fn historical_update_uses_the_local_fork_that_activated_during_fetch() {
    let fixture = Fixture::new();
    let mut spec = fixture.spec.clone();
    spec.capella_fork_epoch = Some(Epoch::new(1));
    let mut source = ScriptedSource::new([step(
        Request::Updates(UpdateRange::new(0, 1).unwrap()),
        Response::Updates(vec![LightClientData {
            data_fork: ForkName::Capella,
            data: upgrade_light_client_update(&fixture.update, ForkName::Capella).unwrap(),
        }]),
    )]);
    let clock = fixture.clock.clone();
    source.on_request = Some(Box::new(move || clock.set_slot(8)));
    let result = process_next_update_range(
        &mut source,
        fixture.store(),
        Arc::new(spec),
        fixture.genesis_validators_root,
        &fixture.clock,
        &policy(),
    )
    .await
    .unwrap();
    assert_eq!(result.store.store_schema(), LightClientStoreSchema::Capella);
    assert_eq!(
        result.store.verified_checkpoint_header().slot(),
        Slot::new(2)
    );
    assert_eq!(
        result.store.verified_checkpoint_header().fork(),
        ForkName::Altair
    );
    source.assert_finished();
}

#[tokio::test]
async fn range_membership_uses_attested_not_signature_period() {
    let fixture = Fixture::new();
    let mut update = fixture.update.clone();
    let LightClientUpdate::Altair(inner) = &mut update else {
        unreachable!()
    };
    let period_slots =
        E::slots_per_epoch() * fixture.spec.epochs_per_sync_committee_period.as_u64();
    inner.signature_slot = Slot::new(period_slots);
    fixture.clock.set_slot(period_slots);
    let mut policy = policy();
    policy.max_updates_per_request = 1;
    let mut source = ScriptedSource::new([step(
        Request::Updates(UpdateRange::new(0, 1).unwrap()),
        Response::Updates(vec![data(update)]),
    )]);
    let error = process_next_update_range(
        &mut source,
        fixture.store(),
        Arc::new(fixture.spec.clone()),
        fixture.genesis_validators_root,
        &fixture.clock,
        &policy,
    )
    .await
    .unwrap_err();
    // The range envelope is valid. The real core rejects the unknown signing committee instead.
    assert!(matches!(
        error,
        ConsumerError::Verification(LightClientSyncError::InvalidSignaturePeriod {
            store_period: 0,
            signature_period: 1
        })
    ));
    source.assert_finished();
}

#[test]
fn planner_checks_configuration_and_local_bounds() {
    let fixture = Fixture::new();
    let store = fixture.store();
    for (count, expected) in [
        (0, PolicyError::ZeroLimit("update count")),
        (
            129,
            PolicyError::TooManyUpdates {
                count: 129,
                maximum: 128,
            },
        ),
    ] {
        let error = next_update_range(&store, Slot::new(4), &fixture.spec, count).unwrap_err();
        let ConsumerError::Policy(actual) = error else {
            panic!("{error:?}")
        };
        assert_eq!(actual, expected);
    }
    assert!(matches!(
        next_update_range(&store, Slot::new(0), &fixture.spec, 1),
        Err(ConsumerError::FutureStore { .. })
    ));
    let mut spec = fixture.spec.clone();
    spec.epochs_per_sync_committee_period = Epoch::new(0);
    assert!(matches!(
        next_update_range(&store, Slot::new(4), &spec, 1),
        Err(ConsumerError::InvalidPeriodConfiguration)
    ));
}
