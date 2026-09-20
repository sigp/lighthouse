use super::{data, require_send, step};
use crate::common::{Fixture, Request, Response, ScriptedSource, policy};
use decentralized_checkpoint_sync::{
    LightClientStoreSchema, LightClientSyncError, upgrade_light_client_bootstrap,
};
use decentralized_checkpoint_sync_client::{
    BootstrapError, LightClientData, PolicyError, bootstrap_light_client_store,
};
use std::{sync::Arc, time::Duration};
use types::{Epoch, ForkName, Hash256, LightClientBootstrap, Slot};

#[tokio::test]
async fn trusted_bootstrap_uses_local_schema_and_preserves_historical_data_fork() {
    let fixture = Fixture::new();
    let mut spec = fixture.spec.clone();
    spec.capella_fork_epoch = Some(Epoch::new(1));
    let spec = Arc::new(spec);
    let mut policy = policy();
    // A stale trusted bootstrap is a valid starting point, not a successful recent sync.
    policy.max_finalized_lag_slots = 0;
    for data_fork in [ForkName::Altair, ForkName::Bellatrix, ForkName::Capella] {
        fixture.clock.set_slot(4);
        let mut source = ScriptedSource::new([step(
            Request::Bootstrap(fixture.trusted_root),
            Response::Bootstrap(Box::new(LightClientData {
                data_fork,
                data: upgrade_light_client_bootstrap(&fixture.bootstrap, data_fork).unwrap(),
            })),
        )]);
        let clock = fixture.clock.clone();
        // Capella activates while the request is in flight; metadata cannot choose the schema.
        source.on_request = Some(Box::new(move || clock.set_slot(8)));
        let result = require_send(bootstrap_light_client_store(
            &mut source,
            fixture.trusted_root,
            spec.clone(),
            &fixture.clock,
            &policy,
        ))
        .await
        .unwrap();
        assert_eq!(result.bytes_received, 128);
        assert_eq!(result.store.store_schema(), LightClientStoreSchema::Capella);
        let checkpoint = result.store.verified_checkpoint_header();
        assert_eq!(checkpoint.beacon_block_root(), fixture.trusted_root);
        assert_eq!(checkpoint.slot(), Slot::new(1));
        assert_eq!(checkpoint.fork(), ForkName::Altair);
        assert_eq!(
            source.requests,
            vec![(
                Request::Bootstrap(fixture.trusted_root),
                policy.request_limits
            )]
        );
        source.assert_finished();
    }
}

#[tokio::test]
async fn invalid_bootstrap_propagates_core_failure_without_returning_a_store() {
    let fixture = Fixture::new();
    let mut spec = fixture.spec.clone();
    spec.capella_fork_epoch = Some(Epoch::new(1));
    let spec = Arc::new(spec);
    fixture.clock.set_slot(8);
    let bootstrap = upgrade_light_client_bootstrap(&fixture.bootstrap, ForkName::Capella).unwrap();
    for fault in ["root", "committee", "execution", "metadata", "unsupported"] {
        let mut wire = LightClientData {
            data_fork: ForkName::Capella,
            data: bootstrap.clone(),
        };
        let LightClientBootstrap::Capella(inner) = &mut wire.data else {
            panic!("expected upgraded Capella fixture");
        };
        let expected = match fault {
            "root" => {
                inner.header.beacon.parent_root = Hash256::repeat_byte(99);
                LightClientSyncError::BootstrapRootMismatch {
                    expected: fixture.trusted_root,
                    actual: inner.header.beacon.canonical_root(),
                }
            }
            "committee" => {
                inner.current_sync_committee_branch[0] = Hash256::repeat_byte(99);
                LightClientSyncError::InvalidCurrentSyncCommitteeProof
            }
            "execution" => {
                inner.header.execution_branch[0] = Hash256::repeat_byte(99);
                LightClientSyncError::NonDefaultExecutionBranch
            }
            "metadata" => {
                wire.data_fork = ForkName::Altair;
                LightClientSyncError::HeaderVariantMismatch {
                    expected: ForkName::Altair,
                    actual: ForkName::Capella,
                }
            }
            "unsupported" => {
                wire.data_fork = ForkName::Gloas;
                LightClientSyncError::UnsupportedFork(ForkName::Gloas)
            }
            _ => unreachable!(),
        };
        let mut source = ScriptedSource::new([step(
            Request::Bootstrap(fixture.trusted_root),
            Response::Bootstrap(Box::new(wire)),
        )]);
        let error = bootstrap_light_client_store(
            &mut source,
            fixture.trusted_root,
            spec.clone(),
            &fixture.clock,
            &policy(),
        )
        .await
        .unwrap_err();
        let BootstrapError::Verification(actual) = error else {
            panic!("{fault}: expected core failure, got {error:?}");
        };
        assert_eq!(actual, expected, "{fault}");
        source.assert_finished();
    }
}

#[tokio::test]
async fn invalid_local_context_fails_before_requesting_data() {
    let fixture = Fixture::new();
    for fault in ["policy", "clock", "fork"] {
        let mut source = ScriptedSource::new([]);
        let mut policy = policy();
        let mut spec = fixture.spec.clone();
        fixture.clock.set_slot(4);
        match fault {
            "policy" => policy.max_requests = 0,
            "clock" => fixture.clock.set_current_time(Duration::ZERO),
            "fork" => spec.gloas_fork_epoch = Some(Epoch::new(0)),
            _ => unreachable!(),
        }
        let error = bootstrap_light_client_store(
            &mut source,
            fixture.trusted_root,
            Arc::new(spec),
            &fixture.clock,
            &policy,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                (fault, &error),
                (
                    "policy",
                    BootstrapError::Policy(PolicyError::ZeroLimit("request limit"))
                ) | ("clock", BootstrapError::ClockUnavailable)
                    | (
                        "fork",
                        BootstrapError::Verification(LightClientSyncError::UnsupportedFork(
                            ForkName::Gloas
                        ))
                    )
            ),
            "{fault}: {error:?}"
        );
        assert!(source.requests.is_empty());
    }
}

#[tokio::test]
async fn bootstrap_rejects_unavailable_regressing_and_behind_clocks() {
    let fixture = Fixture::new();
    let spec = Arc::new(fixture.spec.clone());
    for (start, end) in [(4, Some(3)), (4, None), (0, Some(0))] {
        fixture.clock.set_slot(start);
        let mut source = ScriptedSource::new([step(
            Request::Bootstrap(fixture.trusted_root),
            Response::Bootstrap(Box::new(data(fixture.bootstrap.clone()))),
        )]);
        let clock = fixture.clock.clone();
        source.on_request = Some(Box::new(move || match end {
            Some(slot) => clock.set_slot(slot),
            None => clock.set_current_time(Duration::ZERO),
        }));
        let error = bootstrap_light_client_store(
            &mut source,
            fixture.trusted_root,
            spec.clone(),
            &fixture.clock,
            &policy(),
        )
        .await
        .unwrap_err();
        match error {
            BootstrapError::ClockWentBackwards { previous, current } => {
                assert_eq!((start, end), (4, Some(3)));
                assert_eq!((previous, current), (Slot::new(4), Slot::new(3)));
            }
            BootstrapError::ClockUnavailable => assert_eq!(end, None),
            BootstrapError::FutureBootstrap {
                bootstrap_slot,
                current_slot,
            } => {
                assert_eq!((start, end), (0, Some(0)));
                assert_eq!((bootstrap_slot, current_slot), (Slot::new(1), Slot::new(0)));
            }
            _ => panic!("unexpected clock failure: {error:?}"),
        }
        source.assert_finished();
    }
}

#[test]
fn missing_runtime_returns_an_error_without_requesting_data() {
    use std::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    let fixture = Fixture::new();
    let mut source = ScriptedSource::new([]);
    let policy = policy();
    let spec = Arc::new(fixture.spec.clone());
    {
        let mut future = pin!(bootstrap_light_client_store(
            &mut source,
            fixture.trusted_root,
            spec,
            &fixture.clock,
            &policy,
        ));
        assert!(matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(BootstrapError::RuntimeUnavailable(_)))
        ));
    }
    assert!(source.requests.is_empty());
}
