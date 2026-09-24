#[path = "consumer/bootstrap.rs"]
mod bootstrap;
mod common;
#[path = "consumer/driver.rs"]
mod driver;
#[path = "consumer/finality.rs"]
mod finality;
#[path = "consumer/updates.rs"]
mod updates;

use common::{E, Fixture, Request, Response, ScriptedSource, Step, policy};
use decentralized_checkpoint_sync::{
    LightClientStoreSchema, LightClientSyncError, initialize_light_client_store,
    process_light_client_finality_update, process_light_client_update,
    validate_light_client_update,
};
use decentralized_checkpoint_sync_client::{
    BootstrapError, LightClientData, LightClientDataSource, RequestLimits, SourceError,
    SourceErrorKind, SourceResponse, UpdateRange, bootstrap_light_client_store,
    process_finality_update, process_next_update_range,
};
use slot_clock::SlotClock;
use std::{sync::Arc, time::Duration};
use types::{ForkName, Hash256, LightClientUpdate, Slot, SyncAggregate};

fn data<T>(data: T) -> LightClientData<T> {
    LightClientData {
        data_fork: ForkName::Altair,
        data,
    }
}

fn limits() -> RequestLimits {
    policy().request_limits
}

fn step(request: Request, response: Response) -> Step {
    Step {
        request,
        result: Ok(SourceResponse {
            data: response,
            bytes_received: 128,
        }),
    }
}

fn require_send<T: Send>(value: T) -> T {
    value
}

#[tokio::test]
async fn scripted_reads_preserve_requests_and_produce_real_verifiable_data() {
    let fixture = Fixture::new();
    let range = UpdateRange::new(0, 1).unwrap();
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
            Response::Finality(Box::new(data(fixture.finality.clone()))),
        ),
    ]);

    let bootstrap = require_send(source.get_bootstrap(fixture.trusted_root, limits()))
        .await
        .unwrap();
    assert_eq!(bootstrap.bytes_received, 128);
    assert_eq!(bootstrap.data.data_fork, ForkName::Altair);
    assert_eq!(bootstrap.data.data, fixture.bootstrap);
    let mut store = initialize_light_client_store(
        fixture.trusted_root,
        &bootstrap.data.data,
        bootstrap.data.data_fork,
        LightClientStoreSchema::Altair,
        &fixture.spec,
    )
    .unwrap();
    let mut finality_store = fixture.store();
    let updates = require_send(source.get_updates(range, limits()))
        .await
        .unwrap();
    assert_eq!(updates.bytes_received, 128);
    assert_eq!(updates.data.len(), 1);
    for update in &updates.data {
        let validated = validate_light_client_update(
            &mut store,
            &update.data,
            update.data_fork,
            fixture.clock.now().unwrap(),
            fixture.genesis_validators_root,
            &fixture.spec,
        )
        .unwrap();
        process_light_client_update(validated).unwrap();
    }
    assert_eq!(store.verified_checkpoint_header().slot(), Slot::new(2));
    assert_eq!(
        store.verified_checkpoint_header().beacon_state_root(),
        Hash256::repeat_byte(43)
    );
    assert!(store.next_sync_committee().is_some());

    let finality = require_send(source.get_finality_update(limits()))
        .await
        .unwrap();
    assert_eq!(finality.bytes_received, 128);
    assert_eq!(finality.data.data, fixture.finality);
    process_light_client_finality_update(
        &mut finality_store,
        &finality.data.data,
        finality.data.data_fork,
        fixture.clock.now().unwrap(),
        fixture.genesis_validators_root,
        &fixture.spec,
    )
    .unwrap();
    assert_eq!(
        finality_store
            .verified_checkpoint_header()
            .beacon_block_root(),
        store.verified_checkpoint_header().beacon_block_root()
    );
    assert_eq!(
        source.requests,
        vec![
            (Request::Bootstrap(fixture.trusted_root), limits()),
            (Request::Updates(range), limits()),
            (Request::Finality, limits()),
        ]
    );
    source.assert_finished();
    fixture.clock.advance_slot();
    assert_eq!(fixture.clock.now(), Some(Slot::new(5)));
}

#[tokio::test]
async fn successful_source_read_does_not_authenticate_an_invalid_signature() {
    let mut fixture = Fixture::new();
    let LightClientUpdate::Altair(update) = &mut fixture.update else {
        panic!("expected Altair fixture");
    };
    update.sync_aggregate.sync_committee_signature =
        SyncAggregate::<E>::new().sync_committee_signature;
    let range = UpdateRange::new(0, 1).unwrap();
    let mut source = ScriptedSource::new([step(
        Request::Updates(range),
        Response::Updates(vec![data(fixture.update.clone())]),
    )]);
    let response = source.get_updates(range, limits()).await.unwrap();
    let mut store = fixture.store();
    // Store deliberately exposes neither Clone nor mutable fields to external consumers.
    let before = format!("{store:?}");
    let update = response.data.first().unwrap();
    assert!(matches!(
        validate_light_client_update(
            &mut store,
            &update.data,
            update.data_fork,
            fixture.clock.now().unwrap(),
            fixture.genesis_validators_root,
            &fixture.spec,
        ),
        Err(LightClientSyncError::InvalidSyncCommitteeSignature)
    ));
    assert_eq!(format!("{store:?}"), before);
    source.assert_finished();
}

#[tokio::test]
async fn consumer_steps_preserve_source_error_category_cause_and_failed_response_accounting() {
    let fixture = Fixture::new();
    let spec = Arc::new(fixture.spec.clone());
    for kind in [
        SourceErrorKind::Unavailable,
        SourceErrorKind::Transient {
            retry_after: Some(Duration::from_secs(3)),
        },
        SourceErrorKind::InvalidData,
        SourceErrorKind::UnsupportedFork(ForkName::Gloas),
        SourceErrorKind::Configuration,
        SourceErrorKind::LocalFailure,
    ] {
        for request in [
            Request::Bootstrap(fixture.trusted_root),
            Request::Updates(UpdateRange::new(0, 1).unwrap()),
            Request::Finality,
        ] {
            let mut source = ScriptedSource::new([Step {
                request: request.clone(),
                result: Err(SourceError {
                    kind: kind.clone(),
                    bytes_received: 27,
                    source: Some(Box::new(std::io::Error::other("scripted failure"))),
                }),
            }]);
            let error = match request {
                Request::Bootstrap(_) => bootstrap_light_client_store(
                    &mut source,
                    fixture.trusted_root,
                    spec.clone(),
                    &fixture.clock,
                    &policy(),
                )
                .await
                .unwrap_err(),
                Request::Updates(_) => process_next_update_range(
                    &mut source,
                    fixture.store(),
                    spec.clone(),
                    fixture.genesis_validators_root,
                    &fixture.clock,
                    &policy(),
                )
                .await
                .unwrap_err(),
                Request::Finality => process_finality_update(
                    &mut source,
                    fixture.store(),
                    spec.clone(),
                    fixture.genesis_validators_root,
                    &fixture.clock,
                    &policy(),
                )
                .await
                .unwrap_err(),
            };
            let BootstrapError::Source(error) = error else {
                panic!("expected source error, got {error:?}");
            };
            assert_eq!(error.kind, kind);
            assert_eq!(error.bytes_received, 27);
            assert_eq!(error.source.unwrap().to_string(), "scripted failure");
            source.assert_finished();
        }
    }
}

#[tokio::test]
async fn empty_and_short_pages_remain_explicit_untrusted_responses() {
    let fixture = Fixture::new();
    let range = UpdateRange::new(0, 2).unwrap();
    let mut source = ScriptedSource::new([
        step(Request::Updates(range), Response::Updates(vec![])),
        step(
            Request::Updates(range),
            Response::Updates(vec![data(fixture.update)]),
        ),
    ]);
    assert!(
        source
            .get_updates(range, limits())
            .await
            .unwrap()
            .data
            .is_empty()
    );
    assert_eq!(
        source
            .get_updates(range, limits())
            .await
            .unwrap()
            .data
            .len(),
        1
    );
    source.assert_finished();
}

#[tokio::test]
async fn source_does_not_rewrite_untrusted_fork_metadata() {
    let fixture = Fixture::new();
    let mut source = ScriptedSource::new([step(
        Request::Bootstrap(fixture.trusted_root),
        Response::Bootstrap(Box::new(LightClientData {
            data_fork: ForkName::Gloas,
            data: fixture.bootstrap,
        })),
    )]);
    let response = source
        .get_bootstrap(fixture.trusted_root, limits())
        .await
        .unwrap();
    assert_eq!(response.data.data_fork, ForkName::Gloas);
    assert!(matches!(
        initialize_light_client_store(
            fixture.trusted_root,
            &response.data.data,
            response.data.data_fork,
            LightClientStoreSchema::Altair,
            &fixture.spec,
        ),
        Err(LightClientSyncError::UnsupportedFork(ForkName::Gloas))
    ));
    source.assert_finished();
}

#[tokio::test]
async fn scripted_byte_limits_apply_to_success_and_error_responses() {
    let range = UpdateRange::new(0, 1).unwrap();
    for result in [
        Ok(SourceResponse {
            data: Response::Updates(vec![]),
            bytes_received: 1_025,
        }),
        Err(SourceError {
            kind: SourceErrorKind::Unavailable,
            bytes_received: 1_025,
            source: None,
        }),
    ] {
        let mut source = ScriptedSource::new([Step {
            request: Request::Updates(range),
            result,
        }]);
        let error = source.get_updates(range, limits()).await.unwrap_err();
        assert_eq!(
            error.kind,
            SourceErrorKind::ResponseTooLarge { limit: 1_024 }
        );
        assert_eq!(error.bytes_received, 1_025);
        source.assert_finished();
    }
}

#[tokio::test]
#[should_panic(expected = "source request does not match script")]
async fn script_rejects_wrong_request_parameters() {
    let mut source = ScriptedSource::new([step(
        Request::Updates(UpdateRange::new(0, 1).unwrap()),
        Response::Updates(vec![]),
    )]);
    let _ = source
        .get_updates(UpdateRange::new(1, 1).unwrap(), limits())
        .await;
}
