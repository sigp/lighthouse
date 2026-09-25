// Reuse the real signing fixtures without duplicating helpers used by the scripted-source tests.
#[allow(dead_code, unused_imports)]
mod common;

use common::{E, Fixture, FixtureFor, policy};
use decentralized_checkpoint_sync::{
    LightClientStoreSchema, LightClientSyncError, upgrade_light_client_update,
};
use decentralized_checkpoint_sync_client::{
    ConsumerError, HttpLightClientDataSource, RequestLimits, SourceErrorKind, SyncBudget,
    SyncError, SyncOutcome, SyncPolicy, SyncUsage, UpdateRangeError,
    sync_verified_finalized_header,
};
use eth2::{EmptyMetadata, ForkVersionedResponse, SensitiveUrl};
use mockito::{Matcher, Mock, Server};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use types::{
    Epoch, EthSpec, ForkName, Hash256, LightClientBootstrap, LightClientFinalityUpdate,
    LightClientUpdate, MainnetEthSpec, Slot, SyncAggregate,
};

fn envelope<T>(data: T) -> ForkVersionedResponse<T> {
    ForkVersionedResponse {
        version: ForkName::Altair,
        metadata: EmptyMetadata {},
        data,
    }
}

#[tokio::test]
async fn http_progress_requires_real_verified_finality() {
    verified_http_progress::<E>().await;
}

#[tokio::test]
async fn mainnet_http_progress_requires_real_verified_finality() {
    verified_http_progress::<MainnetEthSpec>().await;
}

async fn verified_http_progress<E: EthSpec>() {
    let fixture = FixtureFor::<E>::new();
    let period_slots =
        E::slots_per_epoch() * fixture.spec.epochs_per_sync_committee_period.as_u64();
    fixture.clock.set_slot(period_slots + 4);

    for corrupt_proof in [false, true] {
        let mut finality = fixture.finality_for_period(1, E::sync_committee_size());
        let LightClientFinalityUpdate::Altair(inner) = &mut finality else {
            unreachable!("fixture uses Altair data");
        };
        let expected_header = inner.finalized_header.beacon.clone();
        if corrupt_proof {
            inner.finality_branch[0] = Hash256::repeat_byte(99);
        }

        let bodies = [
            serde_json::to_vec(&envelope(fixture.bootstrap.clone())).unwrap(),
            // A short page authenticates committee 1 without supplying committee 2.
            serde_json::to_vec(&vec![envelope(fixture.update.clone())]).unwrap(),
            serde_json::to_vec(&envelope(finality)).unwrap(),
        ];
        let total_bytes = bodies
            .iter()
            .map(|body| u64::try_from(body.len()).unwrap())
            .sum();
        let mut policy = policy();
        policy.max_finalized_lag_slots = 2;
        policy.max_updates_per_request = 2;
        policy.max_updates = 2;
        policy.max_requests = 3;
        policy.max_no_progress_requests = 3;
        // Exhausting the exact byte/request/update allowance may still return a fresh header.
        policy.max_total_response_bytes = total_bytes;
        policy.request_limits = RequestLimits::new(Duration::from_secs(5), total_bytes).unwrap();

        let mut server = Server::new_async().await;
        let mut source =
            HttpLightClientDataSource::new(SensitiveUrl::parse(&server.url()).unwrap()).unwrap();
        let routes = [
            format!(
                "/eth/v1/beacon/light_client/bootstrap/{:?}",
                fixture.trusted_root
            ),
            "/eth/v1/beacon/light_client/updates".to_owned(),
            "/eth/v1/beacon/light_client/finality_update".to_owned(),
        ];
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut mocks = Vec::new();
        for (index, (route, body)) in routes.into_iter().zip(bodies).enumerate() {
            let calls = calls.clone();
            let mut mock = server
                .mock("GET", route.as_str())
                .match_header("accept", "application/json")
                .match_header("accept-encoding", "identity")
                .with_header("content-type", "application/json")
                .with_body_from_request(move |_| {
                    calls.lock().unwrap().push(index);
                    body.clone()
                })
                .expect(1);
            if index == 1 {
                mock = mock.match_query(Matcher::AllOf(vec![
                    Matcher::UrlEncoded("start_period".into(), "0".into()),
                    Matcher::UrlEncoded("count".into(), "2".into()),
                ]));
            }
            mocks.push(mock.create_async().await);
        }

        let result = sync_verified_finalized_header::<E>(
            &mut source,
            fixture.trusted_root,
            Arc::new(fixture.spec.clone()),
            fixture.genesis_validators_root,
            &fixture.clock,
            &policy,
        )
        .await;

        if corrupt_proof {
            // HTTP 200 and valid JSON cannot promote unauthenticated data into an anchor.
            assert!(
                matches!(
                    result,
                    Err(SyncError::Consumer(ConsumerError::Verification(
                        LightClientSyncError::InvalidFinalityProof
                    )))
                ),
                "{result:?}"
            );
        } else {
            let outcome = result.unwrap();
            assert_eq!(outcome.header.slot(), Slot::new(period_slots + 2));
            assert_eq!(outcome.header.fork(), ForkName::Altair);
            assert_eq!(
                outcome.header.beacon_block_root(),
                expected_header.canonical_root()
            );
            assert_eq!(
                outcome.header.beacon_state_root(),
                expected_header.state_root
            );
            assert_eq!(
                outcome.usage,
                SyncUsage {
                    requests: 3,
                    updates: 2,
                    response_bytes: total_bytes,
                }
            );
        }
        assert_eq!(*calls.lock().unwrap(), vec![0, 1, 2]);
        for mock in mocks {
            mock.assert_async().await;
        }
    }
}

fn http_policy() -> SyncPolicy {
    let mut policy = policy();
    policy.max_finalized_lag_slots = 2;
    policy.max_total_response_bytes = 1_048_576;
    policy.request_limits = RequestLimits::new(Duration::from_secs(5), 65_536).unwrap();
    policy.initial_retry_delay = Duration::from_millis(1);
    policy
}

async fn sync(
    server: &Server,
    fixture: &Fixture,
    policy: &SyncPolicy,
) -> Result<SyncOutcome<E>, SyncError> {
    let mut source =
        HttpLightClientDataSource::new(SensitiveUrl::parse(&server.url()).unwrap()).unwrap();
    sync_verified_finalized_header(
        &mut source,
        fixture.trusted_root,
        Arc::new(fixture.spec.clone()),
        fixture.genesis_validators_root,
        &fixture.clock,
        policy,
    )
    .await
}

async fn bootstrap_mock(server: &mut Server, fixture: &Fixture) -> Mock {
    server
        .mock(
            "GET",
            format!(
                "/eth/v1/beacon/light_client/bootstrap/{:?}",
                fixture.trusted_root
            )
            .as_str(),
        )
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_vec(&envelope(fixture.bootstrap.clone())).unwrap())
        .expect(1)
        .create_async()
        .await
}

#[tokio::test]
async fn invalid_bootstrap_or_signature_never_returns_an_anchor() {
    for fault in ["root", "committee", "signature"] {
        let mut fixture = Fixture::new();
        let LightClientBootstrap::Altair(bootstrap) = &mut fixture.bootstrap else {
            unreachable!()
        };
        let expected = match fault {
            "root" => {
                bootstrap.header.beacon.parent_root = Hash256::repeat_byte(99);
                LightClientSyncError::BootstrapRootMismatch {
                    expected: fixture.trusted_root,
                    actual: bootstrap.header.beacon.canonical_root(),
                }
            }
            "committee" => {
                bootstrap.current_sync_committee_branch[0] = Hash256::repeat_byte(99);
                LightClientSyncError::InvalidCurrentSyncCommitteeProof
            }
            "signature" => {
                let LightClientFinalityUpdate::Altair(finality) = &mut fixture.finality else {
                    unreachable!()
                };
                finality.sync_aggregate.sync_committee_signature =
                    SyncAggregate::<E>::new().sync_committee_signature;
                LightClientSyncError::InvalidSyncCommitteeSignature
            }
            _ => unreachable!(),
        };
        let mut server = Server::new_async().await;
        let bootstrap = bootstrap_mock(&mut server, &fixture).await;
        let finality = server
            .mock("GET", "/eth/v1/beacon/light_client/finality_update")
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_vec(&envelope(fixture.finality.clone())).unwrap())
            .expect(usize::from(fault == "signature"))
            .create_async()
            .await;
        let error = sync(&server, &fixture, &http_policy()).await.unwrap_err();
        let SyncError::Consumer(ConsumerError::Verification(actual)) = error else {
            panic!("{fault}: expected core verification failure, got {error:?}");
        };
        assert_eq!(actual, expected, "{fault}");
        bootstrap.assert_async().await;
        finality.assert_async().await;
    }
}

#[tokio::test]
async fn empty_minority_and_replayed_stale_http_data_are_bounded() {
    let fixture = Fixture::new();
    let period_slots =
        E::slots_per_epoch() * fixture.spec.epochs_per_sync_committee_period.as_u64();
    for case in [
        "empty",
        "minority_range",
        "minority_finality",
        "stale_replay",
    ] {
        let range = matches!(case, "empty" | "minority_range");
        fixture.clock.set_slot(if range {
            period_slots + 4
        } else if case == "stale_replay" {
            10
        } else {
            4
        });
        let body = match case {
            "empty" => b"[]".to_vec(),
            "minority_range" => {
                serde_json::to_vec(&vec![envelope(fixture.update_for_period(0, 1))]).unwrap()
            }
            "minority_finality" => {
                serde_json::to_vec(&envelope(fixture.finality_for_period(0, 1))).unwrap()
            }
            "stale_replay" => serde_json::to_vec(&envelope(fixture.finality.clone())).unwrap(),
            _ => unreachable!(),
        };
        let mut policy = http_policy();
        policy.max_no_progress_requests = 2;
        let mut server = Server::new_async().await;
        let bootstrap = bootstrap_mock(&mut server, &fixture).await;
        let route = if range {
            "/eth/v1/beacon/light_client/updates"
        } else {
            "/eth/v1/beacon/light_client/finality_update"
        };
        let mut response = server
            .mock("GET", route)
            .with_header("content-type", "application/json")
            .with_body(body)
            // The first stale finality is authentic progress. Replaying it cannot reset the bound.
            .expect(if case == "stale_replay" { 3 } else { 2 });
        if range {
            response = response.match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("start_period".into(), "0".into()),
                Matcher::UrlEncoded("count".into(), "2".into()),
            ]));
        }
        let response = response.create_async().await;
        let error = sync(&server, &fixture, &policy).await.unwrap_err();
        assert!(
            matches!(error, SyncError::NoProgress { requests: 2 }),
            "{case}: {error:?}"
        );
        bootstrap.assert_async().await;
        response.assert_async().await;
    }
}

#[tokio::test]
async fn range_geometry_and_mixed_forks_are_checked_before_handoff() {
    let mut fixture = Fixture::new();
    let period_slots =
        E::slots_per_epoch() * fixture.spec.epochs_per_sync_committee_period.as_u64();
    fixture.clock.set_slot(2 * period_slots + 4);
    let next = fixture.update_for_period(1, E::sync_committee_size());
    for case in [
        "missing",
        "duplicate",
        "signature",
        "future_schema",
        "historical_forks",
    ] {
        fixture.spec.capella_fork_epoch = None;
        let mut page = vec![envelope(fixture.update.clone()), envelope(next.clone())];
        let expected = match case {
            "missing" => {
                page.remove(0);
                Some(ConsumerError::Range(UpdateRangeError::MissingStartPeriod {
                    expected: 0,
                    actual: 1,
                }))
            }
            "duplicate" => {
                page[1] = envelope(fixture.update.clone());
                Some(ConsumerError::Range(
                    UpdateRangeError::NonConsecutivePeriods {
                        expected: 1,
                        actual: 0,
                    },
                ))
            }
            "signature" => {
                let LightClientUpdate::Altair(update) = &mut page[1].data else {
                    unreachable!()
                };
                update.sync_aggregate.sync_committee_signature =
                    SyncAggregate::<E>::new().sync_committee_signature;
                Some(ConsumerError::Verification(
                    LightClientSyncError::InvalidSyncCommitteeSignature,
                ))
            }
            "future_schema" | "historical_forks" => {
                page[1].version = ForkName::Capella;
                page[1].data = upgrade_light_client_update(&next, ForkName::Capella).unwrap();
                if case == "historical_forks" {
                    // Both signed headers predate Capella. Only the trusted local schedule may
                    // enable the upgraded envelope; each item retains its own declared format.
                    fixture.spec.capella_fork_epoch =
                        Some(Epoch::new(2 * period_slots / E::slots_per_epoch()));
                    None
                } else {
                    Some(ConsumerError::Verification(
                        LightClientSyncError::UpdateSchemaTooNew {
                            update_schema: LightClientStoreSchema::Capella,
                            store_schema: LightClientStoreSchema::Altair,
                        },
                    ))
                }
            }
            _ => unreachable!(),
        };
        let mut policy = http_policy();
        policy.max_finalized_lag_slots = period_slots + 2;
        let mut server = Server::new_async().await;
        let bootstrap = bootstrap_mock(&mut server, &fixture).await;
        let updates = server
            .mock("GET", "/eth/v1/beacon/light_client/updates")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("start_period".into(), "0".into()),
                Matcher::UrlEncoded("count".into(), "3".into()),
            ]))
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_vec(&page).unwrap())
            .expect(1)
            .create_async()
            .await;
        let result = sync(&server, &fixture, &policy).await;
        match (result, expected) {
            (Ok(outcome), None) => {
                assert_eq!(outcome.header.slot(), Slot::new(period_slots + 2));
                assert_eq!(outcome.header.fork(), ForkName::Altair);
                assert_eq!(outcome.usage.requests, 2);
                assert_eq!(outcome.usage.updates, 2);
            }
            (
                Err(SyncError::Consumer(ConsumerError::Range(actual))),
                Some(ConsumerError::Range(expected)),
            ) => {
                assert_eq!(actual, expected, "{case}");
            }
            (
                Err(SyncError::Consumer(ConsumerError::Verification(actual))),
                Some(ConsumerError::Verification(expected)),
            ) => {
                assert_eq!(actual, expected, "{case}");
            }
            (result, expected) => panic!("{case}: expected {expected:?}, got {result:?}"),
        }
        bootstrap.assert_async().await;
        updates.assert_async().await;
    }
}

#[tokio::test]
async fn transient_http_errors_recover_only_with_remaining_budget() {
    let fixture = Fixture::new();
    let body = serde_json::to_vec(&envelope(fixture.bootstrap.clone())).unwrap();
    let error_body = b"provider unavailable";
    let error_bytes = error_body.len() as u64;
    let total_bytes = error_bytes + body.len() as u64;
    for status in [429, 503] {
        for stop in ["recover", "requests", "bytes", "retries"] {
            let mut policy = http_policy();
            policy.max_finalized_lag_slots = 3;
            policy.max_requests = if stop == "requests" { 1 } else { 2 };
            policy.max_no_progress_requests = policy.max_requests;
            policy.max_retries = u64::from(stop != "retries");
            policy.max_total_response_bytes = if stop == "bytes" {
                error_bytes
            } else {
                total_bytes
            };
            policy.request_limits =
                RequestLimits::new(Duration::from_secs(5), policy.max_total_response_bytes)
                    .unwrap();
            let mut server = Server::new_async().await;
            let route = format!(
                "/eth/v1/beacon/light_client/bootstrap/{:?}",
                fixture.trusted_root
            );
            let unavailable = server
                .mock("GET", route.as_str())
                .with_status(status)
                .with_header("retry-after", "0")
                .with_body(error_body)
                .expect(1)
                .create_async()
                .await;
            let recovery = server
                .mock("GET", route.as_str())
                .with_header("content-type", "application/json")
                .with_body(body.clone())
                .expect(usize::from(stop == "recover"))
                .create_async()
                .await;
            let result = sync(&server, &fixture, &policy).await;
            match (stop, result) {
                ("recover", Ok(outcome)) => {
                    assert_eq!(outcome.header.beacon_block_root(), fixture.trusted_root);
                    assert_eq!(
                        outcome.usage,
                        SyncUsage {
                            requests: 2,
                            updates: 0,
                            response_bytes: total_bytes
                        }
                    );
                }
                ("requests" | "bytes", Err(SyncError::BudgetExceeded { resource, limit })) => {
                    let expected = if stop == "requests" {
                        (SyncBudget::Requests, 1)
                    } else {
                        (SyncBudget::ResponseBytes, error_bytes)
                    };
                    assert_eq!((resource, limit), expected);
                }
                ("retries", Err(SyncError::RetriesExhausted { attempts, source })) => {
                    assert_eq!(attempts, 1);
                    assert_eq!(source.bytes_received, error_bytes);
                    assert_eq!(
                        source.kind,
                        SourceErrorKind::Transient {
                            retry_after: Some(Duration::ZERO)
                        }
                    );
                    let cause = source.source.unwrap();
                    let cause = cause
                        .downcast_ref::<eth2::light_client::RequestError>()
                        .unwrap();
                    assert_eq!(cause.status.unwrap().as_u16(), status as u16);
                }
                (_, result) => panic!("{status}/{stop}: {result:?}"),
            }
            unavailable.assert_async().await;
            recovery.assert_async().await;
        }
    }
}
