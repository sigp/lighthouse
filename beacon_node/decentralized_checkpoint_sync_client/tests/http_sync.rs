// Reuse the real signing fixtures without duplicating helpers used by the scripted-source tests.
#[allow(dead_code, unused_imports)]
mod common;

use common::{E, Fixture, policy};
use decentralized_checkpoint_sync::LightClientSyncError;
use decentralized_checkpoint_sync_client::{
    ConsumerError, HttpLightClientDataSource, RequestLimits, SyncError, SyncUsage,
    sync_verified_finalized_header,
};
use eth2::{EmptyMetadata, ForkVersionedResponse, SensitiveUrl};
use mockito::{Matcher, Server};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use types::{EthSpec, ForkName, Hash256, LightClientFinalityUpdate, Slot};

fn envelope<T>(data: T) -> ForkVersionedResponse<T> {
    ForkVersionedResponse {
        version: ForkName::Altair,
        metadata: EmptyMetadata {},
        data,
    }
}

#[tokio::test]
async fn http_progress_requires_real_verified_finality() {
    let fixture = Fixture::new();
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
