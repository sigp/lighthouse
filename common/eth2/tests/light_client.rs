use eth2::{
    EmptyMetadata, ForkVersionedResponse, SensitiveUrl,
    light_client::{LightClientHttpClient, RequestErrorKind, RequestLimits},
};
use mockito::{Matcher, Server};
use serde::Serialize;
use std::{sync::Arc, time::Duration};
use types::{
    ForkName, Hash256, LightClientBootstrap, LightClientBootstrapAltair,
    LightClientBootstrapCapella, LightClientBootstrapElectra, LightClientBootstrapFulu,
    LightClientFinalityUpdate, LightClientFinalityUpdateAltair, LightClientUpdate,
    LightClientUpdateAltair, MinimalEthSpec, SyncAggregate, SyncCommittee,
};

type E = MinimalEthSpec;
const FINALITY: &str = "/eth/v1/beacon/light_client/finality_update";
const UPDATES: &str = "/eth/v1/beacon/light_client/updates";

fn client(server: &Server) -> LightClientHttpClient {
    LightClientHttpClient::new(SensitiveUrl::parse(&server.url()).unwrap()).unwrap()
}

fn limits(bytes: u64) -> RequestLimits {
    RequestLimits::new(Duration::from_secs(5), bytes).unwrap()
}

fn envelope<T>(version: ForkName, data: T) -> ForkVersionedResponse<T> {
    ForkVersionedResponse {
        version,
        metadata: EmptyMetadata {},
        data,
    }
}

fn json(value: &impl Serialize) -> String {
    serde_json::to_string(value).unwrap()
}

// These are wire-format fixtures, deliberately not cryptographically valid updates.
// Verification belongs to the consumer core; this client must preserve data and fork metadata.
fn bootstrap() -> LightClientBootstrap<E> {
    LightClientBootstrap::Altair(LightClientBootstrapAltair {
        header: Default::default(),
        current_sync_committee: Arc::new(SyncCommittee::temporary()),
        current_sync_committee_branch: Default::default(),
    })
}

fn update() -> LightClientUpdate<E> {
    LightClientUpdate::Altair(LightClientUpdateAltair {
        attested_header: Default::default(),
        next_sync_committee: Arc::new(SyncCommittee::temporary()),
        next_sync_committee_branch: Default::default(),
        finalized_header: Default::default(),
        finality_branch: Default::default(),
        sync_aggregate: SyncAggregate::empty(),
        signature_slot: 4u64.into(),
    })
}

fn finality() -> LightClientFinalityUpdate<E> {
    LightClientFinalityUpdate::Altair(LightClientFinalityUpdateAltair {
        attested_header: Default::default(),
        finalized_header: Default::default(),
        finality_branch: Default::default(),
        sync_aggregate: SyncAggregate::empty(),
        signature_slot: 4u64.into(),
    })
}

#[tokio::test]
async fn routes_preserve_fork_envelopes_and_count_exact_body_bytes() {
    let mut server = Server::new_async().await;
    let client = client(&server);
    let root = Hash256::repeat_byte(0xab);
    let expected = envelope(ForkName::Bellatrix, bootstrap());
    let body = json(&expected);
    let route = format!("/eth/v1/beacon/light_client/bootstrap/{root:?}");
    let bootstrap_mock = server
        .mock("GET", route.as_str())
        .match_header("accept", "application/json")
        .match_header("accept-encoding", "identity")
        .with_header("content-type", "application/json")
        .with_body(&body)
        .create_async()
        .await;
    let response = client
        .get_bootstrap::<E>(root, limits(body.len() as u64))
        .await
        .unwrap();
    assert_eq!(response.data, expected);
    assert_eq!(response.bytes_received, body.len() as u64);
    bootstrap_mock.assert_async().await;

    // updates-by-range is an array of versioned objects, not a versioned array.
    let expected = vec![envelope(ForkName::Altair, update())];
    let body = json(&expected);
    let updates_mock = server
        .mock("GET", UPDATES)
        .match_query(Matcher::AllOf(vec![
            Matcher::UrlEncoded("start_period".into(), "7".into()),
            Matcher::UrlEncoded("count".into(), "2".into()),
        ]))
        .match_header("accept", "application/json")
        .with_header("content-type", "application/json; charset=utf-8")
        .with_body(&body)
        .create_async()
        .await;
    let response = client
        .get_updates::<E>(7, 2, limits(body.len() as u64))
        .await
        .unwrap();
    assert_eq!(response.data, expected);
    assert_eq!(response.bytes_received, body.len() as u64);
    updates_mock.assert_async().await;

    let expected = envelope(ForkName::Altair, finality());
    let body = json(&expected);
    let finality_mock = server
        .mock("GET", FINALITY)
        .match_header("accept", "application/json")
        .with_header("content-type", "application/json")
        .with_body(&body)
        .create_async()
        .await;
    let response = client
        .get_finality_update::<E>(limits(body.len() as u64))
        .await
        .unwrap();
    assert_eq!(response.data, expected);
    assert_eq!(response.bytes_received, body.len() as u64);
    finality_mock.assert_async().await;
}

#[tokio::test]
async fn upgraded_header_formats_and_empty_update_range_are_preserved() {
    let mut server = Server::new_async().await;
    let client = client(&server);
    let committee = Arc::new(SyncCommittee::temporary());
    for (fork, data) in [
        (
            ForkName::Capella,
            LightClientBootstrap::<E>::Capella(LightClientBootstrapCapella {
                header: Default::default(),
                current_sync_committee: committee.clone(),
                current_sync_committee_branch: Default::default(),
            }),
        ),
        (
            ForkName::Electra,
            LightClientBootstrap::<E>::Electra(LightClientBootstrapElectra {
                header: Default::default(),
                current_sync_committee: committee.clone(),
                current_sync_committee_branch: Default::default(),
            }),
        ),
        (
            ForkName::Fulu,
            LightClientBootstrap::<E>::Fulu(LightClientBootstrapFulu {
                header: Default::default(),
                current_sync_committee: committee.clone(),
                current_sync_committee_branch: Default::default(),
            }),
        ),
    ] {
        // Historical beacon slots do not override the declared, fork-aware wire format.
        let expected = envelope(fork, data);
        let body = json(&expected);
        let mock = server
            .mock("GET", Matcher::Any)
            .with_header("content-type", "application/json")
            .with_body(&body)
            .create_async()
            .await;
        let response = client
            .get_bootstrap::<E>(Hash256::ZERO, limits(body.len() as u64))
            .await
            .unwrap();
        assert_eq!(response.data, expected);
        mock.assert_async().await;
        mock.remove_async().await;
    }
    let mock = server
        .mock("GET", UPDATES)
        .match_query(Matcher::Any)
        .with_header("content-type", "application/json")
        .with_body("[]")
        .create_async()
        .await;
    let response = client.get_updates::<E>(0, 1, limits(2)).await.unwrap();
    assert!(response.data.is_empty());
    assert_eq!(response.bytes_received, 2);
    mock.assert_async().await;
}

#[tokio::test]
async fn malformed_and_unversioned_payloads_fail_without_losing_byte_accounting() {
    let mut server = Server::new_async().await;
    let client = client(&server);
    for body in [
        "",
        "{",
        "{}",
        r#"{"data":{}}"#,
        r#"{"version":"future","data":{}}"#,
        r#"{"version":"gloas","data":{}}"#,
        r#"{"version":"altair","data":{}}"#,
    ] {
        let mock = server
            .mock("GET", FINALITY)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;
        let error = client
            .get_finality_update::<E>(limits(1024))
            .await
            .unwrap_err();
        assert!(
            matches!(error.kind, RequestErrorKind::InvalidJson { .. }),
            "{error:?}"
        );
        assert_eq!(error.bytes_received, body.len() as u64);
        mock.assert_async().await;
        mock.remove_async().await;
    }
    let mock = server
        .mock("GET", UPDATES)
        .match_query(Matcher::Any)
        .with_header("content-type", "application/json")
        .with_body(r#"{"version":"altair","data":[]}"#)
        .create_async()
        .await;
    assert!(matches!(
        client
            .get_updates::<E>(0, 1, limits(1024))
            .await
            .unwrap_err()
            .kind,
        RequestErrorKind::InvalidJson { .. }
    ));
    mock.assert_async().await;
}

#[tokio::test]
async fn body_limits_apply_to_success_error_and_unknown_length_streams() {
    let mut server = Server::new_async().await;
    let client = client(&server);
    for status in [200, 503] {
        for chunked in [false, true] {
            let mock = server
                .mock("GET", FINALITY)
                .with_status(status)
                .with_header("content-type", "application/json");
            let mock = if chunked {
                mock.with_chunked_body(|writer| writer.write_all(b"0123456789"))
            } else {
                mock.with_body("0123456789")
            }
            .create_async()
            .await;
            let error = client
                .get_finality_update::<E>(limits(5))
                .await
                .unwrap_err();
            assert!(
                matches!(error.kind, RequestErrorKind::BodyTooLarge { limit: 5 }),
                "{error:?}"
            );
            if chunked {
                assert!(error.bytes_received > 5 && error.bytes_received <= 10);
            } else {
                assert_eq!(error.bytes_received, 0);
            }
            assert_eq!(error.status.unwrap().as_u16(), status as u16);
            mock.assert_async().await;
            mock.remove_async().await;
        }
    }
}

#[tokio::test]
async fn http_status_is_authoritative_even_for_forged_or_non_json_error_bodies() {
    let mut server = Server::new_async().await;
    let client = client(&server);
    for (status, body) in [
        (404, r#"{"code":503,"message":"retry"}"#),
        (503, "proxy unavailable"),
        (204, ""),
    ] {
        let mock = server
            .mock("GET", FINALITY)
            .with_status(status)
            .with_header("content-type", "text/plain")
            .with_body(body)
            .create_async()
            .await;
        let error = client
            .get_finality_update::<E>(limits(1024))
            .await
            .unwrap_err();
        assert!(matches!(error.kind, RequestErrorKind::Status), "{error:?}");
        assert_eq!(error.status.unwrap().as_u16(), status as u16);
        assert_eq!(error.bytes_received, body.len() as u64);
        mock.assert_async().await;
        mock.remove_async().await;
    }
}

#[tokio::test]
async fn retry_after_supports_seconds_and_http_dates_and_rejects_malformed_values() {
    let mut server = Server::new_async().await;
    let client = client(&server);
    for (value, expected) in [
        ("3", Some(3)),
        ("Sun, 06 Nov 1994 08:49:37 GMT", Some(0)),
        ("Thu, 01 Jan 2099 00:00:00 GMT", None),
    ] {
        let mock = server
            .mock("GET", FINALITY)
            .with_status(429)
            .with_header("retry-after", value)
            .with_body("busy")
            .create_async()
            .await;
        let error = client
            .get_finality_update::<E>(limits(1024))
            .await
            .unwrap_err();
        assert!(matches!(error.kind, RequestErrorKind::Status), "{error:?}");
        let delay = error.retry_after.unwrap();
        if let Some(seconds) = expected {
            assert_eq!(delay, Duration::from_secs(seconds));
        } else {
            assert!(delay > Duration::from_secs(86400));
        }
        assert_eq!(error.bytes_received, 4);
        mock.assert_async().await;
        mock.remove_async().await;
    }
    for value in ["-1", "tomorrow", "18446744073709551616"] {
        let mock = server
            .mock("GET", FINALITY)
            .with_status(503)
            .with_header("retry-after", value)
            .with_body("busy")
            .create_async()
            .await;
        let error = client
            .get_finality_update::<E>(limits(1024))
            .await
            .unwrap_err();
        assert!(
            matches!(error.kind, RequestErrorKind::InvalidRetryAfter),
            "{error:?}"
        );
        assert_eq!(error.bytes_received, 0);
        mock.assert_async().await;
        mock.remove_async().await;
    }
}

#[tokio::test]
async fn success_requires_json_content_type() {
    let mut server = Server::new_async().await;
    let client = client(&server);
    let body = json(&envelope(ForkName::Altair, finality()));
    let mock = server
        .mock("GET", FINALITY)
        .with_header("content-type", "text/html")
        .with_body(&body)
        .create_async()
        .await;
    let error = client
        .get_finality_update::<E>(limits(body.len() as u64))
        .await
        .unwrap_err();
    assert!(
        matches!(error.kind, RequestErrorKind::InvalidHeaders),
        "{error:?}"
    );
    assert_eq!(error.bytes_received, 0);
    mock.assert_async().await;
}

#[tokio::test]
async fn encoded_responses_are_rejected_before_body_or_decode_work() {
    let mut server = Server::new_async().await;
    let client = client(&server);
    for encoding in ["gzip", "br", "deflate", "zstd", "identity, gzip"] {
        let mock = server
            .mock("GET", FINALITY)
            .with_header("content-type", "application/json")
            .with_header("content-encoding", encoding)
            .with_body("encoded")
            .create_async()
            .await;
        let error = client
            .get_finality_update::<E>(limits(1024))
            .await
            .unwrap_err();
        assert!(
            matches!(error.kind, RequestErrorKind::InvalidHeaders),
            "{error:?}"
        );
        assert_eq!(error.bytes_received, 0);
        mock.assert_async().await;
        mock.remove_async().await;
    }
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let mut server = Server::new_async().await;
    let target = server.mock("GET", "/other").expect(0).create_async().await;
    let redirect = server
        .mock("GET", FINALITY)
        .with_status(302)
        .with_header("location", &format!("{}/other", server.url()))
        .with_body("moved")
        .create_async()
        .await;
    let error = client(&server)
        .get_finality_update::<E>(limits(1024))
        .await
        .unwrap_err();
    assert!(matches!(error.kind, RequestErrorKind::Status), "{error:?}");
    assert_eq!(error.status.unwrap().as_u16(), 302);
    assert_eq!(error.bytes_received, 5);
    redirect.assert_async().await;
    target.assert_async().await;
}

#[tokio::test]
async fn timeout_releases_shared_request_slot_for_the_next_request() {
    let mut server = Server::new_async().await;
    let client = client(&server);
    let started = Arc::new(tokio::sync::Notify::new());
    let started_by_server = started.clone();
    let (release, wait) = std::sync::mpsc::channel::<()>();
    let wait = std::sync::Mutex::new(wait);
    let slow = server
        .mock("GET", FINALITY)
        .with_header("content-type", "application/json")
        .with_chunked_body(move |writer| {
            writer.write_all(b"{")?;
            writer.flush()?;
            started_by_server.notify_one();
            let _ = wait.lock().unwrap().recv();
            writer.write_all(b"}")
        })
        .create_async()
        .await;
    let request = client.get_finality_update::<E>(limits(1024));
    tokio::pin!(request);
    tokio::select! {
        result = &mut request => panic!("request ended before the body stalled: {result:?}"),
        () = started.notified() => {},
    }
    // Advance only after the mock has actually received the request: no wall-clock race.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(6)).await;
    let error = request.await.unwrap_err();
    tokio::time::resume();
    drop(release);
    assert!(matches!(error.kind, RequestErrorKind::Timeout), "{error:?}");
    assert!(error.bytes_received <= 2);
    slow.assert_async().await;
    let next = server
        .mock("GET", UPDATES)
        .match_query(Matcher::Any)
        .with_header("content-type", "application/json")
        .with_body("[]")
        .create_async()
        .await;
    assert!(
        client
            .clone()
            .get_updates::<E>(0, 1, limits(2))
            .await
            .unwrap()
            .data
            .is_empty()
    );
    next.assert_async().await;
}

#[tokio::test]
async fn invalid_limits_and_ranges_fail_before_a_request() {
    assert!(matches!(
        RequestLimits::new(Duration::ZERO, 1).unwrap_err().kind,
        RequestErrorKind::InvalidLimits
    ));
    assert!(matches!(
        RequestLimits::new(Duration::from_secs(1), 0)
            .unwrap_err()
            .kind,
        RequestErrorKind::InvalidLimits
    ));
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", Matcher::Any)
        .expect(0)
        .create_async()
        .await;
    let client = client(&server);
    for (start, count) in [(0, 0), (0, 129), (u64::MAX, 2)] {
        let error = client
            .get_updates::<E>(start, count, limits(1024))
            .await
            .unwrap_err();
        assert!(
            matches!(error.kind, RequestErrorKind::InvalidRange),
            "{error:?}"
        );
        assert_eq!(error.bytes_received, 0);
    }
    mock.assert_async().await;
}
