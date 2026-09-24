use decentralized_checkpoint_sync_client::{
    HttpLightClientDataSource, LightClientDataSource, RequestLimits, SourceError, SourceErrorKind,
};
use eth2::{
    EmptyMetadata, ForkVersionedResponse, SensitiveUrl,
    light_client::{RequestError, RequestErrorKind},
};
use mockito::Server;
use std::{sync::Arc, time::Duration};
use types::{
    ForkName, Hash256, LightClientBootstrap, LightClientBootstrapAltair, MinimalEthSpec,
    SyncCommittee,
};

type E = MinimalEthSpec;
const FINALITY: &str = "/eth/v1/beacon/light_client/finality_update";

fn source(server: &Server) -> HttpLightClientDataSource {
    HttpLightClientDataSource::new(SensitiveUrl::parse(&server.url()).unwrap()).unwrap()
}

fn limits(bytes: u64) -> RequestLimits {
    RequestLimits::new(Duration::from_secs(5), bytes).unwrap()
}

fn cause(error: &SourceError) -> &RequestError {
    error.source.as_ref().unwrap().downcast_ref().unwrap()
}

#[tokio::test]
async fn bootstrap_preserves_declared_fork_and_exact_body_usage() {
    let mut server = Server::new_async().await;
    let root = Hash256::repeat_byte(0xab);
    // Wire-only data: decoding must not authenticate it or infer Altair from its slot.
    let data = LightClientBootstrap::<E>::Altair(LightClientBootstrapAltair {
        header: Default::default(),
        current_sync_committee: Arc::new(SyncCommittee::temporary()),
        current_sync_committee_branch: Default::default(),
    });
    let body = serde_json::to_string(&ForkVersionedResponse {
        version: ForkName::Bellatrix,
        metadata: EmptyMetadata {},
        data: &data,
    })
    .unwrap();
    let route = format!("/eth/v1/beacon/light_client/bootstrap/{root:?}");
    let mock = server
        .mock("GET", route.as_str())
        .match_header("accept", "application/json")
        .with_header("content-type", "application/json")
        .with_body(&body)
        .expect(1)
        .create_async()
        .await;
    let response = LightClientDataSource::<E>::get_bootstrap(
        &mut source(&server),
        root,
        limits(body.len() as u64),
    )
    .await
    .unwrap();
    assert_eq!(response.data.data_fork, ForkName::Bellatrix);
    assert_eq!(response.data.data, data);
    assert_eq!(response.bytes_received, body.len() as u64);
    mock.assert_async().await;
}

#[tokio::test]
async fn actual_status_controls_classification_without_adapter_retries() {
    let mut server = Server::new_async().await;
    let mut source = source(&server);
    let retry_after = Some(Duration::from_secs(3));
    let transient = SourceErrorKind::Transient { retry_after };
    let body = r#"{"code":503,"message":"provider-controlled detail"}"#;
    for (status, expected) in [
        (404, SourceErrorKind::Unavailable),
        (408, transient.clone()),
        (429, transient.clone()),
        (500, transient.clone()),
        (502, transient.clone()),
        (503, transient.clone()),
        (504, transient),
        (400, SourceErrorKind::Configuration),
        (401, SourceErrorKind::Configuration),
        (403, SourceErrorKind::Configuration),
        (302, SourceErrorKind::Configuration),
        (501, SourceErrorKind::Configuration),
        (204, SourceErrorKind::Configuration),
    ] {
        // The body's claimed code must not override the actual HTTP status.
        let body = if status == 204 { "" } else { body };
        let mock = server
            .mock("GET", FINALITY)
            .with_status(status)
            .with_header("retry-after", "3")
            .with_body(body)
            .expect(1)
            .create_async()
            .await;
        let error = LightClientDataSource::<E>::get_finality_update(&mut source, limits(1024))
            .await
            .unwrap_err();
        assert_eq!(error.kind, expected, "HTTP {status}");
        assert_eq!(error.bytes_received, body.len() as u64);
        let cause = cause(&error);
        assert!(matches!(cause.kind, RequestErrorKind::Status));
        assert_eq!(cause.status.unwrap().as_u16(), status as u16);
        assert_eq!(cause.retry_after, retry_after);
        assert_eq!(cause.bytes_received, error.bytes_received);
        assert!(!format!("{error:?}").contains("provider-controlled detail"));
        mock.assert_async().await;
        mock.remove_async().await;
    }
}

#[tokio::test]
async fn malformed_or_oversized_responses_are_not_retryable_status_errors() {
    let mut server = Server::new_async().await;
    let mut source = source(&server);
    for (status, header, value, bytes, expected) in [
        (
            503,
            "retry-after",
            "tomorrow",
            1024,
            SourceErrorKind::InvalidData,
        ),
        (
            503,
            "content-type",
            "text/plain",
            5,
            SourceErrorKind::ResponseTooLarge { limit: 5 },
        ),
        (
            200,
            "content-type",
            "text/html",
            1024,
            SourceErrorKind::InvalidData,
        ),
    ] {
        let mock = server
            .mock("GET", FINALITY)
            .with_status(status)
            .with_header(header, value)
            .with_body("0123456789")
            .expect(1)
            .create_async()
            .await;
        let error = LightClientDataSource::<E>::get_finality_update(&mut source, limits(bytes))
            .await
            .unwrap_err();
        assert_eq!(error.kind, expected);
        assert_eq!(error.bytes_received, 0);
        assert_eq!(cause(&error).status.unwrap().as_u16(), status as u16);
        assert_eq!(cause(&error).bytes_received, 0);
        assert!(matches!(
            cause(&error).kind,
            RequestErrorKind::InvalidRetryAfter
                | RequestErrorKind::InvalidHeaders
                | RequestErrorKind::BodyTooLarge { .. }
        ));
        mock.assert_async().await;
        mock.remove_async().await;
    }
}

#[tokio::test]
async fn unsupported_or_unknown_forks_keep_the_decoder_error_and_byte_count() {
    let mut server = Server::new_async().await;
    let mut source = source(&server);
    for version in ["gloas", "future"] {
        let body = format!(r#"{{"version":"{version}","data":{{}}}}"#);
        let mock = server
            .mock("GET", FINALITY)
            .with_header("content-type", "application/json")
            .with_body(&body)
            .expect(1)
            .create_async()
            .await;
        let error = LightClientDataSource::<E>::get_finality_update(&mut source, limits(1024))
            .await
            .unwrap_err();
        assert_eq!(error.kind, SourceErrorKind::InvalidData);
        assert_eq!(error.bytes_received, body.len() as u64);
        assert!(matches!(
            cause(&error).kind,
            RequestErrorKind::InvalidJson { .. }
        ));
        mock.assert_async().await;
        mock.remove_async().await;
    }
}

#[test]
fn non_http_url_is_a_configuration_failure() {
    let error =
        HttpLightClientDataSource::new(SensitiveUrl::parse("ftp://localhost/provider").unwrap())
            .err()
            .unwrap();
    assert_eq!(error.kind, SourceErrorKind::Configuration);
    assert_eq!(error.bytes_received, 0);
    assert!(matches!(cause(&error).kind, RequestErrorKind::InvalidUrl));
}
