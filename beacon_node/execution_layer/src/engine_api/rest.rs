//! Contains an implementation of the Engine API over REST + SSZ (execution-apis#793).

use crate::EngineCapabilities;
use crate::auth::Auth;
use crate::engine_api::{
    ClientVersionV1, Error, ExecutionPayloadBodyV1, ForkchoiceUpdatedResponse, GetPayloadResponse,
    NewPayloadRequest, PayloadAttributes, PayloadId, PayloadStatusV1, PayloadStatusV1Status,
};
use crate::engines::ForkchoiceState;
use crate::http::{CachedResponse, LIGHTHOUSE_JSON_CLIENT_VERSION};
use crate::json_structures::{BlobAndProofV2, BlobAndProofV3, JsonClientVersionV1};
use crate::ssz_structures::{
    JsonCapabilities, SszBlobsRequest, SszBlobsResponse, SszBodiesByHashRequest, SszBodiesResponse,
    SszCapabilities, SszExecutionPayloadEnvelopeBellatrix, SszExecutionPayloadEnvelopeCapella,
    SszExecutionPayloadEnvelopeDeneb, SszExecutionPayloadEnvelopeElectra,
    SszExecutionPayloadEnvelopeFulu, SszExecutionPayloadEnvelopeGloas, SszForkchoiceUpdate,
    SszForkchoiceUpdateAmsterdam, SszForkchoiceUpdatedResponse, SszGetPayloadResponse,
    SszPayloadStatusV1,
};
use bytes::Bytes;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::{Client, Method, StatusCode};
use sensitive_url::SensitiveUrl;
use serde::Deserialize;
use ssz::{Decode, Encode};
use std::sync::{LazyLock, OnceLock};
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::info;
use types::{EthSpec, ExecutionBlockHash, ForkName, Hash256};

const BASE: &str = "/engine/v1";
const ETH_EXECUTION_VERSION: &str = "Eth-Execution-Version";
const X_ENGINE_CLIENT_VERSION: &str = "X-Engine-Client-Version";

// SSZ for hot-path bodies/responses, JSON for the diagnostic endpoints.
const OCTET_STREAM: &str = "application/octet-stream";
const APPLICATION_JSON: &str = "application/json";
const H2_CONNECTION_WINDOW: u32 = 1024 * 1024;
const H2_STREAM_WINDOW: u32 = 1024 * 1024;

// A single HTTP-standard request timeout applied to every REST call (scaled by
// `execution_timeout_multiplier`), replacing the JSON-RPC per-method timeout SHOULDs.
const REST_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

// The CL's `X-Engine-Client-Version` header value, e.g. `LH/v6.2.1`.
static CLIENT_VERSION_HEADER: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{}/{}",
        LIGHTHOUSE_JSON_CLIENT_VERSION.code, LIGHTHOUSE_JSON_CLIENT_VERSION.version
    )
});

#[derive(Debug, Copy, Clone)]
pub enum HttpVersion {
    Http2,
    Http1,
}

impl HttpVersion {
    fn as_str(&self) -> &'static str {
        match self {
            HttpVersion::Http2 => "http2",
            HttpVersion::Http1 => "http1",
        }
    }
}

#[derive(Deserialize)]
struct JsonProblem {
    #[serde(rename = "type")]
    type_uri: String,
    detail: Option<String>,
}

/// A REST + SSZ Engine API client. Mirrors `HttpJsonRpc`, but speaks `/engine/v1/...` with
/// `application/octet-stream` SSZ bodies and RFC 7807 problem responses.
pub struct HttpRestSsz {
    pub client_h2c: Client,
    pub client_h1: Client,
    pub http_version: OnceLock<HttpVersion>,
    pub url: SensitiveUrl,
    pub execution_timeout_multiplier: u32,
    pub ssz_capabilities_cache: Mutex<Option<CachedResponse<SszCapabilities>>>,
    pub engine_version_cache: Mutex<Option<CachedResponse<Vec<ClientVersionV1>>>>,
    auth: Option<Auth>,
}

impl HttpRestSsz {
    pub fn new(
        url: SensitiveUrl,
        execution_timeout_multiplier: Option<u32>,
    ) -> Result<Self, Error> {
        let execution_timeout_multiplier = execution_timeout_multiplier.unwrap_or(1);
        Ok(Self {
            client_h2c: Client::builder()
                .timeout(REST_REQUEST_TIMEOUT * execution_timeout_multiplier)
                .http2_prior_knowledge()
                .http2_initial_stream_window_size(H2_STREAM_WINDOW)
                .http2_initial_connection_window_size(H2_CONNECTION_WINDOW)
                .build()?,
            client_h1: Client::builder()
                .timeout(REST_REQUEST_TIMEOUT * execution_timeout_multiplier)
                .build()?,
            http_version: OnceLock::new(),
            url,
            execution_timeout_multiplier,
            ssz_capabilities_cache: Mutex::new(None),
            engine_version_cache: Mutex::new(None),
            auth: None,
        })
    }

    pub fn new_with_auth(
        url: SensitiveUrl,
        auth: Auth,
        execution_timeout_multiplier: Option<u32>,
    ) -> Result<Self, Error> {
        Ok(Self {
            auth: Some(auth),
            ..Self::new(url, execution_timeout_multiplier)?
        })
    }

    fn selected_client(&self) -> &Client {
        match self.http_version.get() {
            None | Some(HttpVersion::Http2) => &self.client_h2c,
            Some(HttpVersion::Http1) => &self.client_h1,
        }
    }

    /// Probe h2c then latch the REST transport (HTTP/2, else HTTP/1.1), returning capabilities.
    pub async fn resolve_http_and_get_capabilities(
        &self,
        age_limit: Option<Duration>,
    ) -> Result<EngineCapabilities, Error> {
        let capabilities = match self.get_engine_capabilities(age_limit).await {
            Err(e) if e.is_transport_unreachable() => {
                let _ = self.http_version.set(HttpVersion::Http1);
                self.get_engine_capabilities(age_limit).await
            }
            other => {
                let _ = self.http_version.set(HttpVersion::Http2);
                other
            }
        };
        if capabilities.is_ok()
            && let Some(version) = self.http_version.get()
        {
            info!(
                transport = version.as_str(),
                "Selected REST-SSZ engine transport"
            );
        }
        capabilities
    }

    /// The single REST-SSZ transport chokepoint. `Some(bytes)` on `200`, `None` on `204`.
    pub async fn rest_request(
        &self,
        method: Method,
        path: &str,
        fork: Option<ForkName>,
        body: Option<Vec<u8>>,
        accept: &str,
    ) -> Result<Option<Bytes>, Error> {
        let client = self.selected_client();
        let url = self
            .url
            .expose_full()
            .join(&format!("{BASE}/{path}"))
            .map_err(|e| Error::RequestFailed(format!("failed to build REST url: {e}")))?;

        let mut request = client
            .request(method, url)
            .header(ACCEPT, accept)
            .header(X_ENGINE_CLIENT_VERSION, CLIENT_VERSION_HEADER.as_str());

        if let Some(fork) = fork {
            request = request.header(ETH_EXECUTION_VERSION, fork_to_header(fork)?);
        }
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, OCTET_STREAM).body(body);
        }
        if let Some(auth) = &self.auth {
            request = request.bearer_auth(auth.generate_token()?);
        }

        let response = match request.send().await {
            Ok(response) => response,
            Err(e) if e.status().is_none() && !e.is_timeout() => {
                return Err(Error::TransportUnreachable(e.to_string()));
            }
            Err(e) => return Err(e.into()),
        };
        // 401/403 are auth failures, outside the RFC 7807 model — reuse the JSON-RPC `From` mapping.
        if let Err(e) = response.error_for_status_ref()
            && matches!(
                e.status(),
                Some(StatusCode::UNAUTHORIZED) | Some(StatusCode::FORBIDDEN)
            )
        {
            return Err(e.into());
        }

        match response.status() {
            StatusCode::OK => Ok(Some(response.bytes().await?)),
            StatusCode::NO_CONTENT => Ok(None),
            status => {
                let (problem, detail) = match response.json::<JsonProblem>().await {
                    Ok(body) => (
                        body.type_uri
                            .rsplit('/')
                            .next()
                            .unwrap_or_default()
                            .to_string(),
                        body.detail,
                    ),
                    Err(_) => (String::new(), None),
                };
                Err(Error::RestProblem {
                    status: status.as_u16(),
                    problem,
                    detail,
                })
            }
        }
    }

    pub async fn get_engine_capabilities(
        &self,
        age_limit: Option<Duration>,
    ) -> Result<EngineCapabilities, Error> {
        Ok(EngineCapabilities::Ssz(
            self.get_ssz_capabilities(age_limit).await?,
        ))
    }

    pub async fn get_ssz_capabilities(
        &self,
        age_limit: Option<Duration>,
    ) -> Result<SszCapabilities, Error> {
        let mut lock = self.ssz_capabilities_cache.lock().await;
        if let Some(cached) = lock.as_ref().filter(|c| !c.older_than(age_limit)) {
            Ok(cached.data())
        } else {
            let capabilities = self.fetch_ssz_capabilities().await?;
            *lock = Some(CachedResponse::new(capabilities.clone()));
            Ok(capabilities)
        }
    }

    pub async fn clear_ssz_capabilities_cache(&self) {
        *self.ssz_capabilities_cache.lock().await = None;
    }

    async fn fetch_ssz_capabilities(&self) -> Result<SszCapabilities, Error> {
        let body = self
            .rest_request(Method::GET, "capabilities", None, None, APPLICATION_JSON)
            .await?
            .ok_or_else(|| Error::BadResponse("unexpected 204 on /capabilities".to_string()))?;
        let capabilities: JsonCapabilities = serde_json::from_slice(&body)?;
        Ok(capabilities.into())
    }

    pub async fn get_client_version_v1(&self) -> Result<Vec<ClientVersionV1>, Error> {
        let body = self
            .rest_request(Method::GET, "identity", None, None, APPLICATION_JSON)
            .await?
            .ok_or_else(|| Error::BadResponse("unexpected 204 on /identity".to_string()))?;
        let versions: Vec<JsonClientVersionV1> = serde_json::from_slice(&body)?;
        versions
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Error::InvalidClientVersion)
    }

    pub async fn get_engine_version(
        &self,
        age_limit: Option<Duration>,
    ) -> Result<Vec<ClientVersionV1>, Error> {
        if !self
            .get_ssz_capabilities(None)
            .await?
            .get_client_version_v1()
        {
            return Ok(vec![]);
        }
        let mut lock = self.engine_version_cache.lock().await;
        if let Some(cached) = lock.as_ref().filter(|c| !c.older_than(age_limit)) {
            Ok(cached.data())
        } else {
            let versions = self.get_client_version_v1().await?;
            *lock = Some(CachedResponse::new(versions.clone()));
            Ok(versions)
        }
    }

    pub async fn clear_engine_version_cache(&self) {
        *self.engine_version_cache.lock().await = None;
    }

    pub async fn new_payload<E: EthSpec>(
        &self,
        new_payload_request: NewPayloadRequest<'_, E>,
    ) -> Result<PayloadStatusV1, Error> {
        let (fork, body) = match new_payload_request {
            NewPayloadRequest::Bellatrix(request) => (
                ForkName::Bellatrix,
                SszExecutionPayloadEnvelopeBellatrix::from(request).as_ssz_bytes(),
            ),
            NewPayloadRequest::Capella(request) => (
                ForkName::Capella,
                SszExecutionPayloadEnvelopeCapella::from(request).as_ssz_bytes(),
            ),
            NewPayloadRequest::Deneb(request) => (
                ForkName::Deneb,
                SszExecutionPayloadEnvelopeDeneb::from(request).as_ssz_bytes(),
            ),
            NewPayloadRequest::Electra(request) => (
                ForkName::Electra,
                SszExecutionPayloadEnvelopeElectra::try_from(request)?.as_ssz_bytes(),
            ),
            NewPayloadRequest::Fulu(request) => (
                ForkName::Fulu,
                SszExecutionPayloadEnvelopeFulu::try_from(request)?.as_ssz_bytes(),
            ),
            NewPayloadRequest::Gloas(request) => (
                ForkName::Gloas,
                SszExecutionPayloadEnvelopeGloas::try_from(request)?.as_ssz_bytes(),
            ),
        };

        let response = self
            .rest_request(
                Method::POST,
                "payloads",
                Some(fork),
                Some(body),
                OCTET_STREAM,
            )
            .await?
            .ok_or_else(|| Error::BadResponse("unexpected 204 on /payloads".to_string()))?;

        let status =
            SszPayloadStatusV1::<E>::from_ssz_bytes(&response).map_err(Error::SszDecode)?;
        PayloadStatusV1::try_from(status).map_err(Error::BadResponse)
    }

    pub async fn forkchoice_updated<E: EthSpec>(
        &self,
        fork: ForkName,
        forkchoice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<ForkchoiceUpdatedResponse, Error> {
        let body = if fork >= ForkName::Gloas {
            SszForkchoiceUpdateAmsterdam::<E>::new(forkchoice_state, payload_attributes, None)?
                .as_ssz_bytes()
        } else {
            SszForkchoiceUpdate::new(fork, forkchoice_state, payload_attributes)?.as_ssz_bytes()
        };

        let response = self
            .rest_request(
                Method::POST,
                "forkchoice",
                Some(fork),
                Some(body),
                OCTET_STREAM,
            )
            .await?
            .ok_or_else(|| Error::BadResponse("unexpected 204 on /forkchoice".to_string()))?;

        let ssz_response = SszForkchoiceUpdatedResponse::<E>::from_ssz_bytes(&response)
            .map_err(Error::SszDecode)?;
        let response =
            ForkchoiceUpdatedResponse::try_from(ssz_response).map_err(Error::BadResponse)?;

        // `/forkchoice` MUST NOT return ACCEPTED; treat a `3` as a non-conformant EL error.
        if matches!(
            response.payload_status.status,
            PayloadStatusV1Status::Accepted
        ) {
            return Err(Error::BadResponse(
                "forkchoiceUpdated returned ACCEPTED, which is not a valid forkchoice status"
                    .to_string(),
            ));
        }

        Ok(response)
    }

    pub async fn get_payload<E: EthSpec>(
        &self,
        fork: ForkName,
        payload_id: PayloadId,
    ) -> Result<GetPayloadResponse<E>, Error> {
        let path = format!("payloads/0x{}", hex::encode(payload_id));
        let response = self
            .rest_request(Method::GET, &path, Some(fork), None, OCTET_STREAM)
            .await?
            .ok_or_else(|| Error::BadResponse("unexpected 204 on /payloads/{id}".to_string()))?;

        let built_payload = SszGetPayloadResponse::<E>::from_ssz_bytes_by_fork(&response, fork)
            .map_err(Error::SszDecode)?;
        GetPayloadResponse::try_from(built_payload)
            .map_err(|e| Error::BadResponse(format!("{e:?}")))
    }

    pub async fn get_blobs_v2<E: EthSpec>(
        &self,
        versioned_hashes: Vec<Hash256>,
    ) -> Result<Option<Vec<BlobAndProofV2<E>>>, Error> {
        let body = SszBlobsRequest::<E>::new_blobs_request_v1(versioned_hashes)?.as_ssz_bytes();
        let Some(response) = self
            .rest_request(Method::POST, "blobs/v2", None, Some(body), OCTET_STREAM)
            .await?
        else {
            return Ok(None);
        };
        let response =
            SszBlobsResponse::<E>::from_ssz_bytes(&response).map_err(Error::SszDecode)?;
        Ok(Some(response.into_v2()))
    }

    pub async fn get_blobs_v3<E: EthSpec>(
        &self,
        versioned_hashes: Vec<Hash256>,
    ) -> Result<Option<Vec<BlobAndProofV3<E>>>, Error> {
        let body = SszBlobsRequest::<E>::new_blobs_request_v1(versioned_hashes)?.as_ssz_bytes();
        let Some(response) = self
            .rest_request(Method::POST, "blobs/v3", None, Some(body), OCTET_STREAM)
            .await?
        else {
            return Ok(None);
        };
        let response =
            SszBlobsResponse::<E>::from_ssz_bytes(&response).map_err(Error::SszDecode)?;
        Ok(Some(response.into_v3()))
    }

    pub async fn get_payload_bodies_by_hash<E: EthSpec>(
        &self,
        fork: ForkName,
        block_hashes: Vec<ExecutionBlockHash>,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, Error> {
        let block_hashes = block_hashes
            .into_iter()
            .map(|hash| hash.into_root())
            .collect();
        let body = SszBodiesByHashRequest::new(block_hashes)?.as_ssz_bytes();
        let response = self
            .rest_request(
                Method::POST,
                "bodies/hash",
                Some(fork),
                Some(body),
                OCTET_STREAM,
            )
            .await?
            .ok_or_else(|| Error::BadResponse("unexpected 204 on /bodies/hash".to_string()))?;

        SszBodiesResponse::<E>::from_ssz_bytes_by_fork(&response, fork)
            .map_err(Error::SszDecode)?
            .into_bodies()
            .map_err(Error::BadResponse)
    }

    pub async fn get_payload_bodies_by_range<E: EthSpec>(
        &self,
        fork: ForkName,
        start: u64,
        count: u64,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, Error> {
        let path = format!("bodies?from={start}&count={count}");
        let response = self
            .rest_request(Method::GET, &path, Some(fork), None, OCTET_STREAM)
            .await?
            .ok_or_else(|| Error::BadResponse("unexpected 204 on /bodies".to_string()))?;

        SszBodiesResponse::<E>::from_ssz_bytes_by_fork(&response, fork)
            .map_err(Error::SszDecode)?
            .into_bodies()
            .map_err(Error::BadResponse)
    }
}

fn fork_to_header(fork: ForkName) -> Result<&'static str, Error> {
    Ok(match fork {
        ForkName::Bellatrix => "paris",
        ForkName::Capella => "shanghai",
        ForkName::Deneb => "cancun",
        ForkName::Electra => "prague",
        ForkName::Fulu => "osaka",
        ForkName::Gloas => "amsterdam",
        ForkName::Base | ForkName::Altair => {
            return Err(Error::UnsupportedForkVariant(format!(
                "no engine-api fork header for {fork}"
            )));
        }
    })
}

pub fn header_to_fork(header: &str) -> Option<ForkName> {
    Some(match header {
        "paris" => ForkName::Bellatrix,
        "shanghai" => ForkName::Capella,
        "cancun" => ForkName::Deneb,
        "prague" => ForkName::Electra,
        "osaka" => ForkName::Fulu,
        "amsterdam" => ForkName::Gloas,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::JwtKey;
    use crate::engine_api::{
        NewPayloadRequestDeneb, NewPayloadRequestFulu, NewPayloadRequestGloas,
    };
    use crate::test_utils::{Config, DEFAULT_JWT_SECRET, MockExecutionConfig, MockServer};
    use std::future::Future;
    use std::sync::Arc;
    use tokio::runtime;
    use types::{
        Address, ExecutionPayloadDeneb, ExecutionPayloadFulu, ExecutionPayloadGloas,
        ExecutionRequestsElectra, ExecutionRequestsGloas, MainnetEthSpec,
    };

    #[test]
    fn fork_to_header_maps_every_fork() {
        assert_eq!(fork_to_header(ForkName::Bellatrix).unwrap(), "paris");
        assert_eq!(fork_to_header(ForkName::Capella).unwrap(), "shanghai");
        assert_eq!(fork_to_header(ForkName::Deneb).unwrap(), "cancun");
        assert_eq!(fork_to_header(ForkName::Electra).unwrap(), "prague");
        assert_eq!(fork_to_header(ForkName::Fulu).unwrap(), "osaka");
        assert_eq!(fork_to_header(ForkName::Gloas).unwrap(), "amsterdam");
        assert!(fork_to_header(ForkName::Base).is_err());
        assert!(fork_to_header(ForkName::Altair).is_err());
    }

    #[test]
    fn header_to_fork_maps_every_header() {
        assert_eq!(header_to_fork("paris"), Some(ForkName::Bellatrix));
        assert_eq!(header_to_fork("shanghai"), Some(ForkName::Capella));
        assert_eq!(header_to_fork("cancun"), Some(ForkName::Deneb));
        assert_eq!(header_to_fork("prague"), Some(ForkName::Electra));
        assert_eq!(header_to_fork("osaka"), Some(ForkName::Fulu));
        assert_eq!(header_to_fork("amsterdam"), Some(ForkName::Gloas));
        assert_eq!(header_to_fork("frontier"), None);
        assert_eq!(header_to_fork(""), None);
    }

    #[test]
    fn capabilities_parse_full_body() {
        let body = r#"{
            "supported_forks": ["paris","shanghai","cancun","prague","osaka","amsterdam"],
            "fork_scoped_endpoints": ["payloads","forkchoice","bodies"],
            "independently_versioned": { "blobs": ["v1","v2","v3","v4"] },
            "unscoped_endpoints": ["capabilities","identity"],
            "limits": {
                "bodies.max_count": 32,
                "blobs.max_versioned_hashes": 128,
                "payload.max_bytes": 67108864
            }
        }"#;
        let capabilities: SszCapabilities = serde_json::from_str::<JsonCapabilities>(body)
            .unwrap()
            .into();

        for fork in [
            ForkName::Bellatrix,
            ForkName::Capella,
            ForkName::Deneb,
            ForkName::Electra,
            ForkName::Fulu,
            ForkName::Gloas,
        ] {
            assert!(capabilities.supported_forks.contains(&fork));
        }
        assert!(capabilities.payloads && capabilities.forkchoice && capabilities.bodies);
        assert!(
            capabilities.blobs_v1
                && capabilities.blobs_v2
                && capabilities.blobs_v3
                && capabilities.blobs_v4
        );
        assert!(capabilities.get_client_version_v1());
        assert_eq!(capabilities.limits.bodies_max_count, Some(32));
        assert_eq!(capabilities.limits.blobs_max_versioned_hashes, Some(128));
        assert_eq!(capabilities.limits.payload_max_bytes, Some(67108864));

        assert!(capabilities.new_payload(ForkName::Gloas));
        assert!(!capabilities.new_payload(ForkName::Base));
        assert_eq!(capabilities.highest_supported_fork(), Some(ForkName::Gloas));
    }

    #[test]
    fn capabilities_ignore_unknowns_and_default_absent_fields() {
        let body = r#"{
            "supported_forks": ["amsterdam","futurefork"],
            "fork_scoped_endpoints": ["payloads"],
            "independently_versioned": { "blobs": [] },
            "unscoped_endpoints": []
        }"#;
        let capabilities: SszCapabilities = serde_json::from_str::<JsonCapabilities>(body)
            .unwrap()
            .into();

        // Unrecognised forks are dropped rather than rejected.
        assert!(capabilities.supported_forks.contains(&ForkName::Gloas));
        assert_eq!(capabilities.supported_forks.len(), 1);
        assert!(capabilities.payloads && !capabilities.forkchoice && !capabilities.bodies);
        assert!(!capabilities.blobs_v2);
        assert!(!capabilities.get_client_version_v1());
        assert_eq!(capabilities.limits.payload_max_bytes, None);
    }

    #[test]
    fn problem_body_parses_with_and_without_detail() {
        let with_detail = r#"{"type":"/engine-api/errors/unknown-payload","detail":"no such id"}"#;
        let problem: JsonProblem = serde_json::from_str(with_detail).unwrap();
        assert_eq!(problem.type_uri, "/engine-api/errors/unknown-payload");
        assert_eq!(problem.detail.as_deref(), Some("no such id"));

        let canned = r#"{"type":"/engine-api/errors/ssz-decode-error"}"#;
        let problem: JsonProblem = serde_json::from_str(canned).unwrap();
        assert_eq!(problem.detail, None);
    }

    struct ExpectedRest {
        method: &'static str,
        path: String,
        fork_header: Option<String>,
        body: Bytes,
    }

    struct RestTester {
        server: MockServer<MainnetEthSpec>,
        client: Arc<HttpRestSsz>,
    }

    impl RestTester {
        fn new(with_auth: bool) -> Self {
            let config = MockExecutionConfig {
                server_config: Config::default(),
                jwt_key: JwtKey::from_slice(&DEFAULT_JWT_SECRET).unwrap(),
                shanghai_time: None,
                cancun_time: None,
                prague_time: None,
                osaka_time: None,
                amsterdam_time: None,
                serve_rest_ssz: true,
            };
            let server = MockServer::new_with_config(&runtime::Handle::current(), config, None);
            let url = SensitiveUrl::parse(&server.url()).unwrap();
            let client = if with_auth {
                let auth = Auth::new(JwtKey::from_slice(&DEFAULT_JWT_SECRET).unwrap(), None, None);
                Arc::new(HttpRestSsz::new_with_auth(url, auth, None).unwrap())
            } else {
                Arc::new(HttpRestSsz::new(url, None).unwrap())
            };
            Self { server, client }
        }

        /// Asserts the request the client put on the wire: fork header + path/query + exact SSZ bytes.
        async fn assert_ssz_request_equals<R, F>(
            self,
            request_func: R,
            expected: ExpectedRest,
        ) -> Self
        where
            R: Fn(Arc<HttpRestSsz>) -> F,
            F: Future<Output = ()>,
        {
            request_func(self.client.clone()).await;
            let capture = self.server.last_rest_request();
            assert_eq!(capture.method, expected.method);
            assert_eq!(capture.path, expected.path);
            assert_eq!(capture.eth_execution_version, expected.fork_header);
            assert_eq!(capture.body, expected.body);
            assert!(capture.client_version.is_some());
            self
        }

        async fn assert_auth_failure<R, F, T>(self, request_func: R) -> Self
        where
            R: Fn(Arc<HttpRestSsz>) -> F,
            F: Future<Output = Result<T, Error>>,
            T: std::fmt::Debug,
        {
            let result = request_func(self.client.clone()).await;
            assert!(
                matches!(result, Err(Error::Auth(_))),
                "expected an auth failure, got {result:?}"
            );
            self
        }

        /// Asserts the typed value the client decoded from the mock's SSZ response.
        async fn assert_ssz_response<R, F, T>(self, request_func: R, check: impl FnOnce(T)) -> Self
        where
            R: Fn(Arc<HttpRestSsz>) -> F,
            F: Future<Output = Result<T, Error>>,
        {
            let value = request_func(self.client.clone())
                .await
                .expect("rest request should succeed");
            check(value);
            self
        }
    }

    #[tokio::test]
    async fn identity_request_conformance() {
        RestTester::new(true)
            .assert_ssz_request_equals(
                |client| async move {
                    let _ = client.get_client_version_v1().await;
                },
                ExpectedRest {
                    method: "GET",
                    path: "/engine/v1/identity".to_string(),
                    fork_header: None,
                    body: Bytes::new(),
                },
            )
            .await;
    }

    #[tokio::test]
    async fn rest_request_without_auth_fails() {
        RestTester::new(false)
            .assert_auth_failure(|client| async move { client.get_client_version_v1().await })
            .await;
    }

    #[tokio::test]
    async fn get_payload_request_conformance() {
        let payload_id: PayloadId = [1, 2, 3, 4, 5, 6, 7, 8];
        RestTester::new(true)
            .assert_ssz_request_equals(
                move |client| async move {
                    let _ = client
                        .get_payload::<MainnetEthSpec>(ForkName::Deneb, payload_id)
                        .await;
                },
                ExpectedRest {
                    method: "GET",
                    path: "/engine/v1/payloads/0x0102030405060708".to_string(),
                    fork_header: Some("cancun".to_string()),
                    body: Bytes::new(),
                },
            )
            .await;
    }

    #[tokio::test]
    async fn get_blobs_v2_request_conformance() {
        let versioned_hashes = vec![Hash256::repeat_byte(1), Hash256::repeat_byte(2)];
        let expected_body = Bytes::from(
            SszBlobsRequest::<MainnetEthSpec>::new_blobs_request_v1(versioned_hashes.clone())
                .unwrap()
                .as_ssz_bytes(),
        );
        RestTester::new(true)
            .assert_ssz_request_equals(
                move |client| {
                    let versioned_hashes = versioned_hashes.clone();
                    async move {
                        let _ = client
                            .get_blobs_v2::<MainnetEthSpec>(versioned_hashes)
                            .await;
                    }
                },
                ExpectedRest {
                    method: "POST",
                    path: "/engine/v1/blobs/v2".to_string(),
                    fork_header: None,
                    body: expected_body,
                },
            )
            .await;
    }

    #[tokio::test]
    async fn get_blobs_v3_request_conformance() {
        let versioned_hashes = vec![Hash256::repeat_byte(1), Hash256::repeat_byte(2)];
        let expected_body = Bytes::from(
            SszBlobsRequest::<MainnetEthSpec>::new_blobs_request_v1(versioned_hashes.clone())
                .unwrap()
                .as_ssz_bytes(),
        );
        RestTester::new(true)
            .assert_ssz_request_equals(
                move |client| {
                    let versioned_hashes = versioned_hashes.clone();
                    async move {
                        let _ = client
                            .get_blobs_v3::<MainnetEthSpec>(versioned_hashes)
                            .await;
                    }
                },
                ExpectedRest {
                    method: "POST",
                    path: "/engine/v1/blobs/v3".to_string(),
                    fork_header: None,
                    body: expected_body,
                },
            )
            .await;
    }

    #[tokio::test]
    async fn get_payload_bodies_by_range_request_conformance() {
        RestTester::new(true)
            .assert_ssz_request_equals(
                |client| async move {
                    let _ = client
                        .get_payload_bodies_by_range::<MainnetEthSpec>(ForkName::Electra, 10, 5)
                        .await;
                },
                ExpectedRest {
                    method: "GET",
                    path: "/engine/v1/bodies?from=10&count=5".to_string(),
                    fork_header: Some("prague".to_string()),
                    body: Bytes::new(),
                },
            )
            .await;
    }

    #[tokio::test]
    async fn get_payload_bodies_by_hash_request_conformance() {
        let block_hashes = vec![
            ExecutionBlockHash::repeat_byte(3),
            ExecutionBlockHash::repeat_byte(4),
        ];
        let roots = block_hashes
            .clone()
            .into_iter()
            .map(|hash| hash.into_root())
            .collect::<Vec<_>>();
        let expected_body = Bytes::from(SszBodiesByHashRequest::new(roots).unwrap().as_ssz_bytes());
        RestTester::new(true)
            .assert_ssz_request_equals(
                move |client| {
                    let block_hashes = block_hashes.clone();
                    async move {
                        let _ = client
                            .get_payload_bodies_by_hash::<MainnetEthSpec>(
                                ForkName::Fulu,
                                block_hashes,
                            )
                            .await;
                    }
                },
                ExpectedRest {
                    method: "POST",
                    path: "/engine/v1/bodies/hash".to_string(),
                    fork_header: Some("osaka".to_string()),
                    body: expected_body,
                },
            )
            .await;
    }

    fn forkchoice_state() -> ForkchoiceState {
        ForkchoiceState {
            head_block_hash: ExecutionBlockHash::repeat_byte(1),
            safe_block_hash: ExecutionBlockHash::repeat_byte(2),
            finalized_block_hash: ExecutionBlockHash::repeat_byte(3),
        }
    }

    #[tokio::test]
    async fn forkchoice_updated_no_attrs_request_conformance() {
        let state = forkchoice_state();
        let expected_body = Bytes::from(
            SszForkchoiceUpdate::new(ForkName::Deneb, state, None)
                .unwrap()
                .as_ssz_bytes(),
        );
        RestTester::new(true)
            .assert_ssz_request_equals(
                move |client| async move {
                    let _ = client
                        .forkchoice_updated::<MainnetEthSpec>(ForkName::Deneb, state, None)
                        .await;
                },
                ExpectedRest {
                    method: "POST",
                    path: "/engine/v1/forkchoice".to_string(),
                    fork_header: Some("cancun".to_string()),
                    body: expected_body,
                },
            )
            .await;
    }

    #[tokio::test]
    async fn forkchoice_updated_with_attrs_request_conformance() {
        let state = forkchoice_state();
        let attributes = PayloadAttributes::new(
            1_000,
            Hash256::repeat_byte(4),
            Address::repeat_byte(9),
            Some(vec![]),
            Some(Hash256::repeat_byte(5)),
            None,
            None,
        );
        let expected_body = Bytes::from(
            SszForkchoiceUpdate::new(ForkName::Deneb, state, Some(attributes.clone()))
                .unwrap()
                .as_ssz_bytes(),
        );
        RestTester::new(true)
            .assert_ssz_request_equals(
                move |client| {
                    let attributes = attributes.clone();
                    async move {
                        let _ = client
                            .forkchoice_updated::<MainnetEthSpec>(
                                ForkName::Deneb,
                                state,
                                Some(attributes),
                            )
                            .await;
                    }
                },
                ExpectedRest {
                    method: "POST",
                    path: "/engine/v1/forkchoice".to_string(),
                    fork_header: Some("cancun".to_string()),
                    body: expected_body,
                },
            )
            .await;
    }

    #[tokio::test]
    async fn forkchoice_updated_amsterdam_request_conformance() {
        let state = forkchoice_state();
        let expected_body = Bytes::from(
            SszForkchoiceUpdateAmsterdam::<MainnetEthSpec>::new(state, None, None)
                .unwrap()
                .as_ssz_bytes(),
        );
        RestTester::new(true)
            .assert_ssz_request_equals(
                move |client| async move {
                    let _ = client
                        .forkchoice_updated::<MainnetEthSpec>(ForkName::Gloas, state, None)
                        .await;
                },
                ExpectedRest {
                    method: "POST",
                    path: "/engine/v1/forkchoice".to_string(),
                    fork_header: Some("amsterdam".to_string()),
                    body: expected_body,
                },
            )
            .await;
    }

    #[tokio::test]
    async fn new_payload_deneb_request_conformance() {
        let payload = ExecutionPayloadDeneb::<MainnetEthSpec>::default();
        let versioned_hashes = vec![Hash256::repeat_byte(7)];
        let parent_beacon_block_root = Hash256::repeat_byte(8);
        // The envelope drops `versioned_hashes`; the byte-compare confirms they are not sent.
        let expected_body = Bytes::from(
            SszExecutionPayloadEnvelopeDeneb::from(NewPayloadRequestDeneb {
                execution_payload: &payload,
                versioned_hashes: versioned_hashes.clone(),
                parent_beacon_block_root,
            })
            .as_ssz_bytes(),
        );
        RestTester::new(true)
            .assert_ssz_request_equals(
                move |client| {
                    let payload = payload.clone();
                    let versioned_hashes = versioned_hashes.clone();
                    async move {
                        let request = NewPayloadRequest::Deneb(NewPayloadRequestDeneb {
                            execution_payload: &payload,
                            versioned_hashes,
                            parent_beacon_block_root,
                        });
                        let _ = client.new_payload::<MainnetEthSpec>(request).await;
                    }
                },
                ExpectedRest {
                    method: "POST",
                    path: "/engine/v1/payloads".to_string(),
                    fork_header: Some("cancun".to_string()),
                    body: expected_body,
                },
            )
            .await;
    }

    #[tokio::test]
    async fn new_payload_gloas_request_conformance() {
        let payload = ExecutionPayloadGloas::<MainnetEthSpec>::default();
        let versioned_hashes = vec![Hash256::repeat_byte(7)];
        let parent_beacon_block_root = Hash256::repeat_byte(8);
        let execution_requests = ExecutionRequestsGloas::<MainnetEthSpec>::default();
        let expected_body = Bytes::from(
            SszExecutionPayloadEnvelopeGloas::try_from(NewPayloadRequestGloas {
                execution_payload: &payload,
                versioned_hashes: versioned_hashes.clone(),
                parent_beacon_block_root,
                execution_requests: &execution_requests,
            })
            .unwrap()
            .as_ssz_bytes(),
        );
        RestTester::new(true)
            .assert_ssz_request_equals(
                move |client| {
                    let payload = payload.clone();
                    let versioned_hashes = versioned_hashes.clone();
                    let execution_requests = execution_requests.clone();
                    async move {
                        let request = NewPayloadRequest::Gloas(NewPayloadRequestGloas {
                            execution_payload: &payload,
                            versioned_hashes,
                            parent_beacon_block_root,
                            execution_requests: &execution_requests,
                        });
                        let _ = client.new_payload::<MainnetEthSpec>(request).await;
                    }
                },
                ExpectedRest {
                    method: "POST",
                    path: "/engine/v1/payloads".to_string(),
                    fork_header: Some("amsterdam".to_string()),
                    body: expected_body,
                },
            )
            .await;
    }

    #[tokio::test]
    async fn new_payload_valid_round_trip() {
        let payload = ExecutionPayloadFulu::<MainnetEthSpec>::default();
        let execution_requests = ExecutionRequestsElectra::<MainnetEthSpec>::default();
        let tester = RestTester::new(true);
        tester.server.all_payloads_valid_on_new_payload();
        tester
            .assert_ssz_response(
                move |client| {
                    let payload = payload.clone();
                    let execution_requests = execution_requests.clone();
                    async move {
                        let request = NewPayloadRequest::Fulu(NewPayloadRequestFulu {
                            execution_payload: &payload,
                            versioned_hashes: vec![],
                            parent_beacon_block_root: Hash256::repeat_byte(0),
                            execution_requests: &execution_requests,
                        });
                        client.new_payload::<MainnetEthSpec>(request).await
                    }
                },
                |status| assert_eq!(status.status, PayloadStatusV1Status::Valid),
            )
            .await;
    }

    #[tokio::test]
    async fn new_payload_syncing_round_trip() {
        let payload = ExecutionPayloadFulu::<MainnetEthSpec>::default();
        let execution_requests = ExecutionRequestsElectra::<MainnetEthSpec>::default();
        let tester = RestTester::new(true);
        tester.server.all_payloads_syncing_on_new_payload(false);
        tester
            .assert_ssz_response(
                move |client| {
                    let payload = payload.clone();
                    let execution_requests = execution_requests.clone();
                    async move {
                        let request = NewPayloadRequest::Fulu(NewPayloadRequestFulu {
                            execution_payload: &payload,
                            versioned_hashes: vec![],
                            parent_beacon_block_root: Hash256::repeat_byte(0),
                            execution_requests: &execution_requests,
                        });
                        client.new_payload::<MainnetEthSpec>(request).await
                    }
                },
                |status| assert_eq!(status.status, PayloadStatusV1Status::Syncing),
            )
            .await;
    }

    #[tokio::test]
    async fn new_payload_invalid_block_hash_folds_to_invalid_round_trip() {
        let payload = ExecutionPayloadFulu::<MainnetEthSpec>::default();
        let execution_requests = ExecutionRequestsElectra::<MainnetEthSpec>::default();
        let tester = RestTester::new(true);
        tester
            .server
            .all_payloads_invalid_block_hash_on_new_payload();
        tester
            .assert_ssz_response(
                move |client| {
                    let payload = payload.clone();
                    let execution_requests = execution_requests.clone();
                    async move {
                        let request = NewPayloadRequest::Fulu(NewPayloadRequestFulu {
                            execution_payload: &payload,
                            versioned_hashes: vec![],
                            parent_beacon_block_root: Hash256::repeat_byte(0),
                            execution_requests: &execution_requests,
                        });
                        client.new_payload::<MainnetEthSpec>(request).await
                    }
                },
                |status| assert_eq!(status.status, PayloadStatusV1Status::Invalid),
            )
            .await;
    }

    #[tokio::test]
    async fn forkchoice_updated_no_attrs_round_trip() {
        let state = forkchoice_state();
        let tester = RestTester::new(true);
        tester.server.set_fcu_payload_status(
            state.head_block_hash,
            PayloadStatusV1 {
                status: PayloadStatusV1Status::Valid,
                latest_valid_hash: None,
                validation_error: None,
            },
        );
        tester
            .assert_ssz_response(
                move |client| async move {
                    client
                        .forkchoice_updated::<MainnetEthSpec>(ForkName::Fulu, state, None)
                        .await
                },
                |response| {
                    assert_eq!(response.payload_status.status, PayloadStatusV1Status::Valid);
                    assert!(response.payload_id.is_none());
                },
            )
            .await;
    }

    #[tokio::test]
    async fn forkchoice_updated_with_attrs_round_trip() {
        let state = forkchoice_state();
        let attributes = PayloadAttributes::new(
            1_000,
            Hash256::repeat_byte(4),
            Address::repeat_byte(9),
            Some(vec![]),
            Some(Hash256::repeat_byte(5)),
            None,
            None,
        );
        let tester = RestTester::new(true);
        tester.server.set_fcu_payload_status(
            state.head_block_hash,
            PayloadStatusV1 {
                status: PayloadStatusV1Status::Valid,
                latest_valid_hash: None,
                validation_error: None,
            },
        );
        tester
            .assert_ssz_response(
                move |client| {
                    let attributes = attributes.clone();
                    async move {
                        client
                            .forkchoice_updated::<MainnetEthSpec>(
                                ForkName::Fulu,
                                state,
                                Some(attributes),
                            )
                            .await
                    }
                },
                |response| {
                    assert_eq!(response.payload_status.status, PayloadStatusV1Status::Valid);
                },
            )
            .await;
    }

    #[tokio::test]
    async fn get_payload_unknown_id_returns_404() {
        let tester = RestTester::new(true);
        let payload_id: PayloadId = [9; 8];
        let result = tester
            .client
            .get_payload::<MainnetEthSpec>(ForkName::Fulu, payload_id)
            .await;
        assert!(
            matches!(&result, Err(e) if e.is_unknown_payload()),
            "expected unknown-payload error, got {result:?}"
        );
    }

    #[tokio::test]
    async fn get_blobs_v2_miss_returns_none() {
        RestTester::new(true)
            .assert_ssz_response(
                |client| async move {
                    client
                        .get_blobs_v2::<MainnetEthSpec>(vec![Hash256::repeat_byte(1)])
                        .await
                },
                |blobs| assert!(blobs.is_none()),
            )
            .await;
    }
}
