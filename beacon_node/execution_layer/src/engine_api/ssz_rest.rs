//! SSZ-REST client for Engine API (EIP-8161).
//!
//! Provides an alternative SSZ-REST transport for Engine API calls alongside
//! the existing JSON-RPC. When configured, the client tries SSZ-REST first
//! and falls back to JSON-RPC on network errors.

use super::*;
use crate::auth::Auth;
use crate::engine_api::ssz_rest_encoding::{self, SszRestCodecError};
use reqwest::header::CONTENT_TYPE;
use std::time::Duration;

pub use reqwest::Client;

/// Timeout for SSZ-REST requests.
const SSZ_REST_TIMEOUT: Duration = Duration::from_secs(8);

/// SSZ-REST specific error type.
#[derive(Debug)]
pub enum SszRestError {
    /// Network-level error (connection refused, timeout, DNS failure).
    /// These are suitable for fallback to JSON-RPC.
    Network(String),
    /// The server returned an error response with a JSON body.
    ServerError { code: i64, message: String },
    /// SSZ decoding/encoding error.
    Codec(SszRestCodecError),
    /// HTTP error that is not a network error (e.g., 401, 500).
    Http { status: u16, body: String },
    /// JWT auth error.
    Auth(auth::Error),
    /// Other errors.
    Other(String),
}

impl std::fmt::Display for SszRestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(msg) => write!(f, "SSZ-REST network error: {}", msg),
            Self::ServerError { code, message } => {
                write!(f, "SSZ-REST server error (code {}): {}", code, message)
            }
            Self::Codec(e) => write!(f, "SSZ-REST codec error: {}", e),
            Self::Http { status, body } => {
                write!(f, "SSZ-REST HTTP error (status {}): {}", status, body)
            }
            Self::Auth(e) => write!(f, "SSZ-REST auth error: {:?}", e),
            Self::Other(msg) => write!(f, "SSZ-REST error: {}", msg),
        }
    }
}

impl SszRestError {
    /// Returns true if this error is a network-level error suitable for
    /// fallback to JSON-RPC. Includes actual network errors and HTTP
    /// errors (e.g. 404) which indicate the SSZ-REST endpoint may not
    /// support the requested path.
    pub fn is_network_error(&self) -> bool {
        matches!(self, Self::Network(_) | Self::Http { .. })
    }
}

impl From<SszRestCodecError> for SszRestError {
    fn from(e: SszRestCodecError) -> Self {
        Self::Codec(e)
    }
}

impl From<auth::Error> for SszRestError {
    fn from(e: auth::Error) -> Self {
        Self::Auth(e)
    }
}

impl From<SszRestError> for Error {
    fn from(e: SszRestError) -> Self {
        match e {
            SszRestError::Network(msg) => Error::RequestFailed(format!("SSZ-REST: {}", msg)),
            SszRestError::ServerError { code, message } => Error::ServerMessage { code, message },
            SszRestError::Codec(c) => Error::BadResponse(c.to_string()),
            SszRestError::Http { status, body } => {
                Error::RequestFailed(format!("HTTP {}: {}", status, body))
            }
            SszRestError::Auth(e) => Error::Auth(e),
            SszRestError::Other(msg) => Error::BadResponse(msg),
        }
    }
}

/// SSZ-REST client for Engine API calls.
pub struct SszRestClient {
    client: Client,
    base_url: String,
    auth: Option<Auth>,
}

impl SszRestClient {
    /// Create a new SSZ-REST client.
    pub fn new(base_url: String, auth: Option<Auth>) -> Result<Self, SszRestError> {
        let client = Client::builder()
            .build()
            .map_err(|e| SszRestError::Other(format!("Failed to build reqwest client: {}", e)))?;

        // Trim trailing slash from base URL
        let base_url = base_url.trim_end_matches('/').to_string();

        Ok(Self {
            client,
            base_url,
            auth,
        })
    }

    /// Perform a POST request with SSZ body and return the response bytes.
    async fn do_request(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>, SszRestError> {
        self.do_http("POST", path, Some(body)).await
    }

    /// Perform a GET request (no body) and return the response bytes.
    async fn do_get_request(&self, path: &str) -> Result<Vec<u8>, SszRestError> {
        self.do_http("GET", path, None).await
    }

    /// Common HTTP request implementation for both POST and GET.
    async fn do_http(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, SszRestError> {
        let url = format!("{}{}", self.base_url, path);

        let mut request = match method {
            "GET" => self.client.get(&url),
            _ => {
                let b = body.unwrap_or_default();
                self.client
                    .post(&url)
                    .header(CONTENT_TYPE, "application/octet-stream")
                    .body(b)
            }
        };

        request = request
            .timeout(SSZ_REST_TIMEOUT)
            .header("Accept", "application/octet-stream");

        // Add JWT auth if configured
        if let Some(auth) = &self.auth {
            let token = auth.generate_token().map_err(SszRestError::Auth)?;
            request = request.bearer_auth(token);
        }

        let response = request.send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() || e.is_request() {
                SszRestError::Network(e.to_string())
            } else {
                SszRestError::Other(e.to_string())
            }
        })?;

        let status = response.status();
        if status.is_success() {
            let bytes = response
                .bytes()
                .await
                .map_err(|e| SszRestError::Network(e.to_string()))?;
            Ok(bytes.to_vec())
        } else {
            // Error responses use text/plain per execution-apis SSZ spec
            let body_bytes = response
                .bytes()
                .await
                .map_err(|e| SszRestError::Network(e.to_string()))?;

            let body_str =
                String::from_utf8(body_bytes.to_vec()).unwrap_or_else(|_| "<binary>".into());
            Err(SszRestError::Http {
                status: status.as_u16(),
                body: body_str,
            })
        }
    }

    /// Send a NewPayloadV3 request via SSZ-REST.
    pub async fn new_payload_v3<E: EthSpec>(
        &self,
        execution_payload: ExecutionPayloadRef<'_, E>,
        versioned_hashes: &[types::VersionedHash],
        parent_beacon_block_root: Hash256,
    ) -> Result<PayloadStatusV1, SszRestError> {
        let body = ssz_rest_encoding::encode_new_payload_v3(
            execution_payload,
            versioned_hashes,
            parent_beacon_block_root,
        );

        let response_bytes = self.do_request("/engine/v3/payloads", body).await?;
        let status = ssz_rest_encoding::decode_payload_status(&response_bytes)?;
        Ok(status)
    }

    /// Send a NewPayloadV4 request via SSZ-REST.
    pub async fn new_payload_v4<E: EthSpec>(
        &self,
        execution_payload: ExecutionPayloadRef<'_, E>,
        versioned_hashes: &[types::VersionedHash],
        parent_beacon_block_root: Hash256,
        execution_requests: &types::ExecutionRequests<E>,
    ) -> Result<PayloadStatusV1, SszRestError> {
        let body = ssz_rest_encoding::encode_new_payload_v4(
            execution_payload,
            versioned_hashes,
            parent_beacon_block_root,
            execution_requests,
        );

        let response_bytes = self.do_request("/engine/v4/payloads", body).await?;
        let status = ssz_rest_encoding::decode_payload_status(&response_bytes)?;
        Ok(status)
    }

    /// Send a ForkchoiceUpdated request via SSZ-REST.
    pub async fn forkchoice_updated(
        &self,
        forkchoice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<ForkchoiceUpdatedResponse, SszRestError> {
        let body = ssz_rest_encoding::encode_forkchoice_updated_request(
            &forkchoice_state,
            &payload_attributes,
        );

        let response_bytes = self
            .do_request("/engine/v3/forkchoice", body)
            .await?;
        let response = ssz_rest_encoding::decode_forkchoice_updated_response(&response_bytes)?;
        Ok(response)
    }

    /// Send a GetPayload request via SSZ-REST.
    pub async fn get_payload<E: EthSpec>(
        &self,
        fork_name: ForkName,
        payload_id: PayloadId,
    ) -> Result<GetPayloadResponse<E>, SszRestError> {
        let version = match fork_name {
            ForkName::Fulu | ForkName::Gloas => 5,
            ForkName::Electra => 4,
            ForkName::Deneb => 3,
            ForkName::Capella => 2,
            _ => 1,
        };
        let payload_id_hex = format!("0x{}", hex::encode(payload_id));
        let path = format!("/engine/v{}/payloads/{}", version, payload_id_hex);
        let response_bytes = self.do_get_request(&path).await?;
        let resp =
            ssz_rest_encoding::decode_get_payload_response::<E>(&response_bytes, fork_name)?;
        Ok(resp)
    }

    /// Send a GetBlobs request via SSZ-REST.
    ///
    /// Note: Blob decoding is complex - fall back to JSON-RPC for now.
    pub async fn get_blobs<E: EthSpec>(
        &self,
        _versioned_hashes: Vec<Hash256>,
    ) -> Result<Vec<Option<super::json_structures::BlobAndProofV1<E>>>, SszRestError> {
        Err(SszRestError::Network(
            "SSZ-REST GetBlobs not yet implemented, falling back to JSON-RPC".to_string(),
        ))
    }

    /// Send an ExchangeCapabilities request via SSZ-REST.
    pub async fn exchange_capabilities(
        &self,
        capabilities: &[&str],
    ) -> Result<Vec<String>, SszRestError> {
        let body = ssz_rest_encoding::encode_exchange_capabilities(capabilities);

        let response_bytes = self
            .do_request("/engine/v1/capabilities", body)
            .await?;
        let caps = ssz_rest_encoding::decode_exchange_capabilities(&response_bytes)?;
        Ok(caps)
    }
}
