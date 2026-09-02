use crate::{
    DEFAULT_USER_AGENT, Error, JSON_ACCEPT_VALUE, PREFERENCE_ACCEPT_VALUE,
    content_type_from_header, ok_or_error, success_or_error,
};
use bls::PublicKeyBytes;
use eth2::types::{
    BuilderPreferencesRequest, ContentType, EthSpec, ExecutionBlockHash, ForkName,
    ForkVersionedResponse, Hash256, SignedBeaconBlock, SignedExecutionPayloadBid,
    SignedRequestAuth, Slot,
};
use eth2::{
    CONSENSUS_VERSION_HEADER, CONTENT_TYPE_HEADER, JSON_CONTENT_TYPE_HEADER,
    SSZ_CONTENT_TYPE_HEADER,
};
use reqwest::StatusCode;
use reqwest::header::{ACCEPT, HeaderMap, HeaderName, HeaderValue};
use sensitive_url::SensitiveUrl;
use ssz::{Decode, Encode};
use std::time::Duration;
use tracing::warn;

/// This is a whole rabbithole.. see discussion:
/// https://discord.com/channels/595666850260713488/874767108809031740/1529125867484348577
pub const DEFAULT_GET_EXECUTION_PAYLOAD_BID_TIMEOUT_MILLIS: u64 = 400;

/// Default timeout for builder submit requests (preferences and signed block).
pub const DEFAULT_SUBMIT_TIMEOUT_MILLIS: u64 = 1000;

/// Header advertising the proposer's request timeout (in milliseconds) to the builder.
const X_TIMEOUT_MS: HeaderName = HeaderName::from_static("x-timeout-ms");
/// Header carrying the Unix send-time (in milliseconds) so the builder can measure latency.
const DATE_MILLISECONDS: HeaderName = HeaderName::from_static("date-milliseconds");

/// A client for the Gloas (ePBS) Builder API.
///
/// This client is **not** bound to a single builder URL and holds **no** per-connection state:
/// every request takes the target `builder_url` as a parameter, so one instance can fan out to any
/// number of builders. SSZ negotiation is done per-request rather than cached, because in Gloas the
/// bid request and the signed-block submission are separated by a full VC round-trip
/// (produce -> sign -> publish) and so cannot share instance state.
#[derive(Clone)]
pub struct BuilderHttpClient {
    client: reqwest::Client,
    user_agent: String,
    /// Only use json for all request/response types.
    disable_ssz: bool,
}

impl BuilderHttpClient {
    pub fn new(user_agent: Option<String>, disable_ssz: bool) -> Result<Self, Error> {
        let user_agent = user_agent.unwrap_or_else(|| DEFAULT_USER_AGENT.to_string());
        let client = reqwest::Client::builder().user_agent(&user_agent).build()?;
        Ok(Self {
            client,
            user_agent,
            disable_ssz,
        })
    }

    pub fn get_user_agent(&self) -> &str {
        &self.user_agent
    }

    /// Build the HTTP headers sent with a `getExecutionPayloadBid` request.
    ///
    /// Sets three headers:
    /// - `Accept`: requests SSZ (with JSON fallback) for the response, or JSON only when
    ///   `disable_ssz` is set. This governs the (larger) bid response encoding only.
    /// - `X-Timeout-Ms`: the proposer's request timeout, measured from `Date-Milliseconds`. The
    ///   builder must respond within this window; required by the builder spec.
    /// - `Date-Milliseconds`: the Unix ms send time, letting the builder estimate transit delay;
    ///   required by the builder spec.
    ///
    /// The `Accept` header is best-effort (logged and skipped if it cannot be constructed). The two
    /// required timing headers are built from a static timeout and the system clock, so their
    /// construction cannot realistically fail.
    fn compute_get_execution_payload_bid_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();

        let accept_value = if self.disable_ssz {
            JSON_ACCEPT_VALUE
        } else {
            PREFERENCE_ACCEPT_VALUE
        };

        match HeaderValue::from_str(accept_value) {
            Ok(accept_header) => {
                headers.insert(ACCEPT, accept_header);
            }
            Err(e) => {
                warn!("Invalid accept value: {}", e);
            }
        }

        // Advertise our timeout to the builder so it can bound its own work.
        headers.insert(
            X_TIMEOUT_MS,
            HeaderValue::from(DEFAULT_GET_EXECUTION_PAYLOAD_BID_TIMEOUT_MILLIS),
        );

        // Timestamp the request (Unix ms) so the builder can measure one-way latency.
        match std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
        {
            Ok(now_millis) => {
                headers.insert(DATE_MILLISECONDS, HeaderValue::from(now_millis));
            }
            Err(e) => {
                warn!("Failed to compute date header: {}", e);
            }
        }

        headers
    }

    /// `POST /eth/v1/builder/execution_payload_bid/{slot}/{parent_hash}/{parent_root}/{proposer_pubkey}`
    ///
    /// Request a bid from a single builder. Returns `Ok(None)` if the builder has no bid available
    /// (HTTP 204).
    ///
    /// The `SignedRequestAuth` body is required by the builder spec (a builder returns 400 if it
    /// is missing), and `RequestAuth` is fork-versioned, so the `Eth-Consensus-Version` header is
    /// required too. The body is small and always sent as JSON; SSZ is only negotiated for the
    /// (larger) response via the `Accept` header, and the response is decoded according to its
    /// `Content-Type`.
    #[allow(clippy::too_many_arguments)]
    pub async fn get_execution_payload_bid<E: EthSpec>(
        &self,
        builder_url: &SensitiveUrl,
        slot: Slot,
        parent_hash: ExecutionBlockHash,
        parent_root: Hash256,
        proposer_pubkey: &PublicKeyBytes,
        signed_request_auth: &SignedRequestAuth,
        fork_name: ForkName,
    ) -> Result<Option<SignedExecutionPayloadBid<E>>, Error> {
        let mut path = builder_url.expose_full().clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(builder_url.clone()))?
            .push("eth")
            .push("v1")
            .push("builder")
            .push("execution_payload_bid")
            .push(slot.to_string().as_str())
            .push(format!("{parent_hash:?}").as_str())
            .push(format!("{parent_root:?}").as_str())
            .push(proposer_pubkey.as_hex_string().as_str());

        let timeout = Duration::from_millis(DEFAULT_GET_EXECUTION_PAYLOAD_BID_TIMEOUT_MILLIS);
        let headers = self.compute_get_execution_payload_bid_headers();
        // The auth body is tiny; always send it as JSON. SSZ-encoding it buys nothing and avoids
        // having to probe the builder's SSZ request-ingest support.
        let request = self
            .client
            .post(path)
            .timeout(timeout)
            .headers(headers)
            .header(CONSENSUS_VERSION_HEADER, fork_name.to_string())
            .json(signed_request_auth);

        let response = ok_or_error(request.send().await.map_err(Error::from)?).await?;

        if response.status() == StatusCode::NO_CONTENT {
            return Ok(None);
        }

        let response_headers = response.headers().clone();
        let response_bytes = response.bytes().await?;

        match content_type_from_header(&response_headers) {
            ContentType::Ssz => {
                let bid = SignedExecutionPayloadBid::<E>::from_ssz_bytes(&response_bytes)
                    .map_err(Error::InvalidSsz)?;
                Ok(Some(bid))
            }
            ContentType::Json => {
                let versioned: ForkVersionedResponse<SignedExecutionPayloadBid<E>> =
                    serde_json::from_slice(&response_bytes).map_err(Error::InvalidJson)?;
                Ok(Some(versioned.data))
            }
        }
    }

    /// `POST /eth/v1/builder/builder_preferences/{validator_pubkey}`
    ///
    /// Submit a validator's builder preferences to a builder ahead of the bid request (typically in
    /// the epoch before the proposal, so the builder has them before `getExecutionPayloadBid`
    /// arrives). Success is HTTP 202.
    ///
    /// `BuilderPreferencesRequest` is fork-versioned, so `fork_name` is sent as the required
    /// `Eth-Consensus-Version` header (builder-specs #165); the body is small and sent as JSON.
    pub async fn submit_builder_preferences(
        &self,
        builder_url: &SensitiveUrl,
        proposer_pubkey: &PublicKeyBytes,
        preferences: &BuilderPreferencesRequest,
        fork_name: ForkName,
    ) -> Result<(), Error> {
        let mut path = builder_url.expose_full().clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(builder_url.clone()))?
            .push("eth")
            .push("v1")
            .push("builder")
            .push("builder_preferences")
            .push(proposer_pubkey.as_hex_string().as_str());

        let timeout = Duration::from_millis(DEFAULT_SUBMIT_TIMEOUT_MILLIS);
        let request = self
            .client
            .post(path)
            .timeout(timeout)
            .header(CONSENSUS_VERSION_HEADER, fork_name.to_string())
            .json(preferences);

        let response = success_or_error(request.send().await.map_err(Error::from)?).await?;

        if response.status() == StatusCode::ACCEPTED {
            Ok(())
        } else {
            // ACCEPTED is the only valid status code response
            Err(Error::StatusCode(response.status()))
        }
    }

    /// `POST /eth/v1/builder/beacon_blocks`
    ///
    /// Submit the signed Gloas beacon block to the builder that won selection. On success (HTTP
    /// 202) the builder becomes responsible for publishing the execution payload envelope.
    ///
    /// `ssz_request` selects the request-body encoding: SSZ when `true` and the client has SSZ
    /// enabled, otherwise JSON.
    pub async fn submit_signed_beacon_block<E: EthSpec>(
        &self,
        builder_url: &SensitiveUrl,
        block: &SignedBeaconBlock<E>,
        ssz_request: bool,
    ) -> Result<(), Error> {
        let mut path = builder_url.expose_full().clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(builder_url.clone()))?
            .push("eth")
            .push("v1")
            .push("builder")
            .push("beacon_blocks");

        let mut headers = HeaderMap::new();
        headers.insert(
            CONSENSUS_VERSION_HEADER,
            HeaderValue::from_str(&block.fork_name_unchecked().to_string())
                .map_err(|e| Error::InvalidHeaders(format!("{}", e)))?,
        );

        let timeout = Duration::from_millis(DEFAULT_SUBMIT_TIMEOUT_MILLIS);
        let request = if ssz_request && !self.disable_ssz {
            headers.insert(
                CONTENT_TYPE_HEADER,
                HeaderValue::from_str(SSZ_CONTENT_TYPE_HEADER)
                    .map_err(|e| Error::InvalidHeaders(format!("{}", e)))?,
            );
            self.client
                .post(path)
                .timeout(timeout)
                .headers(headers)
                .body(block.as_ssz_bytes())
        } else {
            headers.insert(
                CONTENT_TYPE_HEADER,
                HeaderValue::from_str(JSON_CONTENT_TYPE_HEADER)
                    .map_err(|e| Error::InvalidHeaders(format!("{}", e)))?,
            );
            self.client
                .post(path)
                .timeout(timeout)
                .headers(headers)
                .json(block)
        };

        let response = success_or_error(request.send().await.map_err(Error::from)?).await?;

        if response.status() == StatusCode::ACCEPTED {
            Ok(())
        } else {
            // ACCEPTED is the only valid status code response
            Err(Error::StatusCode(response.status()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary::Arbitrary;
    use eth2::types::beacon_response::EmptyMetadata;
    use eth2::types::{ForkName, MainnetEthSpec};
    use mockito::{Matcher, Server, ServerGuard};
    use std::str::FromStr;

    type E = MainnetEthSpec;

    fn client_for() -> BuilderHttpClient {
        BuilderHttpClient::new(None, false).unwrap()
    }

    fn builder_url(server: &ServerGuard) -> SensitiveUrl {
        SensitiveUrl::from_str(&server.url()).unwrap()
    }

    fn signed_request_auth() -> SignedRequestAuth {
        let mut u = types::test_utils::test_unstructured();
        SignedRequestAuth::arbitrary(&mut u).unwrap()
    }

    fn empty_bid_response() -> ForkVersionedResponse<SignedExecutionPayloadBid<E>> {
        ForkVersionedResponse {
            version: ForkName::Gloas,
            metadata: EmptyMetadata {},
            data: SignedExecutionPayloadBid::empty(),
        }
    }

    fn mock_bid(server: &mut ServerGuard, content_type: ContentType) {
        let body = empty_bid_response();
        let mut mock = server.mock(
            "POST",
            Matcher::Regex(r"^/eth/v1/builder/execution_payload_bid/.+$".to_string()),
        );
        mock = match content_type {
            ContentType::Json => mock
                .with_header(CONTENT_TYPE_HEADER, JSON_CONTENT_TYPE_HEADER)
                .with_header(CONSENSUS_VERSION_HEADER, "gloas")
                .with_body(serde_json::to_string(&body).unwrap()),
            ContentType::Ssz => mock
                .with_header(CONTENT_TYPE_HEADER, SSZ_CONTENT_TYPE_HEADER)
                .with_header(CONSENSUS_VERSION_HEADER, "gloas")
                .with_body(body.data.as_ssz_bytes()),
        };
        mock.with_status(200).create();
    }

    async fn request_bid(server: &ServerGuard) -> Option<SignedExecutionPayloadBid<E>> {
        client_for()
            .get_execution_payload_bid::<E>(
                &builder_url(server),
                Slot::new(1),
                ExecutionBlockHash::repeat_byte(1),
                Hash256::repeat_byte(2),
                &PublicKeyBytes::empty(),
                &signed_request_auth(),
                ForkName::Gloas,
            )
            .await
            .expect("bid request should succeed")
    }

    #[tokio::test]
    async fn get_execution_payload_bid_json() {
        let mut server = Server::new_async().await;
        mock_bid(&mut server, ContentType::Json);
        let bid = request_bid(&server).await.expect("should have a bid");
        assert_eq!(bid, SignedExecutionPayloadBid::empty());
    }

    #[tokio::test]
    async fn get_execution_payload_bid_ssz() {
        let mut server = Server::new_async().await;
        mock_bid(&mut server, ContentType::Ssz);
        let bid = request_bid(&server).await.expect("should have a bid");
        assert_eq!(bid, SignedExecutionPayloadBid::empty());
    }

    #[tokio::test]
    async fn submit_builder_preferences_accepted() {
        use arbitrary::Arbitrary;
        let mut server = Server::new_async().await;
        server
            .mock(
                "POST",
                Matcher::Regex(r"^/eth/v1/builder/builder_preferences/.+$".to_string()),
            )
            .with_status(202)
            .create();

        let mut u = types::test_utils::test_unstructured();
        let preferences = BuilderPreferencesRequest::arbitrary(&mut u).unwrap();

        client_for()
            .submit_builder_preferences(
                &builder_url(&server),
                &PublicKeyBytes::empty(),
                &preferences,
                ForkName::Gloas,
            )
            .await
            .expect("preferences should be accepted");
    }

    /// The bid request must carry the spec-required headers: `Eth-Consensus-Version` (fork of the
    /// auth body), `Date-Milliseconds` + `X-Timeout-Ms` (timing), a JSON `Content-Type` for the
    /// auth body, and an `Accept` preferring SSZ for the response.
    #[tokio::test]
    async fn bid_request_sends_expected_headers() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock(
                "POST",
                Matcher::Regex(r"^/eth/v1/builder/execution_payload_bid/.+$".to_string()),
            )
            .match_header("accept", PREFERENCE_ACCEPT_VALUE)
            .match_header(CONSENSUS_VERSION_HEADER, "gloas")
            .match_header(CONTENT_TYPE_HEADER, JSON_CONTENT_TYPE_HEADER)
            .match_header(
                X_TIMEOUT_MS.as_str(),
                DEFAULT_GET_EXECUTION_PAYLOAD_BID_TIMEOUT_MILLIS
                    .to_string()
                    .as_str(),
            )
            .match_header(
                DATE_MILLISECONDS.as_str(),
                Matcher::Regex(r"^\d+$".to_string()),
            )
            .match_header("user-agent", DEFAULT_USER_AGENT)
            .with_status(204)
            .create();

        assert!(request_bid(&server).await.is_none());
        mock.assert_async().await;
    }

    /// With SSZ responses disabled, the bid request's `Accept` asks for JSON only.
    #[tokio::test]
    async fn bid_request_accepts_json_only_when_ssz_disabled() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock(
                "POST",
                Matcher::Regex(r"^/eth/v1/builder/execution_payload_bid/.+$".to_string()),
            )
            .match_header("accept", JSON_ACCEPT_VALUE)
            .with_status(204)
            .create();

        BuilderHttpClient::new(None, true)
            .unwrap()
            .get_execution_payload_bid::<E>(
                &builder_url(&server),
                Slot::new(1),
                ExecutionBlockHash::repeat_byte(1),
                Hash256::repeat_byte(2),
                &PublicKeyBytes::empty(),
                &signed_request_auth(),
                ForkName::Gloas,
            )
            .await
            .expect("bid request should succeed");
        mock.assert_async().await;
    }

    /// The preferences submission must carry `Eth-Consensus-Version` (the body is fork-versioned)
    /// and a JSON `Content-Type`.
    #[tokio::test]
    async fn submit_builder_preferences_sends_expected_headers() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock(
                "POST",
                Matcher::Regex(r"^/eth/v1/builder/builder_preferences/.+$".to_string()),
            )
            .match_header(CONSENSUS_VERSION_HEADER, "gloas")
            .match_header(CONTENT_TYPE_HEADER, JSON_CONTENT_TYPE_HEADER)
            .with_status(202)
            .create();

        let mut u = types::test_utils::test_unstructured();
        let preferences = BuilderPreferencesRequest::arbitrary(&mut u).unwrap();
        client_for()
            .submit_builder_preferences(
                &builder_url(&server),
                &PublicKeyBytes::empty(),
                &preferences,
                ForkName::Gloas,
            )
            .await
            .expect("preferences should be accepted");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn get_execution_payload_bid_no_content() {
        let mut server = Server::new_async().await;
        server
            .mock(
                "POST",
                Matcher::Regex(r"^/eth/v1/builder/execution_payload_bid/.+$".to_string()),
            )
            .with_status(204)
            .create();
        assert!(request_bid(&server).await.is_none());
    }
}
