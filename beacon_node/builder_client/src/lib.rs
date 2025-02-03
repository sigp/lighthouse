use eth2::types::builder_bid::SignedBuilderBid;
use eth2::types::fork_versioned_response::EmptyMetadata;
use eth2::types::{
    ContentType, EthSpec, ExecutionBlockHash, ForkName, ForkVersionDecode, ForkVersionDeserialize,
    ForkVersionedResponse, PublicKeyBytes, SignedValidatorRegistrationData, Slot,
};
use eth2::types::{FullPayloadContents, SignedBlindedBeaconBlock};
pub use eth2::Error;
use eth2::{
    ok_or_error, StatusCode, CONSENSUS_VERSION_HEADER, CONTENT_TYPE_HEADER,
    JSON_CONTENT_TYPE_HEADER, SSZ_CONTENT_TYPE_HEADER,
};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT};
use reqwest::{IntoUrl, Response};
use sensitive_url::SensitiveUrl;
use serde::de::DeserializeOwned;
use serde::Serialize;
use ssz::Encode;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const DEFAULT_TIMEOUT_MILLIS: u64 = 15000;

/// This timeout is in accordance with v0.2.0 of the [builder specs](https://github.com/flashbots/mev-boost/pull/20).
pub const DEFAULT_GET_HEADER_TIMEOUT_MILLIS: u64 = 1000;

/// Default user agent for HTTP requests.
pub const DEFAULT_USER_AGENT: &str = lighthouse_version::VERSION;

#[derive(Clone)]
pub struct Timeouts {
    get_header: Duration,
    post_validators: Duration,
    post_blinded_blocks: Duration,
    get_builder_status: Duration,
}

impl Timeouts {
    fn new(get_header_timeout: Option<Duration>) -> Self {
        let get_header =
            get_header_timeout.unwrap_or(Duration::from_millis(DEFAULT_GET_HEADER_TIMEOUT_MILLIS));

        Self {
            get_header,
            post_validators: Duration::from_millis(DEFAULT_TIMEOUT_MILLIS),
            post_blinded_blocks: Duration::from_millis(DEFAULT_TIMEOUT_MILLIS),
            get_builder_status: Duration::from_millis(DEFAULT_TIMEOUT_MILLIS),
        }
    }
}

#[derive(Clone)]
pub struct BuilderHttpClient {
    client: reqwest::Client,
    server: SensitiveUrl,
    timeouts: Timeouts,
    user_agent: String,
    ssz_enabled: Arc<AtomicBool>,
}

impl BuilderHttpClient {
    pub fn new(
        server: SensitiveUrl,
        user_agent: Option<String>,
        builder_header_timeout: Option<Duration>,
    ) -> Result<Self, Error> {
        let user_agent = user_agent.unwrap_or(DEFAULT_USER_AGENT.to_string());
        let client = reqwest::Client::builder().user_agent(&user_agent).build()?;
        Ok(Self {
            client,
            server,
            timeouts: Timeouts::new(builder_header_timeout),
            user_agent,
            ssz_enabled: Arc::new(false.into()),
        })
    }

    pub fn get_user_agent(&self) -> &str {
        &self.user_agent
    }

    fn fork_name_from_header(&self, headers: &HeaderMap) -> Result<Option<ForkName>, String> {
        headers
            .get(CONSENSUS_VERSION_HEADER)
            .map(|fork_name| {
                fork_name
                    .to_str()
                    .map_err(|e| e.to_string())
                    .and_then(ForkName::from_str)
            })
            .transpose()
    }

    fn content_type_from_header(&self, headers: &HeaderMap) -> ContentType {
        let Some(content_type) = headers.get(CONTENT_TYPE_HEADER).map(|content_type| {
            let content_type = content_type.to_str();
            match content_type {
                Ok(SSZ_CONTENT_TYPE_HEADER) => ContentType::Ssz,
                _ => ContentType::Json,
            }
        }) else {
            return ContentType::Json;
        };
        content_type
    }

    async fn get_with_header<
        T: DeserializeOwned + ForkVersionDecode + ForkVersionDeserialize,
        U: IntoUrl,
    >(
        &self,
        url: U,
        timeout: Duration,
        headers: HeaderMap,
    ) -> Result<ForkVersionedResponse<T>, Error> {
        let response = self
            .get_response_with_header(url, Some(timeout), headers)
            .await?;

        let headers = response.headers().clone();
        let response_bytes = response.bytes().await?;

        let Ok(Some(fork_name)) = self.fork_name_from_header(&headers) else {
            // if no fork version specified, attempt to fallback to JSON
            self.ssz_enabled.store(false, Ordering::SeqCst);
            return serde_json::from_slice(&response_bytes).map_err(Error::InvalidJson);
        };

        let content_type = self.content_type_from_header(&headers);

        match content_type {
            ContentType::Ssz => {
                self.ssz_enabled.store(true, Ordering::SeqCst);
                T::from_ssz_bytes_by_fork(&response_bytes, fork_name)
                    .map(|data| ForkVersionedResponse {
                        version: Some(fork_name),
                        metadata: EmptyMetadata {},
                        data,
                    })
                    .map_err(Error::InvalidSsz)
            }
            ContentType::Json => {
                self.ssz_enabled.store(false, Ordering::SeqCst);
                serde_json::from_slice(&response_bytes).map_err(Error::InvalidJson)
            }
        }
    }

    /// Return `true` if the most recently received response from the builder had SSZ Content-Type.
    pub fn is_ssz_enabled(&self) -> bool {
        self.ssz_enabled.load(Ordering::SeqCst)
    }

    async fn get_with_timeout<T: DeserializeOwned, U: IntoUrl>(
        &self,
        url: U,
        timeout: Duration,
    ) -> Result<T, Error> {
        self.get_response_with_timeout(url, Some(timeout))
            .await?
            .json()
            .await
            .map_err(Into::into)
    }

    /// Perform a HTTP GET request, returning the `Response` for further processing.
    async fn get_response_with_header<U: IntoUrl>(
        &self,
        url: U,
        timeout: Option<Duration>,
        headers: HeaderMap,
    ) -> Result<Response, Error> {
        let mut builder = self.client.get(url);
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        let response = builder.headers(headers).send().await.map_err(Error::from)?;
        ok_or_error(response).await
    }

    /// Perform a HTTP GET request, returning the `Response` for further processing.
    async fn get_response_with_timeout<U: IntoUrl>(
        &self,
        url: U,
        timeout: Option<Duration>,
    ) -> Result<Response, Error> {
        let mut builder = self.client.get(url);
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        let response = builder.send().await.map_err(Error::from)?;
        ok_or_error(response).await
    }

    /// Generic POST function supporting arbitrary responses and timeouts.
    async fn post_generic<T: Serialize, U: IntoUrl>(
        &self,
        url: U,
        body: &T,
        timeout: Option<Duration>,
    ) -> Result<Response, Error> {
        let mut builder = self.client.post(url);
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        let response = builder.json(body).send().await?;
        ok_or_error(response).await
    }

    async fn post_ssz_with_raw_response<U: IntoUrl>(
        &self,
        url: U,
        ssz_body: Vec<u8>,
        mut headers: HeaderMap,
        timeout: Option<Duration>,
    ) -> Result<Response, Error> {
        let mut builder = self.client.post(url);
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }

        headers.insert(
            CONTENT_TYPE_HEADER,
            HeaderValue::from_static(SSZ_CONTENT_TYPE_HEADER),
        );

        let response = builder
            .headers(headers)
            .body(ssz_body)
            .send()
            .await
            .map_err(Error::from)?;
        ok_or_error(response).await
    }

    async fn post_with_raw_response<T: Serialize, U: IntoUrl>(
        &self,
        url: U,
        body: &T,
        headers: HeaderMap,
        timeout: Option<Duration>,
    ) -> Result<Response, Error> {
        let mut builder = self.client.post(url);
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }

        let response = builder
            .headers(headers)
            .json(body)
            .send()
            .await
            .map_err(Error::from)?;
        ok_or_error(response).await
    }

    /// `POST /eth/v1/builder/validators`
    pub async fn post_builder_validators(
        &self,
        validator: &[SignedValidatorRegistrationData],
    ) -> Result<(), Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("builder")
            .push("validators");

        self.post_generic(path, &validator, Some(self.timeouts.post_validators))
            .await?;
        Ok(())
    }

    /// `POST /eth/v1/builder/blinded_blocks` with SSZ serialized request body
    pub async fn post_builder_blinded_blocks_ssz<E: EthSpec>(
        &self,
        blinded_block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<FullPayloadContents<E>, Error> {
        let mut path = self.server.full.clone();

        let body = blinded_block.as_ssz_bytes();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("builder")
            .push("blinded_blocks");

        let mut headers = HeaderMap::new();
        if let Ok(value) = HeaderValue::from_str(&blinded_block.fork_name_unchecked().to_string()) {
            headers.insert(CONSENSUS_VERSION_HEADER, value);
        }

        let result = self
            .post_ssz_with_raw_response(
                path,
                body,
                headers,
                Some(self.timeouts.post_blinded_blocks),
            )
            .await?
            .bytes()
            .await?;

        FullPayloadContents::from_ssz_bytes_by_fork(&result, blinded_block.fork_name_unchecked())
            .map_err(Error::InvalidSsz)
    }

    /// `POST /eth/v1/builder/blinded_blocks`
    pub async fn post_builder_blinded_blocks<E: EthSpec>(
        &self,
        blinded_block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<ForkVersionedResponse<FullPayloadContents<E>>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("builder")
            .push("blinded_blocks");

        let mut headers = HeaderMap::new();
        if let Ok(value) = HeaderValue::from_str(&blinded_block.fork_name_unchecked().to_string()) {
            headers.insert(CONSENSUS_VERSION_HEADER, value);
        }

        Ok(self
            .post_with_raw_response(
                path,
                &blinded_block,
                headers,
                Some(self.timeouts.post_blinded_blocks),
            )
            .await?
            .json()
            .await?)
    }

    /// `GET /eth/v1/builder/header`
    pub async fn get_builder_header<E: EthSpec>(
        &self,
        slot: Slot,
        parent_hash: ExecutionBlockHash,
        pubkey: &PublicKeyBytes,
    ) -> Result<Option<ForkVersionedResponse<SignedBuilderBid<E>>>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("builder")
            .push("header")
            .push(slot.to_string().as_str())
            .push(format!("{parent_hash:?}").as_str())
            .push(pubkey.as_hex_string().as_str());

        let mut headers = HeaderMap::new();
        if let Ok(ssz_content_type_header) = HeaderValue::from_str(&format!(
            "{}; q=1.0,{}; q=0.9",
            SSZ_CONTENT_TYPE_HEADER, JSON_CONTENT_TYPE_HEADER
        )) {
            headers.insert(ACCEPT, ssz_content_type_header);
        };

        let resp = self
            .get_with_header(path, self.timeouts.get_header, headers)
            .await;

        if matches!(resp, Err(Error::StatusCode(StatusCode::NO_CONTENT))) {
            Ok(None)
        } else {
            resp.map(Some)
        }
    }

    /// `GET /eth/v1/builder/status`
    pub async fn get_builder_status<E: EthSpec>(&self) -> Result<(), Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("builder")
            .push("status");

        self.get_with_timeout(path, self.timeouts.get_builder_status)
            .await
    }
}
