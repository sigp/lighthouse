//! This crate provides two major things:
//!
//! 1. The types served by the `http_api` crate.
//! 2. A wrapper around `reqwest` that forms a HTTP client, able of consuming the endpoints served
//!    by the `http_api` crate.
//!
//! Eventually it would be ideal to publish this crate on crates.io, however we have some local
//! dependencies preventing this presently.

#[cfg(feature = "lighthouse")]
pub mod lighthouse;
#[cfg(feature = "lighthouse")]
pub mod lighthouse_vc;
pub mod mixin;
pub mod types;

use self::mixin::{RequestAccept, ResponseOptional};
use self::types::{Error as ResponseError, *};
use futures::Stream;
use futures_util::StreamExt;
use lighthouse_network::PeerId;
use pretty_reqwest_error::PrettyReqwestError;
pub use reqwest;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Body, IntoUrl, RequestBuilder, Response,
};
pub use reqwest::{StatusCode, Url};
pub use sensitive_url::{SensitiveError, SensitiveUrl};
use serde::{de::DeserializeOwned, Serialize};
use ssz::Encode;
use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;
use store::fork_versioned_response::ExecutionOptimisticFinalizedForkVersionedResponse;

pub const V1: EndpointVersion = EndpointVersion(1);
pub const V2: EndpointVersion = EndpointVersion(2);
pub const V3: EndpointVersion = EndpointVersion(3);

pub const CONSENSUS_VERSION_HEADER: &str = "Eth-Consensus-Version";
pub const EXECUTION_PAYLOAD_BLINDED_HEADER: &str = "Eth-Execution-Payload-Blinded";
pub const EXECUTION_PAYLOAD_VALUE_HEADER: &str = "Eth-Execution-Payload-Value";
pub const CONSENSUS_BLOCK_VALUE_HEADER: &str = "Eth-Consensus-Block-Value";

pub const CONTENT_TYPE_HEADER: &str = "Content-Type";
pub const SSZ_CONTENT_TYPE_HEADER: &str = "application/octet-stream";

#[derive(Debug)]
pub enum Error {
    /// The `reqwest` client raised an error.
    HttpClient(PrettyReqwestError),
    /// The server returned an error message where the body was able to be parsed.
    ServerMessage(ErrorMessage),
    /// The server returned an error message with an array of errors.
    ServerIndexedMessage(IndexedErrorMessage),
    /// The server returned an error message where the body was unable to be parsed.
    StatusCode(StatusCode),
    /// The supplied URL is badly formatted. It should look something like `http://127.0.0.1:5052`.
    InvalidUrl(SensitiveUrl),
    /// The supplied validator client secret is invalid.
    InvalidSecret(String),
    /// The server returned a response with an invalid signature. It may be an impostor.
    InvalidSignatureHeader,
    /// The server returned a response without a signature header. It may be an impostor.
    MissingSignatureHeader,
    /// The server returned an invalid JSON response.
    InvalidJson(serde_json::Error),
    /// The server returned an invalid server-sent event.
    InvalidServerSentEvent(String),
    /// The server sent invalid response headers.
    InvalidHeaders(String),
    /// The server returned an invalid SSZ response.
    InvalidSsz(ssz::DecodeError),
    /// An I/O error occurred while loading an API token from disk.
    TokenReadError(PathBuf, std::io::Error),
    /// The client has been configured without a server pubkey, but requires one for this request.
    NoServerPubkey,
    /// The client has been configured without an API token, but requires one for this request.
    NoToken,
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Error::HttpClient(error.into())
    }
}

impl Error {
    /// If the error has a HTTP status code, return it.
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Error::HttpClient(error) => error.inner().status(),
            Error::ServerMessage(msg) => StatusCode::try_from(msg.code).ok(),
            Error::ServerIndexedMessage(msg) => StatusCode::try_from(msg.code).ok(),
            Error::StatusCode(status) => Some(*status),
            Error::InvalidUrl(_) => None,
            Error::InvalidSecret(_) => None,
            Error::InvalidSignatureHeader => None,
            Error::MissingSignatureHeader => None,
            Error::InvalidJson(_) => None,
            Error::InvalidServerSentEvent(_) => None,
            Error::InvalidHeaders(_) => None,
            Error::InvalidSsz(_) => None,
            Error::TokenReadError(..) => None,
            Error::NoServerPubkey | Error::NoToken => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A struct to define a variety of different timeouts for different validator tasks to ensure
/// proper fallback behaviour.
#[derive(Clone)]
pub struct Timeouts {
    pub attestation: Duration,
    pub attester_duties: Duration,
    pub liveness: Duration,
    pub proposal: Duration,
    pub proposer_duties: Duration,
    pub sync_committee_contribution: Duration,
    pub sync_duties: Duration,
    pub get_beacon_blocks_ssz: Duration,
    pub get_debug_beacon_states: Duration,
    pub get_deposit_snapshot: Duration,
    pub get_validator_block: Duration,
}

impl Timeouts {
    pub fn set_all(timeout: Duration) -> Self {
        Timeouts {
            attestation: timeout,
            attester_duties: timeout,
            liveness: timeout,
            proposal: timeout,
            proposer_duties: timeout,
            sync_committee_contribution: timeout,
            sync_duties: timeout,
            get_beacon_blocks_ssz: timeout,
            get_debug_beacon_states: timeout,
            get_deposit_snapshot: timeout,
            get_validator_block: timeout,
        }
    }
}

/// A wrapper around `reqwest::Client` which provides convenience methods for interfacing with a
/// Lighthouse Beacon Node HTTP server (`http_api`).
#[derive(Clone)]
pub struct BeaconNodeHttpClient {
    client: reqwest::Client,
    server: SensitiveUrl,
    timeouts: Timeouts,
}

impl fmt::Display for BeaconNodeHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.server.fmt(f)
    }
}

impl AsRef<str> for BeaconNodeHttpClient {
    fn as_ref(&self) -> &str {
        self.server.as_ref()
    }
}

impl BeaconNodeHttpClient {
    pub fn new(server: SensitiveUrl, timeouts: Timeouts) -> Self {
        Self {
            client: reqwest::Client::new(),
            server,
            timeouts,
        }
    }

    pub fn from_components(
        server: SensitiveUrl,
        client: reqwest::Client,
        timeouts: Timeouts,
    ) -> Self {
        Self {
            client,
            server,
            timeouts,
        }
    }

    /// Return the path with the standard `/eth/vX` prefix applied.
    fn eth_path(&self, version: EndpointVersion) -> Result<Url, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push(&version.to_string());

        Ok(path)
    }

    /// Perform a HTTP GET request.
    async fn get<T: DeserializeOwned, U: IntoUrl>(&self, url: U) -> Result<T, Error> {
        let response = self.get_response(url, |b| b).await?;
        Ok(response.json().await?)
    }

    /// Perform an HTTP GET request, returning the `Response` for processing.
    pub async fn get_response<U: IntoUrl>(
        &self,
        url: U,
        builder: impl FnOnce(RequestBuilder) -> RequestBuilder,
    ) -> Result<Response, Error> {
        let response = builder(self.client.get(url)).send().await?;
        ok_or_error(response).await
    }

    /// Perform a HTTP GET request with a custom timeout.
    async fn get_with_timeout<T: DeserializeOwned, U: IntoUrl>(
        &self,
        url: U,
        timeout: Duration,
    ) -> Result<T, Error> {
        let response = self
            .get_response(url, |builder| builder.timeout(timeout))
            .await?;
        Ok(response.json().await?)
    }

    /// Perform a HTTP GET request, returning `None` on a 404 error.
    async fn get_opt<T: DeserializeOwned, U: IntoUrl>(&self, url: U) -> Result<Option<T>, Error> {
        match self
            .get_response(url, |b| b.accept(Accept::Json))
            .await
            .optional()?
        {
            Some(response) => Ok(Some(response.json().await?)),
            None => Ok(None),
        }
    }

    /// Perform a HTTP GET request with a custom timeout, returning `None` on a 404 error.
    async fn get_opt_with_timeout<T: DeserializeOwned, U: IntoUrl>(
        &self,
        url: U,
        timeout: Duration,
    ) -> Result<Option<T>, Error> {
        let opt_response = self
            .get_response(url, |b| b.timeout(timeout).accept(Accept::Json))
            .await
            .optional()?;
        match opt_response {
            Some(response) => Ok(Some(response.json().await?)),
            None => Ok(None),
        }
    }

    /// Perform a HTTP GET request using an 'accept' header, returning `None` on a 404 error.
    pub async fn get_bytes_opt_accept_header<U: IntoUrl>(
        &self,
        url: U,
        accept_header: Accept,
        timeout: Duration,
    ) -> Result<Option<Vec<u8>>, Error> {
        let opt_response = self
            .get_response(url, |b| b.accept(accept_header).timeout(timeout))
            .await
            .optional()?;
        match opt_response {
            Some(resp) => Ok(Some(resp.bytes().await?.into_iter().collect::<Vec<_>>())),
            None => Ok(None),
        }
    }

    /// Perform a HTTP GET request using an 'accept' header, returning `None` on a 404 error.
    pub async fn get_response_with_response_headers<U: IntoUrl, F, T>(
        &self,
        url: U,
        accept_header: Accept,
        timeout: Duration,
        parser: impl FnOnce(Response, HeaderMap) -> F,
    ) -> Result<Option<T>, Error>
    where
        F: Future<Output = Result<T, Error>>,
    {
        let opt_response = self
            .get_response(url, |b| b.accept(accept_header).timeout(timeout))
            .await
            .optional()?;

        match opt_response {
            Some(resp) => {
                let response_headers = resp.headers().clone();
                let parsed_response = parser(resp, response_headers).await?;
                Ok(Some(parsed_response))
            }
            None => Ok(None),
        }
    }

    /// Perform a HTTP POST request.
    async fn post<T: Serialize, U: IntoUrl>(&self, url: U, body: &T) -> Result<(), Error> {
        self.post_generic(url, body, None).await?;
        Ok(())
    }

    /// Perform a HTTP POST request, returning a JSON response.
    #[cfg(feature = "lighthouse")]
    async fn post_with_response<T: Serialize, U: IntoUrl, R: DeserializeOwned>(
        &self,
        url: U,
        body: &T,
    ) -> Result<R, Error> {
        self.post_generic(url, body, None)
            .await?
            .json()
            .await
            .map_err(Into::into)
    }

    async fn post_with_opt_response<T: Serialize, U: IntoUrl, R: DeserializeOwned>(
        &self,
        url: U,
        body: &T,
    ) -> Result<Option<R>, Error> {
        if let Some(response) = self.post_generic(url, body, None).await.optional()? {
            response.json().await.map_err(Into::into)
        } else {
            Ok(None)
        }
    }

    /// Perform a HTTP POST request with a custom timeout.
    async fn post_with_timeout<T: Serialize, U: IntoUrl>(
        &self,
        url: U,
        body: &T,
        timeout: Duration,
    ) -> Result<(), Error> {
        self.post_generic(url, body, Some(timeout)).await?;
        Ok(())
    }

    /// Perform a HTTP POST request with a custom timeout, returning a JSON response.
    async fn post_with_timeout_and_response<T: DeserializeOwned, U: IntoUrl, V: Serialize>(
        &self,
        url: U,
        body: &V,
        timeout: Duration,
    ) -> Result<T, Error> {
        self.post_generic(url, body, Some(timeout))
            .await?
            .json()
            .await
            .map_err(Error::from)
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

    /// Generic POST function supporting arbitrary responses and timeouts.
    /// Does not include Content-Type application/json in the request header.
    async fn post_generic_json_without_content_type_header<T: Serialize, U: IntoUrl>(
        &self,
        url: U,
        body: &T,
        timeout: Option<Duration>,
    ) -> Result<Response, Error> {
        let mut builder = self.client.post(url);
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }

        let serialized_body = serde_json::to_vec(body).map_err(Error::InvalidJson)?;

        let response = builder.body(serialized_body).send().await?;
        ok_or_error(response).await
    }

    /// Generic POST function supporting arbitrary responses and timeouts.
    async fn post_generic_with_consensus_version<T: Serialize, U: IntoUrl>(
        &self,
        url: U,
        body: &T,
        timeout: Option<Duration>,
        fork: ForkName,
    ) -> Result<Response, Error> {
        let mut builder = self.client.post(url);
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        let response = builder
            .header(CONSENSUS_VERSION_HEADER, fork.to_string())
            .json(body)
            .send()
            .await?;
        ok_or_error(response).await
    }

    /// Generic POST function supporting arbitrary responses and timeouts.
    async fn post_generic_with_consensus_version_and_ssz_body<T: Into<Body>, U: IntoUrl>(
        &self,
        url: U,
        body: T,
        timeout: Option<Duration>,
        fork: ForkName,
    ) -> Result<Response, Error> {
        let mut builder = self.client.post(url);
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            CONSENSUS_VERSION_HEADER,
            HeaderValue::from_str(&fork.to_string()).expect("Failed to create header value"),
        );
        headers.insert(
            "Content-Type",
            HeaderValue::from_static("application/octet-stream"),
        );
        let response = builder.headers(headers).body(body).send().await?;
        ok_or_error(response).await
    }

    /// `GET beacon/genesis`
    ///
    /// ## Errors
    ///
    /// May return a `404` if beacon chain genesis has not yet occurred.
    pub async fn get_beacon_genesis(&self) -> Result<GenericResponse<GenesisData>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("genesis");

        self.get(path).await
    }

    /// `GET beacon/states/{state_id}/root`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_root(
        &self,
        state_id: StateId,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<RootData>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("root");

        self.get_opt(path).await
    }

    /// `GET beacon/states/{state_id}/fork`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_fork(
        &self,
        state_id: StateId,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<Fork>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("fork");

        self.get_opt(path).await
    }

    /// `GET beacon/states/{state_id}/finality_checkpoints`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_finality_checkpoints(
        &self,
        state_id: StateId,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<FinalityCheckpointsData>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("finality_checkpoints");

        self.get_opt(path).await
    }

    /// `GET beacon/states/{state_id}/validator_balances?id`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_validator_balances(
        &self,
        state_id: StateId,
        ids: Option<&[ValidatorId]>,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<Vec<ValidatorBalanceData>>>, Error>
    {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("validator_balances");

        if let Some(ids) = ids {
            let id_string = ids
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",");
            path.query_pairs_mut().append_pair("id", &id_string);
        }

        self.get_opt(path).await
    }

    /// `POST beacon/states/{state_id}/validator_balances`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn post_beacon_states_validator_balances(
        &self,
        state_id: StateId,
        ids: Vec<ValidatorId>,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<Vec<ValidatorBalanceData>>>, Error>
    {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("validator_balances");

        let request = ValidatorBalancesRequestBody { ids };

        self.post_with_opt_response(path, &request).await
    }

    /// `GET beacon/states/{state_id}/validators?id,status`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_validators(
        &self,
        state_id: StateId,
        ids: Option<&[ValidatorId]>,
        statuses: Option<&[ValidatorStatus]>,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<Vec<ValidatorData>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("validators");

        if let Some(ids) = ids {
            let id_string = ids
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",");
            path.query_pairs_mut().append_pair("id", &id_string);
        }

        if let Some(statuses) = statuses {
            let status_string = statuses
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",");
            path.query_pairs_mut().append_pair("status", &status_string);
        }

        self.get_opt(path).await
    }

    /// `POST beacon/states/{state_id}/validators`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn post_beacon_states_validators(
        &self,
        state_id: StateId,
        ids: Option<Vec<ValidatorId>>,
        statuses: Option<Vec<ValidatorStatus>>,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<Vec<ValidatorData>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("validators");

        let request = ValidatorsRequestBody { ids, statuses };

        self.post_with_opt_response(path, &request).await
    }

    /// `GET beacon/states/{state_id}/committees?slot,index,epoch`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_committees(
        &self,
        state_id: StateId,
        slot: Option<Slot>,
        index: Option<u64>,
        epoch: Option<Epoch>,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<Vec<CommitteeData>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("committees");

        if let Some(slot) = slot {
            path.query_pairs_mut()
                .append_pair("slot", &slot.to_string());
        }

        if let Some(index) = index {
            path.query_pairs_mut()
                .append_pair("index", &index.to_string());
        }

        if let Some(epoch) = epoch {
            path.query_pairs_mut()
                .append_pair("epoch", &epoch.to_string());
        }

        self.get_opt(path).await
    }

    /// `GET beacon/states/{state_id}/sync_committees?epoch`
    pub async fn get_beacon_states_sync_committees(
        &self,
        state_id: StateId,
        epoch: Option<Epoch>,
    ) -> Result<ExecutionOptimisticFinalizedResponse<SyncCommitteeByValidatorIndices>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("sync_committees");

        if let Some(epoch) = epoch {
            path.query_pairs_mut()
                .append_pair("epoch", &epoch.to_string());
        }

        self.get(path).await
    }

    /// `GET beacon/states/{state_id}/randao?epoch`
    pub async fn get_beacon_states_randao(
        &self,
        state_id: StateId,
        epoch: Option<Epoch>,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<RandaoMix>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("randao");

        if let Some(epoch) = epoch {
            path.query_pairs_mut()
                .append_pair("epoch", &epoch.to_string());
        }

        self.get_opt(path).await
    }

    /// `GET beacon/states/{state_id}/validators/{validator_id}`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_validator_id(
        &self,
        state_id: StateId,
        validator_id: &ValidatorId,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<ValidatorData>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("validators")
            .push(&validator_id.to_string());

        self.get_opt(path).await
    }

    /// `GET beacon/light_client/bootstrap`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_light_client_bootstrap<E: EthSpec>(
        &self,
        block_root: Hash256,
    ) -> Result<Option<ForkVersionedResponse<LightClientBootstrap<E>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("light_client")
            .push("bootstrap")
            .push(&format!("{:?}", block_root));

        self.get_opt(path).await
    }

    /// `GET beacon/light_client/optimistic_update`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_light_client_optimistic_update<E: EthSpec>(
        &self,
    ) -> Result<Option<ForkVersionedResponse<LightClientOptimisticUpdate<E>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("light_client")
            .push("optimistic_update");

        self.get_opt(path).await
    }

    /// `GET beacon/light_client/finality_update`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_light_client_finality_update<E: EthSpec>(
        &self,
    ) -> Result<Option<ForkVersionedResponse<LightClientFinalityUpdate<E>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("light_client")
            .push("finality_update");

        self.get_opt(path).await
    }

    /// `GET beacon/headers?slot,parent_root`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_headers(
        &self,
        slot: Option<Slot>,
        parent_root: Option<Hash256>,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<Vec<BlockHeaderData>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("headers");

        if let Some(slot) = slot {
            path.query_pairs_mut()
                .append_pair("slot", &slot.to_string());
        }

        if let Some(root) = parent_root {
            path.query_pairs_mut()
                .append_pair("parent_root", &format!("{:?}", root));
        }

        self.get_opt(path).await
    }

    /// `GET beacon/headers/{block_id}`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_headers_block_id(
        &self,
        block_id: BlockId,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<BlockHeaderData>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("headers")
            .push(&block_id.to_string());

        self.get_opt(path).await
    }

    /// `POST beacon/blocks`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn post_beacon_blocks<E: EthSpec>(
        &self,
        block_contents: &PublishBlockRequest<E>,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("blocks");

        self.post_with_timeout(path, block_contents, self.timeouts.proposal)
            .await?;

        Ok(())
    }

    /// `POST beacon/blocks`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn post_beacon_blocks_ssz<E: EthSpec>(
        &self,
        block_contents: &PublishBlockRequest<E>,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("blocks");

        self.post_generic_with_consensus_version_and_ssz_body(
            path,
            block_contents.as_ssz_bytes(),
            Some(self.timeouts.proposal),
            block_contents.signed_block().fork_name_unchecked(),
        )
        .await?;

        Ok(())
    }

    /// `POST beacon/blinded_blocks`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn post_beacon_blinded_blocks<E: EthSpec>(
        &self,
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("blinded_blocks");

        self.post_with_timeout(path, block, self.timeouts.proposal)
            .await?;

        Ok(())
    }

    /// `POST beacon/blinded_blocks`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn post_beacon_blinded_blocks_ssz<E: EthSpec>(
        &self,
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("blinded_blocks");

        self.post_generic_with_consensus_version_and_ssz_body(
            path,
            block.as_ssz_bytes(),
            Some(self.timeouts.proposal),
            block.fork_name_unchecked(),
        )
        .await?;

        Ok(())
    }

    pub fn post_beacon_blocks_v2_path(
        &self,
        validation_level: Option<BroadcastValidation>,
    ) -> Result<Url, Error> {
        let mut path = self.eth_path(V2)?;
        path.path_segments_mut()
            .map_err(|_| Error::InvalidUrl(self.server.clone()))?
            .extend(&["beacon", "blocks"]);

        path.set_query(
            validation_level
                .map(|v| format!("broadcast_validation={}", v))
                .as_deref(),
        );

        Ok(path)
    }

    pub fn post_beacon_blinded_blocks_v2_path(
        &self,
        validation_level: Option<BroadcastValidation>,
    ) -> Result<Url, Error> {
        let mut path = self.eth_path(V2)?;
        path.path_segments_mut()
            .map_err(|_| Error::InvalidUrl(self.server.clone()))?
            .extend(&["beacon", "blinded_blocks"]);

        path.set_query(
            validation_level
                .map(|v| format!("broadcast_validation={}", v))
                .as_deref(),
        );

        Ok(path)
    }

    /// `POST v2/beacon/blocks`
    pub async fn post_beacon_blocks_v2<E: EthSpec>(
        &self,
        block_contents: &PublishBlockRequest<E>,
        validation_level: Option<BroadcastValidation>,
    ) -> Result<(), Error> {
        self.post_generic_with_consensus_version(
            self.post_beacon_blocks_v2_path(validation_level)?,
            block_contents,
            Some(self.timeouts.proposal),
            block_contents.signed_block().message().body().fork_name(),
        )
        .await?;

        Ok(())
    }

    /// `POST v2/beacon/blocks`
    pub async fn post_beacon_blocks_v2_ssz<E: EthSpec>(
        &self,
        block_contents: &PublishBlockRequest<E>,
        validation_level: Option<BroadcastValidation>,
    ) -> Result<(), Error> {
        self.post_generic_with_consensus_version_and_ssz_body(
            self.post_beacon_blocks_v2_path(validation_level)?,
            block_contents.as_ssz_bytes(),
            Some(self.timeouts.proposal),
            block_contents.signed_block().message().body().fork_name(),
        )
        .await?;

        Ok(())
    }

    /// `POST v2/beacon/blinded_blocks`
    pub async fn post_beacon_blinded_blocks_v2<E: EthSpec>(
        &self,
        signed_block: &SignedBlindedBeaconBlock<E>,
        validation_level: Option<BroadcastValidation>,
    ) -> Result<(), Error> {
        self.post_generic_with_consensus_version(
            self.post_beacon_blinded_blocks_v2_path(validation_level)?,
            signed_block,
            Some(self.timeouts.proposal),
            signed_block.message().body().fork_name(),
        )
        .await?;

        Ok(())
    }

    /// `POST v2/beacon/blinded_blocks`
    pub async fn post_beacon_blinded_blocks_v2_ssz<E: EthSpec>(
        &self,
        signed_block: &SignedBlindedBeaconBlock<E>,
        validation_level: Option<BroadcastValidation>,
    ) -> Result<(), Error> {
        self.post_generic_with_consensus_version_and_ssz_body(
            self.post_beacon_blinded_blocks_v2_path(validation_level)?,
            signed_block.as_ssz_bytes(),
            Some(self.timeouts.proposal),
            signed_block.message().body().fork_name(),
        )
        .await?;

        Ok(())
    }

    /// Path for `v2/beacon/blocks`
    pub fn get_beacon_blocks_path(&self, block_id: BlockId) -> Result<Url, Error> {
        let mut path = self.eth_path(V2)?;
        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("blocks")
            .push(&block_id.to_string());
        Ok(path)
    }

    /// Path for `v1/beacon/blob_sidecars/{block_id}`
    pub fn get_blobs_path(&self, block_id: BlockId) -> Result<Url, Error> {
        let mut path = self.eth_path(V1)?;
        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("blob_sidecars")
            .push(&block_id.to_string());
        Ok(path)
    }

    /// Path for `v1/beacon/blinded_blocks/{block_id}`
    pub fn get_beacon_blinded_blocks_path(&self, block_id: BlockId) -> Result<Url, Error> {
        let mut path = self.eth_path(V1)?;
        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("blinded_blocks")
            .push(&block_id.to_string());
        Ok(path)
    }

    /// `GET v2/beacon/blocks`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blocks<E: EthSpec>(
        &self,
        block_id: BlockId,
    ) -> Result<
        Option<ExecutionOptimisticFinalizedForkVersionedResponse<SignedBeaconBlock<E>>>,
        Error,
    > {
        let path = self.get_beacon_blocks_path(block_id)?;
        let Some(response) = self.get_response(path, |b| b).await.optional()? else {
            return Ok(None);
        };

        Ok(Some(response.json().await?))
    }

    /// `GET v1/beacon/blob_sidecars/{block_id}`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_blobs<E: EthSpec>(
        &self,
        block_id: BlockId,
        indices: Option<&[u64]>,
    ) -> Result<Option<GenericResponse<BlobSidecarList<E>>>, Error> {
        let mut path = self.get_blobs_path(block_id)?;
        if let Some(indices) = indices {
            let indices_string = indices
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",");
            path.query_pairs_mut()
                .append_pair("indices", &indices_string);
        }

        let Some(response) = self.get_response(path, |b| b).await.optional()? else {
            return Ok(None);
        };

        Ok(Some(response.json().await?))
    }

    /// `GET v1/beacon/blinded_blocks/{block_id}`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blinded_blocks<E: EthSpec>(
        &self,
        block_id: BlockId,
    ) -> Result<
        Option<ExecutionOptimisticFinalizedForkVersionedResponse<SignedBlindedBeaconBlock<E>>>,
        Error,
    > {
        let path = self.get_beacon_blinded_blocks_path(block_id)?;
        let Some(response) = self.get_response(path, |b| b).await.optional()? else {
            return Ok(None);
        };

        Ok(Some(response.json().await?))
    }

    /// `GET v1/beacon/blocks` (LEGACY)
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blocks_v1<E: EthSpec>(
        &self,
        block_id: BlockId,
    ) -> Result<Option<ForkVersionedResponse<SignedBeaconBlock<E>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("blocks")
            .push(&block_id.to_string());

        self.get_opt(path).await
    }

    /// `GET beacon/blocks` as SSZ
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blocks_ssz<E: EthSpec>(
        &self,
        block_id: BlockId,
        spec: &ChainSpec,
    ) -> Result<Option<SignedBeaconBlock<E>>, Error> {
        let path = self.get_beacon_blocks_path(block_id)?;

        self.get_bytes_opt_accept_header(path, Accept::Ssz, self.timeouts.get_beacon_blocks_ssz)
            .await?
            .map(|bytes| SignedBeaconBlock::from_ssz_bytes(&bytes, spec).map_err(Error::InvalidSsz))
            .transpose()
    }

    /// `GET beacon/blinded_blocks/{block_id}` as SSZ
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blinded_blocks_ssz<E: EthSpec>(
        &self,
        block_id: BlockId,
        spec: &ChainSpec,
    ) -> Result<Option<SignedBlindedBeaconBlock<E>>, Error> {
        let path = self.get_beacon_blinded_blocks_path(block_id)?;

        self.get_bytes_opt_accept_header(path, Accept::Ssz, self.timeouts.get_beacon_blocks_ssz)
            .await?
            .map(|bytes| {
                SignedBlindedBeaconBlock::from_ssz_bytes(&bytes, spec).map_err(Error::InvalidSsz)
            })
            .transpose()
    }

    /// `GET beacon/blocks/{block_id}/root`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blocks_root(
        &self,
        block_id: BlockId,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<RootData>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("blocks")
            .push(&block_id.to_string())
            .push("root");

        self.get_opt(path).await
    }

    /// `GET beacon/blocks/{block_id}/attestations`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blocks_attestations<E: EthSpec>(
        &self,
        block_id: BlockId,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<Vec<Attestation<E>>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("blocks")
            .push(&block_id.to_string())
            .push("attestations");

        self.get_opt(path).await
    }

    /// `POST beacon/pool/attestations`
    pub async fn post_beacon_pool_attestations<E: EthSpec>(
        &self,
        attestations: &[Attestation<E>],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("pool")
            .push("attestations");

        self.post_with_timeout(path, &attestations, self.timeouts.attestation)
            .await?;

        Ok(())
    }

    /// `GET beacon/pool/attestations?slot,committee_index`
    pub async fn get_beacon_pool_attestations<E: EthSpec>(
        &self,
        slot: Option<Slot>,
        committee_index: Option<u64>,
    ) -> Result<GenericResponse<Vec<Attestation<E>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("pool")
            .push("attestations");

        if let Some(slot) = slot {
            path.query_pairs_mut()
                .append_pair("slot", &slot.to_string());
        }

        if let Some(index) = committee_index {
            path.query_pairs_mut()
                .append_pair("committee_index", &index.to_string());
        }

        self.get(path).await
    }

    /// `POST beacon/pool/attester_slashings`
    pub async fn post_beacon_pool_attester_slashings<E: EthSpec>(
        &self,
        slashing: &AttesterSlashing<E>,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("pool")
            .push("attester_slashings");

        self.post_generic_json_without_content_type_header(path, slashing, None)
            .await?;

        Ok(())
    }

    /// `GET beacon/pool/attester_slashings`
    pub async fn get_beacon_pool_attester_slashings<E: EthSpec>(
        &self,
    ) -> Result<GenericResponse<Vec<AttesterSlashing<E>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("pool")
            .push("attester_slashings");

        self.get(path).await
    }

    /// `POST beacon/pool/proposer_slashings`
    pub async fn post_beacon_pool_proposer_slashings(
        &self,
        slashing: &ProposerSlashing,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("pool")
            .push("proposer_slashings");

        self.post(path, slashing).await?;

        Ok(())
    }

    /// `GET beacon/pool/proposer_slashings`
    pub async fn get_beacon_pool_proposer_slashings(
        &self,
    ) -> Result<GenericResponse<Vec<ProposerSlashing>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("pool")
            .push("proposer_slashings");

        self.get(path).await
    }

    /// `POST beacon/pool/voluntary_exits`
    pub async fn post_beacon_pool_voluntary_exits(
        &self,
        exit: &SignedVoluntaryExit,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("pool")
            .push("voluntary_exits");

        self.post(path, exit).await?;

        Ok(())
    }

    /// `GET beacon/pool/voluntary_exits`
    pub async fn get_beacon_pool_voluntary_exits(
        &self,
    ) -> Result<GenericResponse<Vec<SignedVoluntaryExit>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("pool")
            .push("voluntary_exits");

        self.get(path).await
    }

    /// `POST beacon/pool/sync_committees`
    pub async fn post_beacon_pool_sync_committee_signatures(
        &self,
        signatures: &[SyncCommitteeMessage],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("pool")
            .push("sync_committees");

        self.post(path, &signatures).await?;

        Ok(())
    }

    /// `POST beacon/pool/bls_to_execution_changes`
    pub async fn post_beacon_pool_bls_to_execution_changes(
        &self,
        address_changes: &[SignedBlsToExecutionChange],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("pool")
            .push("bls_to_execution_changes");

        self.post(path, &address_changes).await?;

        Ok(())
    }

    /// `GET beacon/deposit_snapshot`
    pub async fn get_deposit_snapshot(&self) -> Result<Option<types::DepositTreeSnapshot>, Error> {
        let mut path = self.eth_path(V1)?;
        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("deposit_snapshot");
        self.get_opt_with_timeout::<GenericResponse<_>, _>(path, self.timeouts.get_deposit_snapshot)
            .await
            .map(|opt| opt.map(|r| r.data))
    }

    /// `POST beacon/rewards/sync_committee`
    pub async fn post_beacon_rewards_sync_committee(
        &self,
        rewards: &[Option<Vec<lighthouse::SyncCommitteeReward>>],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("rewards")
            .push("sync_committee");

        self.post(path, &rewards).await?;

        Ok(())
    }

    /// `GET beacon/rewards/blocks`
    pub async fn get_beacon_rewards_blocks(&self, epoch: Epoch) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("rewards")
            .push("blocks");

        path.query_pairs_mut()
            .append_pair("epoch", &epoch.to_string());

        self.get(path).await
    }

    /// `POST beacon/rewards/attestations`
    pub async fn post_beacon_rewards_attestations(
        &self,
        attestations: &[ValidatorId],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("rewards")
            .push("attestations");

        self.post(path, &attestations).await?;

        Ok(())
    }

    // GET builder/states/{state_id}/expected_withdrawals
    pub async fn get_expected_withdrawals(
        &self,
        state_id: &StateId,
    ) -> Result<ExecutionOptimisticFinalizedResponse<Vec<Withdrawal>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("builder")
            .push("states")
            .push(&state_id.to_string())
            .push("expected_withdrawals");

        self.get(path).await
    }

    /// `POST validator/contribution_and_proofs`
    pub async fn post_validator_contribution_and_proofs<E: EthSpec>(
        &self,
        signed_contributions: &[SignedContributionAndProof<E>],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("contribution_and_proofs");

        self.post_with_timeout(
            path,
            &signed_contributions,
            self.timeouts.sync_committee_contribution,
        )
        .await?;

        Ok(())
    }

    /// `POST validator/prepare_beacon_proposer`
    pub async fn post_validator_prepare_beacon_proposer(
        &self,
        preparation_data: &[ProposerPreparationData],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("prepare_beacon_proposer");

        self.post(path, &preparation_data).await?;

        Ok(())
    }

    /// `POST validator/register_validator`
    pub async fn post_validator_register_validator(
        &self,
        registration_data: &[SignedValidatorRegistrationData],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("register_validator");

        self.post(path, &registration_data).await?;

        Ok(())
    }

    /// `GET config/fork_schedule`
    pub async fn get_config_fork_schedule(&self) -> Result<GenericResponse<Vec<Fork>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("config")
            .push("fork_schedule");

        self.get(path).await
    }

    /// `GET config/spec`
    pub async fn get_config_spec<T: Serialize + DeserializeOwned>(
        &self,
    ) -> Result<GenericResponse<T>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("config")
            .push("spec");

        self.get(path).await
    }

    /// `GET config/deposit_contract`
    pub async fn get_config_deposit_contract(
        &self,
    ) -> Result<GenericResponse<DepositContractData>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("config")
            .push("deposit_contract");

        self.get(path).await
    }

    /// `GET node/version`
    pub async fn get_node_version(&self) -> Result<GenericResponse<VersionData>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("node")
            .push("version");

        self.get(path).await
    }

    /// `GET node/identity`
    pub async fn get_node_identity(&self) -> Result<GenericResponse<IdentityData>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("node")
            .push("identity");

        self.get(path).await
    }

    /// `GET node/syncing`
    pub async fn get_node_syncing(&self) -> Result<GenericResponse<SyncingData>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("node")
            .push("syncing");

        self.get(path).await
    }

    /// `GET node/health`
    pub async fn get_node_health(&self) -> Result<StatusCode, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("node")
            .push("health");

        let status = self.client.get(path).send().await?.status();
        if status == StatusCode::OK || status == StatusCode::PARTIAL_CONTENT {
            Ok(status)
        } else {
            Err(Error::StatusCode(status))
        }
    }

    /// `GET node/peers/{peer_id}`
    pub async fn get_node_peers_by_id(
        &self,
        peer_id: PeerId,
    ) -> Result<GenericResponse<PeerData>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("node")
            .push("peers")
            .push(&peer_id.to_string());

        self.get(path).await
    }

    /// `GET node/peers`
    pub async fn get_node_peers(
        &self,
        states: Option<&[PeerState]>,
        directions: Option<&[PeerDirection]>,
    ) -> Result<PeersData, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("node")
            .push("peers");

        if let Some(states) = states {
            let state_string = states
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",");
            path.query_pairs_mut().append_pair("state", &state_string);
        }

        if let Some(directions) = directions {
            let dir_string = directions
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",");
            path.query_pairs_mut().append_pair("direction", &dir_string);
        }

        self.get(path).await
    }

    /// `GET node/peer_count`
    pub async fn get_node_peer_count(&self) -> Result<GenericResponse<PeerCount>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("node")
            .push("peer_count");

        self.get(path).await
    }

    /// URL path for `v2/debug/beacon/states/{state_id}`.
    pub fn get_debug_beacon_states_path(&self, state_id: StateId) -> Result<Url, Error> {
        let mut path = self.eth_path(V2)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("debug")
            .push("beacon")
            .push("states")
            .push(&state_id.to_string());
        Ok(path)
    }

    /// `GET v2/debug/beacon/states/{state_id}`
    pub async fn get_debug_beacon_states<E: EthSpec>(
        &self,
        state_id: StateId,
    ) -> Result<Option<ExecutionOptimisticFinalizedForkVersionedResponse<BeaconState<E>>>, Error>
    {
        let path = self.get_debug_beacon_states_path(state_id)?;
        self.get_opt(path).await
    }

    /// `GET debug/beacon/states/{state_id}`
    /// `-H "accept: application/octet-stream"`
    pub async fn get_debug_beacon_states_ssz<E: EthSpec>(
        &self,
        state_id: StateId,
        spec: &ChainSpec,
    ) -> Result<Option<BeaconState<E>>, Error> {
        let path = self.get_debug_beacon_states_path(state_id)?;

        self.get_bytes_opt_accept_header(path, Accept::Ssz, self.timeouts.get_debug_beacon_states)
            .await?
            .map(|bytes| BeaconState::from_ssz_bytes(&bytes, spec).map_err(Error::InvalidSsz))
            .transpose()
    }

    /// `GET v2/debug/beacon/heads`
    pub async fn get_debug_beacon_heads(
        &self,
    ) -> Result<GenericResponse<Vec<ChainHeadData>>, Error> {
        let mut path = self.eth_path(V2)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("debug")
            .push("beacon")
            .push("heads");

        self.get(path).await
    }

    /// `GET v1/debug/beacon/heads` (LEGACY)
    pub async fn get_debug_beacon_heads_v1(
        &self,
    ) -> Result<GenericResponse<Vec<ChainHeadData>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("debug")
            .push("beacon")
            .push("heads");

        self.get(path).await
    }

    /// `GET v1/debug/fork_choice`
    pub async fn get_debug_fork_choice(&self) -> Result<ForkChoice, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("debug")
            .push("fork_choice");

        self.get(path).await
    }

    /// `GET validator/duties/proposer/{epoch}`
    pub async fn get_validator_duties_proposer(
        &self,
        epoch: Epoch,
    ) -> Result<DutiesResponse<Vec<ProposerData>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("duties")
            .push("proposer")
            .push(&epoch.to_string());

        self.get_with_timeout(path, self.timeouts.proposer_duties)
            .await
    }

    /// `GET v2/validator/blocks/{slot}`
    pub async fn get_validator_blocks<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
    ) -> Result<ForkVersionedResponse<FullBlockContents<E>>, Error> {
        self.get_validator_blocks_modular(slot, randao_reveal, graffiti, SkipRandaoVerification::No)
            .await
    }

    /// `GET v2/validator/blocks/{slot}`
    pub async fn get_validator_blocks_modular<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
    ) -> Result<ForkVersionedResponse<FullBlockContents<E>>, Error> {
        let path = self
            .get_validator_blocks_path::<E>(slot, randao_reveal, graffiti, skip_randao_verification)
            .await?;

        self.get(path).await
    }

    /// returns `GET v2/validator/blocks/{slot}` URL path
    pub async fn get_validator_blocks_path<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
    ) -> Result<Url, Error> {
        let mut path = self.eth_path(V2)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("blocks")
            .push(&slot.to_string());

        path.query_pairs_mut()
            .append_pair("randao_reveal", &randao_reveal.to_string());

        if let Some(graffiti) = graffiti {
            path.query_pairs_mut()
                .append_pair("graffiti", &graffiti.to_string());
        }

        if skip_randao_verification == SkipRandaoVerification::Yes {
            path.query_pairs_mut()
                .append_pair("skip_randao_verification", "");
        }

        Ok(path)
    }

    /// returns `GET v3/validator/blocks/{slot}` URL path
    pub async fn get_validator_blocks_v3_path(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
        builder_booster_factor: Option<u64>,
    ) -> Result<Url, Error> {
        let mut path = self.eth_path(V3)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("blocks")
            .push(&slot.to_string());

        path.query_pairs_mut()
            .append_pair("randao_reveal", &randao_reveal.to_string());

        if let Some(graffiti) = graffiti {
            path.query_pairs_mut()
                .append_pair("graffiti", &graffiti.to_string());
        }

        if skip_randao_verification == SkipRandaoVerification::Yes {
            path.query_pairs_mut()
                .append_pair("skip_randao_verification", "");
        }

        if let Some(builder_booster_factor) = builder_booster_factor {
            path.query_pairs_mut()
                .append_pair("builder_boost_factor", &builder_booster_factor.to_string());
        }

        Ok(path)
    }

    /// `GET v3/validator/blocks/{slot}`
    pub async fn get_validator_blocks_v3<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        builder_booster_factor: Option<u64>,
    ) -> Result<(JsonProduceBlockV3Response<E>, ProduceBlockV3Metadata), Error> {
        self.get_validator_blocks_v3_modular(
            slot,
            randao_reveal,
            graffiti,
            SkipRandaoVerification::No,
            builder_booster_factor,
        )
        .await
    }

    /// `GET v3/validator/blocks/{slot}`
    pub async fn get_validator_blocks_v3_modular<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
        builder_booster_factor: Option<u64>,
    ) -> Result<(JsonProduceBlockV3Response<E>, ProduceBlockV3Metadata), Error> {
        let path = self
            .get_validator_blocks_v3_path(
                slot,
                randao_reveal,
                graffiti,
                skip_randao_verification,
                builder_booster_factor,
            )
            .await?;

        let opt_result = self
            .get_response_with_response_headers(
                path,
                Accept::Json,
                self.timeouts.get_validator_block,
                |response, headers| async move {
                    let header_metadata = ProduceBlockV3Metadata::try_from(&headers)
                        .map_err(Error::InvalidHeaders)?;
                    if header_metadata.execution_payload_blinded {
                        let blinded_response = response
                            .json::<ForkVersionedResponse<BlindedBeaconBlock<E>,
                                ProduceBlockV3Metadata>>()
                            .await?
                            .map_data(ProduceBlockV3Response::Blinded);
                        Ok((blinded_response, header_metadata))
                    } else {
                        let full_block_response= response
                            .json::<ForkVersionedResponse<FullBlockContents<E>,
                            ProduceBlockV3Metadata>>()
                            .await?
                            .map_data(ProduceBlockV3Response::Full);
                        Ok((full_block_response, header_metadata))
                    }
                },
            )
            .await?;

        // Generic handler is optional but this route should never 404 unless unimplemented, so
        // treat that as an error.
        opt_result.ok_or(Error::StatusCode(StatusCode::NOT_FOUND))
    }

    /// `GET v3/validator/blocks/{slot}` in ssz format
    pub async fn get_validator_blocks_v3_ssz<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        builder_booster_factor: Option<u64>,
    ) -> Result<(ProduceBlockV3Response<E>, ProduceBlockV3Metadata), Error> {
        self.get_validator_blocks_v3_modular_ssz::<E>(
            slot,
            randao_reveal,
            graffiti,
            SkipRandaoVerification::No,
            builder_booster_factor,
        )
        .await
    }

    /// `GET v3/validator/blocks/{slot}` in ssz format
    pub async fn get_validator_blocks_v3_modular_ssz<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
        builder_booster_factor: Option<u64>,
    ) -> Result<(ProduceBlockV3Response<E>, ProduceBlockV3Metadata), Error> {
        let path = self
            .get_validator_blocks_v3_path(
                slot,
                randao_reveal,
                graffiti,
                skip_randao_verification,
                builder_booster_factor,
            )
            .await?;

        let opt_response = self
            .get_response_with_response_headers(
                path,
                Accept::Ssz,
                self.timeouts.get_validator_block,
                |response, headers| async move {
                    let metadata = ProduceBlockV3Metadata::try_from(&headers)
                        .map_err(Error::InvalidHeaders)?;
                    let response_bytes = response.bytes().await?;

                    // Parse bytes based on metadata.
                    let response = if metadata.execution_payload_blinded {
                        ProduceBlockV3Response::Blinded(
                            BlindedBeaconBlock::from_ssz_bytes_for_fork(
                                &response_bytes,
                                metadata.consensus_version,
                            )
                            .map_err(Error::InvalidSsz)?,
                        )
                    } else {
                        ProduceBlockV3Response::Full(
                            FullBlockContents::from_ssz_bytes_for_fork(
                                &response_bytes,
                                metadata.consensus_version,
                            )
                            .map_err(Error::InvalidSsz)?,
                        )
                    };

                    Ok((response, metadata))
                },
            )
            .await?;

        // Generic handler is optional but this route should never 404 unless unimplemented, so
        // treat that as an error.
        opt_response.ok_or(Error::StatusCode(StatusCode::NOT_FOUND))
    }

    /// `GET v2/validator/blocks/{slot}` in ssz format
    pub async fn get_validator_blocks_ssz<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
    ) -> Result<Option<Vec<u8>>, Error> {
        self.get_validator_blocks_modular_ssz::<E>(
            slot,
            randao_reveal,
            graffiti,
            SkipRandaoVerification::No,
        )
        .await
    }

    /// `GET v2/validator/blocks/{slot}` in ssz format
    pub async fn get_validator_blocks_modular_ssz<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
    ) -> Result<Option<Vec<u8>>, Error> {
        let path = self
            .get_validator_blocks_path::<E>(slot, randao_reveal, graffiti, skip_randao_verification)
            .await?;

        self.get_bytes_opt_accept_header(path, Accept::Ssz, self.timeouts.get_validator_block)
            .await
    }

    /// `GET v2/validator/blinded_blocks/{slot}`
    pub async fn get_validator_blinded_blocks<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
    ) -> Result<ForkVersionedResponse<BlindedBeaconBlock<E>>, Error> {
        self.get_validator_blinded_blocks_modular(
            slot,
            randao_reveal,
            graffiti,
            SkipRandaoVerification::No,
        )
        .await
    }

    /// returns `GET v1/validator/blinded_blocks/{slot}` URL path
    pub async fn get_validator_blinded_blocks_path<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
    ) -> Result<Url, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("blinded_blocks")
            .push(&slot.to_string());

        path.query_pairs_mut()
            .append_pair("randao_reveal", &randao_reveal.to_string());

        if let Some(graffiti) = graffiti {
            path.query_pairs_mut()
                .append_pair("graffiti", &graffiti.to_string());
        }

        if skip_randao_verification == SkipRandaoVerification::Yes {
            path.query_pairs_mut()
                .append_key_only("skip_randao_verification");
        }

        Ok(path)
    }

    /// `GET v1/validator/blinded_blocks/{slot}`
    pub async fn get_validator_blinded_blocks_modular<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
    ) -> Result<ForkVersionedResponse<BlindedBeaconBlock<E>>, Error> {
        let path = self
            .get_validator_blinded_blocks_path::<E>(
                slot,
                randao_reveal,
                graffiti,
                skip_randao_verification,
            )
            .await?;

        self.get(path).await
    }

    /// `GET v2/validator/blinded_blocks/{slot}` in ssz format
    pub async fn get_validator_blinded_blocks_ssz<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
    ) -> Result<Option<Vec<u8>>, Error> {
        self.get_validator_blinded_blocks_modular_ssz::<E>(
            slot,
            randao_reveal,
            graffiti,
            SkipRandaoVerification::No,
        )
        .await
    }

    pub async fn get_validator_blinded_blocks_modular_ssz<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
    ) -> Result<Option<Vec<u8>>, Error> {
        let path = self
            .get_validator_blinded_blocks_path::<E>(
                slot,
                randao_reveal,
                graffiti,
                skip_randao_verification,
            )
            .await?;

        self.get_bytes_opt_accept_header(path, Accept::Ssz, self.timeouts.get_validator_block)
            .await
    }

    /// `GET validator/attestation_data?slot,committee_index`
    pub async fn get_validator_attestation_data(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<GenericResponse<AttestationData>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("attestation_data");

        path.query_pairs_mut()
            .append_pair("slot", &slot.to_string())
            .append_pair("committee_index", &committee_index.to_string());

        self.get_with_timeout(path, self.timeouts.attestation).await
    }

    /// `GET validator/aggregate_attestation?slot,attestation_data_root`
    pub async fn get_validator_aggregate_attestation<E: EthSpec>(
        &self,
        slot: Slot,
        attestation_data_root: Hash256,
    ) -> Result<Option<GenericResponse<Attestation<E>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("aggregate_attestation");

        path.query_pairs_mut()
            .append_pair("slot", &slot.to_string())
            .append_pair(
                "attestation_data_root",
                &format!("{:?}", attestation_data_root),
            );

        self.get_opt_with_timeout(path, self.timeouts.attestation)
            .await
    }

    /// `GET validator/sync_committee_contribution`
    pub async fn get_validator_sync_committee_contribution<E: EthSpec>(
        &self,
        sync_committee_data: &SyncContributionData,
    ) -> Result<Option<GenericResponse<SyncCommitteeContribution<E>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("sync_committee_contribution");

        path.query_pairs_mut()
            .append_pair("slot", &sync_committee_data.slot.to_string())
            .append_pair(
                "beacon_block_root",
                &format!("{:?}", sync_committee_data.beacon_block_root),
            )
            .append_pair(
                "subcommittee_index",
                &sync_committee_data.subcommittee_index.to_string(),
            );

        self.get_opt(path).await
    }

    /// `POST lighthouse/liveness`
    pub async fn post_lighthouse_liveness(
        &self,
        ids: &[u64],
        epoch: Epoch,
    ) -> Result<GenericResponse<Vec<LivenessResponseData>>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("liveness");

        self.post_with_timeout_and_response(
            path,
            &LivenessRequestData {
                indices: ids.to_vec(),
                epoch,
            },
            self.timeouts.liveness,
        )
        .await
    }

    /// `POST validator/liveness/{epoch}`
    pub async fn post_validator_liveness_epoch(
        &self,
        epoch: Epoch,
        indices: &[u64],
    ) -> Result<GenericResponse<Vec<StandardLivenessResponseData>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("liveness")
            .push(&epoch.to_string());

        self.post_with_timeout_and_response(
            path,
            &ValidatorIndexDataRef(indices),
            self.timeouts.liveness,
        )
        .await
    }

    /// `POST validator/duties/attester/{epoch}`
    pub async fn post_validator_duties_attester(
        &self,
        epoch: Epoch,
        indices: &[u64],
    ) -> Result<DutiesResponse<Vec<AttesterData>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("duties")
            .push("attester")
            .push(&epoch.to_string());

        self.post_with_timeout_and_response(
            path,
            &ValidatorIndexDataRef(indices),
            self.timeouts.attester_duties,
        )
        .await
    }

    /// `POST validator/aggregate_and_proofs`
    pub async fn post_validator_aggregate_and_proof<E: EthSpec>(
        &self,
        aggregates: &[SignedAggregateAndProof<E>],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("aggregate_and_proofs");

        self.post_with_timeout(path, &aggregates, self.timeouts.attestation)
            .await?;

        Ok(())
    }

    /// `POST validator/beacon_committee_subscriptions`
    pub async fn post_validator_beacon_committee_subscriptions(
        &self,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("beacon_committee_subscriptions");

        self.post(path, &subscriptions).await?;

        Ok(())
    }

    /// `POST validator/sync_committee_subscriptions`
    pub async fn post_validator_sync_committee_subscriptions(
        &self,
        subscriptions: &[SyncCommitteeSubscription],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("sync_committee_subscriptions");

        self.post(path, &subscriptions).await?;

        Ok(())
    }

    /// `GET events?topics`
    pub async fn get_events<E: EthSpec>(
        &self,
        topic: &[EventTopic],
    ) -> Result<impl Stream<Item = Result<EventKind<E>, Error>>, Error> {
        let mut path = self.eth_path(V1)?;
        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("events");

        let topic_string = topic
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        path.query_pairs_mut().append_pair("topics", &topic_string);

        Ok(self
            .client
            .get(path)
            .send()
            .await?
            .bytes_stream()
            .map(|next| match next {
                Ok(bytes) => EventKind::from_sse_bytes(bytes.as_ref()),
                Err(e) => Err(Error::HttpClient(e.into())),
            }))
    }

    /// `POST validator/duties/sync/{epoch}`
    pub async fn post_validator_duties_sync(
        &self,
        epoch: Epoch,
        indices: &[u64],
    ) -> Result<ExecutionOptimisticFinalizedResponse<Vec<SyncDuty>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("duties")
            .push("sync")
            .push(&epoch.to_string());

        self.post_with_timeout_and_response(
            path,
            &ValidatorIndexDataRef(indices),
            self.timeouts.sync_duties,
        )
        .await
    }
}

/// Returns `Ok(response)` if the response is a `200 OK` response. Otherwise, creates an
/// appropriate error message.
pub async fn ok_or_error(response: Response) -> Result<Response, Error> {
    let status = response.status();

    if status == StatusCode::OK {
        Ok(response)
    } else if let Ok(message) = response.json().await {
        match message {
            ResponseError::Message(message) => Err(Error::ServerMessage(message)),
            ResponseError::Indexed(indexed) => Err(Error::ServerIndexedMessage(indexed)),
        }
    } else {
        Err(Error::StatusCode(status))
    }
}
