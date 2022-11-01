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

use self::mixin::{RequestAccept, ResponseForkName, ResponseOptional};
use self::types::{Error as ResponseError, *};
use ::types::map_fork_name_with;
use futures::Stream;
use futures_util::StreamExt;
use lighthouse_network::PeerId;
pub use reqwest;
use reqwest::{IntoUrl, RequestBuilder, Response};
pub use reqwest::{StatusCode, Url};
pub use sensitive_url::SensitiveUrl;
use serde::{de::DeserializeOwned, Serialize};
use std::convert::TryFrom;
use std::fmt;
use std::iter::Iterator;
use std::path::PathBuf;
use std::time::Duration;

pub const V1: EndpointVersion = EndpointVersion(1);
pub const V2: EndpointVersion = EndpointVersion(2);

pub const CONSENSUS_VERSION_HEADER: &str = "Eth-Consensus-Version";

#[derive(Debug)]
pub enum Error {
    /// The `reqwest` client raised an error.
    Reqwest(reqwest::Error),
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
        Error::Reqwest(error)
    }
}

impl Error {
    /// If the error has a HTTP status code, return it.
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Error::Reqwest(error) => error.status(),
            Error::ServerMessage(msg) => StatusCode::try_from(msg.code).ok(),
            Error::ServerIndexedMessage(msg) => StatusCode::try_from(msg.code).ok(),
            Error::StatusCode(status) => Some(*status),
            Error::InvalidUrl(_) => None,
            Error::InvalidSecret(_) => None,
            Error::InvalidSignatureHeader => None,
            Error::MissingSignatureHeader => None,
            Error::InvalidJson(_) => None,
            Error::InvalidServerSentEvent(_) => None,
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
        match self.get_response(url, |b| b).await.optional()? {
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
            .get_response(url, |b| b.timeout(timeout))
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
            .map_err(Error::Reqwest)
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
            .map_err(Error::Reqwest)
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
    ) -> Result<Option<ExecutionOptimisticResponse<RootData>>, Error> {
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
    ) -> Result<Option<ExecutionOptimisticResponse<Fork>>, Error> {
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
    ) -> Result<Option<ExecutionOptimisticResponse<FinalityCheckpointsData>>, Error> {
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
    ) -> Result<Option<ExecutionOptimisticResponse<Vec<ValidatorBalanceData>>>, Error> {
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

    /// `GET beacon/states/{state_id}/validators?id,status`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_validators(
        &self,
        state_id: StateId,
        ids: Option<&[ValidatorId]>,
        statuses: Option<&[ValidatorStatus]>,
    ) -> Result<Option<ExecutionOptimisticResponse<Vec<ValidatorData>>>, Error> {
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

    /// `GET beacon/states/{state_id}/committees?slot,index,epoch`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_committees(
        &self,
        state_id: StateId,
        slot: Option<Slot>,
        index: Option<u64>,
        epoch: Option<Epoch>,
    ) -> Result<Option<ExecutionOptimisticResponse<Vec<CommitteeData>>>, Error> {
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
    ) -> Result<ExecutionOptimisticResponse<SyncCommitteeByValidatorIndices>, Error> {
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

    /// `GET beacon/states/{state_id}/validators/{validator_id}`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_validator_id(
        &self,
        state_id: StateId,
        validator_id: &ValidatorId,
    ) -> Result<Option<ExecutionOptimisticResponse<ValidatorData>>, Error> {
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

    /// `GET beacon/headers?slot,parent_root`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_headers(
        &self,
        slot: Option<Slot>,
        parent_root: Option<Hash256>,
    ) -> Result<Option<ExecutionOptimisticResponse<Vec<BlockHeaderData>>>, Error> {
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
    ) -> Result<Option<ExecutionOptimisticResponse<BlockHeaderData>>, Error> {
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
    pub async fn post_beacon_blocks<T: EthSpec, Payload: AbstractExecPayload<T>>(
        &self,
        block: &SignedBeaconBlock<T, Payload>,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("blocks");

        self.post_with_timeout(path, block, self.timeouts.proposal)
            .await?;

        Ok(())
    }

    /// `POST beacon/blobs`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn post_beacon_blobs<T: EthSpec>(
        &self,
        block: &BlobsSidecar<T>,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("blobs");

        //FIXME(sean) should we re-use the proposal timeout? seems reasonable to..
        self.post_with_timeout(path, block, self.timeouts.proposal)
            .await?;

        Ok(())
    }

    /// `POST beacon/blinded_blocks`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn post_beacon_blinded_blocks<T: EthSpec, Payload: AbstractExecPayload<T>>(
        &self,
        block: &SignedBeaconBlock<T, Payload>,
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

    /// `GET v2/beacon/blocks`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blocks<T: EthSpec>(
        &self,
        block_id: BlockId,
    ) -> Result<Option<ExecutionOptimisticForkVersionedResponse<SignedBeaconBlock<T>>>, Error> {
        let path = self.get_beacon_blocks_path(block_id)?;
        let response = match self.get_response(path, |b| b).await.optional()? {
            Some(res) => res,
            None => return Ok(None),
        };

        // If present, use the fork provided in the headers to decode the block. Gracefully handle
        // missing and malformed fork names by falling back to regular deserialisation.
        let (block, version, execution_optimistic) = match response.fork_name_from_header() {
            Ok(Some(fork_name)) => {
                let (data, (version, execution_optimistic)) =
                    map_fork_name_with!(fork_name, SignedBeaconBlock, {
                        let ExecutionOptimisticForkVersionedResponse {
                            version,
                            execution_optimistic,
                            data,
                        } = response.json().await?;
                        (data, (version, execution_optimistic))
                    });
                (data, version, execution_optimistic)
            }
            Ok(None) | Err(_) => {
                let ExecutionOptimisticForkVersionedResponse {
                    version,
                    execution_optimistic,
                    data,
                } = response.json().await?;
                (data, version, execution_optimistic)
            }
        };
        Ok(Some(ExecutionOptimisticForkVersionedResponse {
            version,
            execution_optimistic,
            data: block,
        }))
    }

    /// `GET v1/beacon/blocks` (LEGACY)
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blocks_v1<T: EthSpec>(
        &self,
        block_id: BlockId,
    ) -> Result<Option<ForkVersionedResponse<SignedBeaconBlock<T>>>, Error> {
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
    pub async fn get_beacon_blocks_ssz<T: EthSpec>(
        &self,
        block_id: BlockId,
        spec: &ChainSpec,
    ) -> Result<Option<SignedBeaconBlock<T>>, Error> {
        let path = self.get_beacon_blocks_path(block_id)?;

        self.get_bytes_opt_accept_header(path, Accept::Ssz, self.timeouts.get_beacon_blocks_ssz)
            .await?
            .map(|bytes| SignedBeaconBlock::from_ssz_bytes(&bytes, spec).map_err(Error::InvalidSsz))
            .transpose()
    }

    /// `GET beacon/blocks/{block_id}/root`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blocks_root(
        &self,
        block_id: BlockId,
    ) -> Result<Option<ExecutionOptimisticResponse<RootData>>, Error> {
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
    pub async fn get_beacon_blocks_attestations<T: EthSpec>(
        &self,
        block_id: BlockId,
    ) -> Result<Option<ExecutionOptimisticResponse<Vec<Attestation<T>>>>, Error> {
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
    pub async fn post_beacon_pool_attestations<T: EthSpec>(
        &self,
        attestations: &[Attestation<T>],
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
    pub async fn get_beacon_pool_attestations<T: EthSpec>(
        &self,
        slot: Option<Slot>,
        committee_index: Option<u64>,
    ) -> Result<GenericResponse<Vec<Attestation<T>>>, Error> {
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
    pub async fn post_beacon_pool_attester_slashings<T: EthSpec>(
        &self,
        slashing: &AttesterSlashing<T>,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("pool")
            .push("attester_slashings");

        self.post(path, slashing).await?;

        Ok(())
    }

    /// `GET beacon/pool/attester_slashings`
    pub async fn get_beacon_pool_attester_slashings<T: EthSpec>(
        &self,
    ) -> Result<GenericResponse<Vec<AttesterSlashing<T>>>, Error> {
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

    /// `GET beacon/deposit_snapshot`
    pub async fn get_deposit_snapshot(&self) -> Result<Option<types::DepositTreeSnapshot>, Error> {
        use ssz::Decode;
        let mut path = self.eth_path(V1)?;
        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("deposit_snapshot");
        self.get_bytes_opt_accept_header(path, Accept::Ssz, self.timeouts.get_deposit_snapshot)
            .await?
            .map(|bytes| DepositTreeSnapshot::from_ssz_bytes(&bytes).map_err(Error::InvalidSsz))
            .transpose()
    }

    /// `POST validator/contribution_and_proofs`
    pub async fn post_validator_contribution_and_proofs<T: EthSpec>(
        &self,
        signed_contributions: &[SignedContributionAndProof<T>],
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
    pub async fn get_debug_beacon_states<T: EthSpec>(
        &self,
        state_id: StateId,
    ) -> Result<Option<ExecutionOptimisticForkVersionedResponse<BeaconState<T>>>, Error> {
        let path = self.get_debug_beacon_states_path(state_id)?;
        self.get_opt(path).await
    }

    /// `GET v1/debug/beacon/states/{state_id}` (LEGACY)
    pub async fn get_debug_beacon_states_v1<T: EthSpec>(
        &self,
        state_id: StateId,
    ) -> Result<Option<ExecutionOptimisticForkVersionedResponse<BeaconState<T>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("debug")
            .push("beacon")
            .push("states")
            .push(&state_id.to_string());

        self.get_opt(path).await
    }

    /// `GET debug/beacon/states/{state_id}`
    /// `-H "accept: application/octet-stream"`
    pub async fn get_debug_beacon_states_ssz<T: EthSpec>(
        &self,
        state_id: StateId,
        spec: &ChainSpec,
    ) -> Result<Option<BeaconState<T>>, Error> {
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
    pub async fn get_validator_blocks<T: EthSpec, Payload: AbstractExecPayload<T>>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
    ) -> Result<ForkVersionedResponse<BeaconBlock<T, Payload>>, Error> {
        self.get_validator_blocks_modular(slot, randao_reveal, graffiti, SkipRandaoVerification::No)
            .await
    }

    /// `GET v2/validator/blocks/{slot}`
    pub async fn get_validator_blocks_modular<T: EthSpec, Payload: AbstractExecPayload<T>>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
    ) -> Result<ForkVersionedResponse<BeaconBlock<T, Payload>>, Error> {
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

        self.get(path).await
    }

    /// `GET v1/validator/blocks_and_blobs/{slot}`
    pub async fn get_validator_blocks_and_blobs<T: EthSpec, Payload: AbstractExecPayload<T>>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
    ) -> Result<ForkVersionedResponse<BlocksAndBlobs<T, Payload>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("blocks_and_blobs")
            .push(&slot.to_string());

        path.query_pairs_mut()
            .append_pair("randao_reveal", &randao_reveal.to_string());

        if let Some(graffiti) = graffiti {
            path.query_pairs_mut()
                .append_pair("graffiti", &graffiti.to_string());
        }

        self.get(path).await
    }

    /// `GET v2/validator/blinded_blocks/{slot}`
    pub async fn get_validator_blinded_blocks<T: EthSpec, Payload: AbstractExecPayload<T>>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
    ) -> Result<ForkVersionedResponse<BeaconBlock<T, Payload>>, Error> {
        self.get_validator_blinded_blocks_modular(
            slot,
            randao_reveal,
            graffiti,
            SkipRandaoVerification::No,
        )
        .await
    }

    /// `GET v1/validator/blinded_blocks/{slot}`
    pub async fn get_validator_blinded_blocks_modular<
        T: EthSpec,
        Payload: AbstractExecPayload<T>,
    >(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
    ) -> Result<ForkVersionedResponse<BeaconBlock<T, Payload>>, Error> {
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

        self.get(path).await
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
    pub async fn get_validator_aggregate_attestation<T: EthSpec>(
        &self,
        slot: Slot,
        attestation_data_root: Hash256,
    ) -> Result<Option<GenericResponse<Attestation<T>>>, Error> {
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
    pub async fn get_validator_sync_committee_contribution<T: EthSpec>(
        &self,
        sync_committee_data: &SyncContributionData,
    ) -> Result<Option<GenericResponse<SyncCommitteeContribution<T>>>, Error> {
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
    pub async fn post_validator_aggregate_and_proof<T: EthSpec>(
        &self,
        aggregates: &[SignedAggregateAndProof<T>],
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
    pub async fn get_events<T: EthSpec>(
        &self,
        topic: &[EventTopic],
    ) -> Result<impl Stream<Item = Result<EventKind<T>, Error>>, Error> {
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
                Err(e) => Err(Error::Reqwest(e)),
            }))
    }

    /// `POST validator/duties/sync/{epoch}`
    pub async fn post_validator_duties_sync(
        &self,
        epoch: Epoch,
        indices: &[u64],
    ) -> Result<ExecutionOptimisticResponse<Vec<SyncDuty>>, Error> {
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
