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
pub mod lighthouse_vc;
pub mod types;

use self::types::*;
use eth2_libp2p::PeerId;
use futures::Stream;
use futures_util::StreamExt;
pub use reqwest;
use reqwest::{IntoUrl, Response};
pub use reqwest::{StatusCode, Url};
use sensitive_url::SensitiveUrl;
use serde::{de::DeserializeOwned, Serialize};
use ssz::Decode;
use std::convert::TryFrom;
use std::fmt;
use std::iter::Iterator;

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
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A wrapper around `reqwest::Client` which provides convenience methods for interfacing with a
/// Lighthouse Beacon Node HTTP server (`http_api`).
#[derive(Clone)]
pub struct BeaconNodeHttpClient {
    client: reqwest::Client,
    server: SensitiveUrl,
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
    pub fn new(server: SensitiveUrl) -> Self {
        Self {
            client: reqwest::Client::new(),
            server,
        }
    }

    pub fn from_components(server: SensitiveUrl, client: reqwest::Client) -> Self {
        Self { client, server }
    }

    /// Return the path with the standard `/eth1/v1` prefix applied.
    fn eth_path(&self) -> Result<Url, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1");

        Ok(path)
    }

    /// Perform a HTTP GET request.
    async fn get<T: DeserializeOwned, U: IntoUrl>(&self, url: U) -> Result<T, Error> {
        let response = self.client.get(url).send().await.map_err(Error::Reqwest)?;
        ok_or_error(response)
            .await?
            .json()
            .await
            .map_err(Error::Reqwest)
    }

    /// Perform a HTTP GET request, returning `None` on a 404 error.
    async fn get_opt<T: DeserializeOwned, U: IntoUrl>(&self, url: U) -> Result<Option<T>, Error> {
        let response = self.client.get(url).send().await.map_err(Error::Reqwest)?;
        match ok_or_error(response).await {
            Ok(resp) => resp.json().await.map(Option::Some).map_err(Error::Reqwest),
            Err(err) => {
                if err.status() == Some(StatusCode::NOT_FOUND) {
                    Ok(None)
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Perform a HTTP GET request using an 'accept' header, returning `None` on a 404 error.
    pub async fn get_bytes_opt_accept_header<U: IntoUrl>(
        &self,
        url: U,
        accept_header: Accept,
    ) -> Result<Option<Vec<u8>>, Error> {
        let response = self
            .client
            .get(url)
            .header(ACCEPT, accept_header.to_string())
            .send()
            .await
            .map_err(Error::Reqwest)?;
        match ok_or_error(response).await {
            Ok(resp) => Ok(Some(
                resp.bytes()
                    .await
                    .map_err(Error::Reqwest)?
                    .into_iter()
                    .collect::<Vec<_>>(),
            )),
            Err(err) => {
                if err.status() == Some(StatusCode::NOT_FOUND) {
                    Ok(None)
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Perform a HTTP POST request.
    async fn post<T: Serialize, U: IntoUrl>(&self, url: U, body: &T) -> Result<(), Error> {
        let response = self
            .client
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(Error::Reqwest)?;
        ok_or_error(response).await?;
        Ok(())
    }

    /// Perform a HTTP POST request, returning a JSON response.
    async fn post_with_response<T: DeserializeOwned, U: IntoUrl, V: Serialize>(
        &self,
        url: U,
        body: &V,
    ) -> Result<T, Error> {
        let response = self
            .client
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(Error::Reqwest)?;
        ok_or_error(response)
            .await?
            .json()
            .await
            .map_err(Error::Reqwest)
    }

    /// `GET beacon/genesis`
    ///
    /// ## Errors
    ///
    /// May return a `404` if beacon chain genesis has not yet occurred.
    pub async fn get_beacon_genesis(&self) -> Result<GenericResponse<GenesisData>, Error> {
        let mut path = self.eth_path()?;

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
    ) -> Result<Option<GenericResponse<RootData>>, Error> {
        let mut path = self.eth_path()?;

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
    ) -> Result<Option<GenericResponse<Fork>>, Error> {
        let mut path = self.eth_path()?;

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
    ) -> Result<Option<GenericResponse<FinalityCheckpointsData>>, Error> {
        let mut path = self.eth_path()?;

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
    ) -> Result<Option<GenericResponse<Vec<ValidatorBalanceData>>>, Error> {
        let mut path = self.eth_path()?;

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
    ) -> Result<Option<GenericResponse<Vec<ValidatorData>>>, Error> {
        let mut path = self.eth_path()?;

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
    ) -> Result<Option<GenericResponse<Vec<CommitteeData>>>, Error> {
        let mut path = self.eth_path()?;

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

    /// `GET beacon/states/{state_id}/validators/{validator_id}`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_validator_id(
        &self,
        state_id: StateId,
        validator_id: &ValidatorId,
    ) -> Result<Option<GenericResponse<ValidatorData>>, Error> {
        let mut path = self.eth_path()?;

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
    ) -> Result<Option<GenericResponse<Vec<BlockHeaderData>>>, Error> {
        let mut path = self.eth_path()?;

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
    ) -> Result<Option<GenericResponse<BlockHeaderData>>, Error> {
        let mut path = self.eth_path()?;

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
    pub async fn post_beacon_blocks<T: EthSpec>(
        &self,
        block: &SignedBeaconBlock<T>,
    ) -> Result<(), Error> {
        let mut path = self.eth_path()?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("blocks");

        self.post(path, block).await?;

        Ok(())
    }

    /// `GET beacon/blocks`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blocks<T: EthSpec>(
        &self,
        block_id: BlockId,
    ) -> Result<Option<GenericResponse<SignedBeaconBlock<T>>>, Error> {
        let mut path = self.eth_path()?;

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
    ) -> Result<Option<SignedBeaconBlock<T>>, Error> {
        let mut path = self.eth_path()?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("blocks")
            .push(&block_id.to_string());

        self.get_bytes_opt_accept_header(path, Accept::Ssz)
            .await?
            .map(|bytes| SignedBeaconBlock::from_ssz_bytes(&bytes).map_err(Error::InvalidSsz))
            .transpose()
    }

    /// `GET beacon/blocks/{block_id}/root`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blocks_root(
        &self,
        block_id: BlockId,
    ) -> Result<Option<GenericResponse<RootData>>, Error> {
        let mut path = self.eth_path()?;

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
    ) -> Result<Option<GenericResponse<Vec<Attestation<T>>>>, Error> {
        let mut path = self.eth_path()?;

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
        let mut path = self.eth_path()?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("pool")
            .push("attestations");

        let response = self
            .client
            .post(path)
            .json(attestations)
            .send()
            .await
            .map_err(Error::Reqwest)?;
        ok_or_indexed_error(response).await?;

        Ok(())
    }

    /// `GET beacon/pool/attestations?slot,committee_index`
    pub async fn get_beacon_pool_attestations<T: EthSpec>(
        &self,
        slot: Option<Slot>,
        committee_index: Option<u64>,
    ) -> Result<GenericResponse<Vec<Attestation<T>>>, Error> {
        let mut path = self.eth_path()?;

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
        let mut path = self.eth_path()?;

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
        let mut path = self.eth_path()?;

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
        let mut path = self.eth_path()?;

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
        let mut path = self.eth_path()?;

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
        let mut path = self.eth_path()?;

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
        let mut path = self.eth_path()?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("beacon")
            .push("pool")
            .push("voluntary_exits");

        self.get(path).await
    }

    /// `GET config/fork_schedule`
    pub async fn get_config_fork_schedule(&self) -> Result<GenericResponse<Vec<Fork>>, Error> {
        let mut path = self.eth_path()?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("config")
            .push("fork_schedule");

        self.get(path).await
    }

    /// `GET config/spec`
    pub async fn get_config_spec(&self) -> Result<GenericResponse<YamlConfig>, Error> {
        let mut path = self.eth_path()?;

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
        let mut path = self.eth_path()?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("config")
            .push("deposit_contract");

        self.get(path).await
    }

    /// `GET node/version`
    pub async fn get_node_version(&self) -> Result<GenericResponse<VersionData>, Error> {
        let mut path = self.eth_path()?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("node")
            .push("version");

        self.get(path).await
    }

    /// `GET node/identity`
    pub async fn get_node_identity(&self) -> Result<GenericResponse<IdentityData>, Error> {
        let mut path = self.eth_path()?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("node")
            .push("identity");

        self.get(path).await
    }

    /// `GET node/syncing`
    pub async fn get_node_syncing(&self) -> Result<GenericResponse<SyncingData>, Error> {
        let mut path = self.eth_path()?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("node")
            .push("syncing");

        self.get(path).await
    }

    /// `GET node/health`
    pub async fn get_node_health(&self) -> Result<StatusCode, Error> {
        let mut path = self.eth_path()?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("node")
            .push("health");

        let status = self
            .client
            .get(path)
            .send()
            .await
            .map_err(Error::Reqwest)?
            .status();
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
        let mut path = self.eth_path()?;

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
        let mut path = self.eth_path()?;

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
        let mut path = self.eth_path()?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("node")
            .push("peer_count");

        self.get(path).await
    }

    /// `GET debug/beacon/states/{state_id}`
    pub async fn get_debug_beacon_states<T: EthSpec>(
        &self,
        state_id: StateId,
    ) -> Result<Option<GenericResponse<BeaconState<T>>>, Error> {
        let mut path = self.eth_path()?;

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
    ) -> Result<Option<BeaconState<T>>, Error> {
        let mut path = self.eth_path()?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("debug")
            .push("beacon")
            .push("states")
            .push(&state_id.to_string());

        self.get_bytes_opt_accept_header(path, Accept::Ssz)
            .await?
            .map(|bytes| BeaconState::from_ssz_bytes(&bytes).map_err(Error::InvalidSsz))
            .transpose()
    }

    /// `GET debug/beacon/heads`
    pub async fn get_debug_beacon_heads(
        &self,
    ) -> Result<GenericResponse<Vec<ChainHeadData>>, Error> {
        let mut path = self.eth_path()?;

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
        let mut path = self.eth_path()?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("duties")
            .push("proposer")
            .push(&epoch.to_string());

        self.get(path).await
    }

    /// `GET validator/blocks/{slot}`
    pub async fn get_validator_blocks<T: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
    ) -> Result<GenericResponse<BeaconBlock<T>>, Error> {
        let mut path = self.eth_path()?;

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

        self.get(path).await
    }

    /// `GET validator/attestation_data?slot,committee_index`
    pub async fn get_validator_attestation_data(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<GenericResponse<AttestationData>, Error> {
        let mut path = self.eth_path()?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("attestation_data");

        path.query_pairs_mut()
            .append_pair("slot", &slot.to_string())
            .append_pair("committee_index", &committee_index.to_string());

        self.get(path).await
    }

    /// `GET validator/attestation_attestation?slot,attestation_data_root`
    pub async fn get_validator_aggregate_attestation<T: EthSpec>(
        &self,
        slot: Slot,
        attestation_data_root: Hash256,
    ) -> Result<Option<GenericResponse<Attestation<T>>>, Error> {
        let mut path = self.eth_path()?;

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

        self.get_opt(path).await
    }

    /// `POST validator/duties/attester/{epoch}`
    pub async fn post_validator_duties_attester(
        &self,
        epoch: Epoch,
        indices: &[u64],
    ) -> Result<DutiesResponse<Vec<AttesterData>>, Error> {
        let mut path = self.eth_path()?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("duties")
            .push("attester")
            .push(&epoch.to_string());

        self.post_with_response(path, &indices).await
    }

    /// `POST validator/aggregate_and_proofs`
    pub async fn post_validator_aggregate_and_proof<T: EthSpec>(
        &self,
        aggregates: &[SignedAggregateAndProof<T>],
    ) -> Result<(), Error> {
        let mut path = self.eth_path()?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("aggregate_and_proofs");

        let response = self
            .client
            .post(path)
            .json(aggregates)
            .send()
            .await
            .map_err(Error::Reqwest)?;
        ok_or_indexed_error(response).await?;

        Ok(())
    }

    /// `POST validator/beacon_committee_subscriptions`
    pub async fn post_validator_beacon_committee_subscriptions(
        &self,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<(), Error> {
        let mut path = self.eth_path()?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("beacon_committee_subscriptions");

        self.post(path, &subscriptions).await?;

        Ok(())
    }

    /// `GET events?topics`
    pub async fn get_events<T: EthSpec>(
        &self,
        topic: &[EventTopic],
    ) -> Result<impl Stream<Item = Result<EventKind<T>, Error>>, Error> {
        let mut path = self.eth_path()?;
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
            .await
            .map_err(Error::Reqwest)?
            .bytes_stream()
            .map(|next| match next {
                Ok(bytes) => EventKind::from_sse_bytes(bytes.as_ref()),
                Err(e) => Err(Error::Reqwest(e)),
            }))
    }
}

/// Returns `Ok(response)` if the response is a `200 OK` response. Otherwise, creates an
/// appropriate error message.
async fn ok_or_error(response: Response) -> Result<Response, Error> {
    let status = response.status();

    if status == StatusCode::OK {
        Ok(response)
    } else if let Ok(message) = response.json().await {
        Err(Error::ServerMessage(message))
    } else {
        Err(Error::StatusCode(status))
    }
}

/// Returns `Ok(response)` if the response is a `200 OK` response. Otherwise, creates an
/// appropriate indexed error message.
async fn ok_or_indexed_error(response: Response) -> Result<Response, Error> {
    let status = response.status();

    if status == StatusCode::OK {
        Ok(response)
    } else if let Ok(message) = response.json().await {
        Err(Error::ServerIndexedMessage(message))
    } else {
        Err(Error::StatusCode(status))
    }
}
