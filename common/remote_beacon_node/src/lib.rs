//! Provides a `RemoteBeaconNode` which interacts with a HTTP API on another Lighthouse (or
//! compatible) instance.
//!
//! Presently, this is only used for testing but it _could_ become a user-facing library.

use eth2_config::Eth2Config;
use reqwest::{Client, ClientBuilder, Response, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use ssz::Encode;
use std::marker::PhantomData;
use std::time::Duration;
use types::{
    Attestation, AttestationData, AttesterSlashing, BeaconBlock, BeaconState, CommitteeIndex,
    Epoch, EthSpec, Fork, Hash256, ProposerSlashing, PublicKey, PublicKeyBytes, Signature,
    SignedAggregateAndProof, SignedBeaconBlock, Slot, SubnetId,
};
use url::Url;

pub use operation_pool::PersistedOperationPool;
pub use proto_array::core::ProtoArray;
pub use rest_types::{
    CanonicalHeadResponse, Committee, HeadBeaconBlock, Health, IndividualVotesRequest,
    IndividualVotesResponse, SyncingResponse, ValidatorDutiesRequest, ValidatorDutyBytes,
    ValidatorRequest, ValidatorResponse, ValidatorSubscription,
};

// Setting a long timeout for debug ensures that crypto-heavy operations can still succeed.
#[cfg(debug_assertions)]
pub const REQUEST_TIMEOUT_SECONDS: u64 = 15;

#[cfg(not(debug_assertions))]
pub const REQUEST_TIMEOUT_SECONDS: u64 = 5;

#[derive(Clone)]
/// Connects to a remote Lighthouse (or compatible) node via HTTP.
pub struct RemoteBeaconNode<E: EthSpec> {
    pub http: HttpClient<E>,
}

impl<E: EthSpec> RemoteBeaconNode<E> {
    /// Uses the default HTTP timeout.
    pub fn new(http_endpoint: String) -> Result<Self, String> {
        Self::new_with_timeout(http_endpoint, Duration::from_secs(REQUEST_TIMEOUT_SECONDS))
    }

    pub fn new_with_timeout(http_endpoint: String, timeout: Duration) -> Result<Self, String> {
        Ok(Self {
            http: HttpClient::new(http_endpoint, timeout)
                .map_err(|e| format!("Unable to create http client: {:?}", e))?,
        })
    }
}

#[derive(Debug)]
pub enum Error {
    /// Unable to parse a URL. Check the server URL.
    UrlParseError(url::ParseError),
    /// The `reqwest` library returned an error.
    ReqwestError(reqwest::Error),
    /// There was an error when encoding/decoding an object using serde.
    SerdeJsonError(serde_json::Error),
    /// The server responded to the request, however it did not return a 200-type success code.
    DidNotSucceed { status: StatusCode, body: String },
    /// The request input was invalid.
    InvalidInput,
}

#[derive(Clone)]
pub struct HttpClient<E> {
    client: Client,
    url: Url,
    timeout: Duration,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> HttpClient<E> {
    /// Creates a new instance (without connecting to the node).
    pub fn new(server_url: String, timeout: Duration) -> Result<Self, Error> {
        Ok(Self {
            client: ClientBuilder::new()
                .timeout(timeout)
                .build()
                .expect("should build from static configuration"),
            url: Url::parse(&server_url)?,
            timeout: Duration::from_secs(15),
            _phantom: PhantomData,
        })
    }

    pub fn beacon(&self) -> Beacon<E> {
        Beacon(self.clone())
    }

    pub fn validator(&self) -> Validator<E> {
        Validator(self.clone())
    }

    pub fn spec(&self) -> Spec<E> {
        Spec(self.clone())
    }

    pub fn node(&self) -> Node<E> {
        Node(self.clone())
    }

    pub fn advanced(&self) -> Advanced<E> {
        Advanced(self.clone())
    }

    pub fn consensus(&self) -> Consensus<E> {
        Consensus(self.clone())
    }

    fn url(&self, path: &str) -> Result<Url, Error> {
        self.url.join(path).map_err(|e| e.into())
    }

    pub async fn json_post<T: Serialize>(&self, url: Url, body: T) -> Result<Response, Error> {
        self.client
            .post(&url.to_string())
            .json(&body)
            .send()
            .await
            .map_err(Error::from)
    }

    pub async fn json_get<T: DeserializeOwned>(
        &self,
        mut url: Url,
        query_pairs: Vec<(String, String)>,
    ) -> Result<T, Error> {
        query_pairs.into_iter().for_each(|(key, param)| {
            url.query_pairs_mut().append_pair(&key, &param);
        });

        let response = self
            .client
            .get(&url.to_string())
            .send()
            .await
            .map_err(Error::from)?;

        let success = error_for_status(response).await.map_err(Error::from)?;
        success.json::<T>().await.map_err(Error::from)
    }
}

/// Returns an `Error` (with a description) if the `response` was not a 200-type success response.
///
/// Distinct from `Response::error_for_status` because it includes the body of the response as
/// text. This ensures the error message from the server is not discarded.
async fn error_for_status(response: Response) -> Result<Response, Error> {
    let status = response.status();

    if status.is_success() {
        return Ok(response);
    } else {
        let text_result = response.text().await;
        match text_result {
            Err(e) => Err(Error::ReqwestError(e)),
            Ok(body) => Err(Error::DidNotSucceed { status, body }),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum PublishStatus {
    /// The object was valid and has been published to the network.
    Valid,
    /// The object was not valid and may or may not have been published to the network.
    Invalid(String),
    /// The server responded with an unknown status code. The object may or may not have been
    /// published to the network.
    Unknown,
}

impl PublishStatus {
    /// Returns `true` if `*self == PublishStatus::Valid`.
    pub fn is_valid(&self) -> bool {
        *self == PublishStatus::Valid
    }
}

/// Provides the functions on the `/validator` endpoint of the node.
#[derive(Clone)]
pub struct Validator<E>(HttpClient<E>);

impl<E: EthSpec> Validator<E> {
    fn url(&self, path: &str) -> Result<Url, Error> {
        self.0
            .url("validator/")
            .and_then(move |url| url.join(path).map_err(Error::from))
            .map_err(Into::into)
    }

    /// Produces an unsigned attestation.
    pub async fn produce_attestation(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<Attestation<E>, Error> {
        let query_params = vec![
            ("slot".into(), format!("{}", slot)),
            ("committee_index".into(), format!("{}", committee_index)),
        ];

        let client = self.0.clone();
        let url = self.url("attestation")?;
        client.json_get(url, query_params).await
    }

    /// Produces an aggregate attestation.
    pub async fn produce_aggregate_attestation(
        &self,
        attestation_data: &AttestationData,
    ) -> Result<Attestation<E>, Error> {
        let query_params = vec![(
            "attestation_data".into(),
            as_ssz_hex_string(attestation_data),
        )];

        let client = self.0.clone();
        let url = self.url("aggregate_attestation")?;
        client.json_get(url, query_params).await
    }

    /// Posts a list of attestations to the beacon node, expecting it to verify it and publish it to the network.
    pub async fn publish_attestations(
        &self,
        attestation: Vec<(Attestation<E>, SubnetId)>,
    ) -> Result<PublishStatus, Error> {
        let client = self.0.clone();
        let url = self.url("attestations")?;
        let response = client.json_post::<_>(url, attestation).await?;

        match response.status() {
            StatusCode::OK => Ok(PublishStatus::Valid),
            StatusCode::ACCEPTED => Ok(PublishStatus::Invalid(
                response.text().await.map_err(Error::from)?,
            )),
            _ => response
                .error_for_status()
                .map_err(Error::from)
                .map(|_| PublishStatus::Unknown),
        }
    }

    /// Posts a list of signed aggregates and proofs to the beacon node, expecting it to verify it and publish it to the network.
    pub async fn publish_aggregate_and_proof(
        &self,
        signed_aggregate_and_proofs: Vec<SignedAggregateAndProof<E>>,
    ) -> Result<PublishStatus, Error> {
        let client = self.0.clone();
        let url = self.url("aggregate_and_proofs")?;
        let response = client
            .json_post::<_>(url, signed_aggregate_and_proofs)
            .await?;

        match response.status() {
            StatusCode::OK => Ok(PublishStatus::Valid),
            StatusCode::ACCEPTED => Ok(PublishStatus::Invalid(
                response.text().await.map_err(Error::from)?,
            )),
            _ => response
                .error_for_status()
                .map_err(Error::from)
                .map(|_| PublishStatus::Unknown),
        }
    }

    /// Returns the duties required of the given validator pubkeys in the given epoch.
    pub async fn get_duties(
        &self,
        epoch: Epoch,
        validator_pubkeys: &[PublicKey],
    ) -> Result<Vec<ValidatorDutyBytes>, Error> {
        let client = self.0.clone();

        let bulk_request = ValidatorDutiesRequest {
            epoch,
            pubkeys: validator_pubkeys
                .iter()
                .map(|pubkey| pubkey.clone().into())
                .collect(),
        };

        let url = self.url("duties")?;
        let response = client.json_post::<_>(url, bulk_request).await?;
        let success = error_for_status(response).await.map_err(Error::from)?;
        success.json().await.map_err(Error::from)
    }

    /// Posts a block to the beacon node, expecting it to verify it and publish it to the network.
    pub async fn publish_block(&self, block: SignedBeaconBlock<E>) -> Result<PublishStatus, Error> {
        let client = self.0.clone();
        let url = self.url("block")?;
        let response = client.json_post::<_>(url, block).await?;

        match response.status() {
            StatusCode::OK => Ok(PublishStatus::Valid),
            StatusCode::ACCEPTED => Ok(PublishStatus::Invalid(
                response.text().await.map_err(Error::from)?,
            )),
            _ => response
                .error_for_status()
                .map_err(Error::from)
                .map(|_| PublishStatus::Unknown),
        }
    }

    /// Requests a new (unsigned) block from the beacon node.
    pub async fn produce_block(
        &self,
        slot: Slot,
        randao_reveal: Signature,
    ) -> Result<BeaconBlock<E>, Error> {
        let client = self.0.clone();
        let url = self.url("block")?;
        client
            .json_get::<BeaconBlock<E>>(
                url,
                vec![
                    ("slot".into(), format!("{}", slot.as_u64())),
                    ("randao_reveal".into(), as_ssz_hex_string(&randao_reveal)),
                ],
            )
            .await
    }

    /// Subscribes a list of validators to particular slots for attestation production/publication.
    pub async fn subscribe(
        &self,
        subscriptions: Vec<ValidatorSubscription>,
    ) -> Result<PublishStatus, Error> {
        let client = self.0.clone();
        let url = self.url("subscribe")?;
        let response = client.json_post::<_>(url, subscriptions).await?;

        match response.status() {
            StatusCode::OK => Ok(PublishStatus::Valid),
            StatusCode::ACCEPTED => Ok(PublishStatus::Invalid(
                response.text().await.map_err(Error::from)?,
            )),
            _ => response
                .error_for_status()
                .map_err(Error::from)
                .map(|_| PublishStatus::Unknown),
        }
    }
}

/// Provides the functions on the `/beacon` endpoint of the node.
#[derive(Clone)]
pub struct Beacon<E>(HttpClient<E>);

impl<E: EthSpec> Beacon<E> {
    fn url(&self, path: &str) -> Result<Url, Error> {
        self.0
            .url("beacon/")
            .and_then(move |url| url.join(path).map_err(Error::from))
            .map_err(Into::into)
    }

    /// Returns the genesis time.
    pub async fn get_genesis_time(&self) -> Result<u64, Error> {
        let client = self.0.clone();
        let url = self.url("genesis_time")?;
        client.json_get(url, vec![]).await
    }

    /// Returns the genesis validators root.
    pub async fn get_genesis_validators_root(&self) -> Result<Hash256, Error> {
        let client = self.0.clone();
        let url = self.url("genesis_validators_root")?;
        client.json_get(url, vec![]).await
    }

    /// Returns the fork at the head of the beacon chain.
    pub async fn get_fork(&self) -> Result<Fork, Error> {
        let client = self.0.clone();
        let url = self.url("fork")?;
        client.json_get(url, vec![]).await
    }

    /// Returns info about the head of the canonical beacon chain.
    pub async fn get_head(&self) -> Result<CanonicalHeadResponse, Error> {
        let client = self.0.clone();
        let url = self.url("head")?;
        client.json_get::<CanonicalHeadResponse>(url, vec![]).await
    }

    /// Returns the set of known beacon chain head blocks. One of these will be the canonical head.
    pub async fn get_heads(&self) -> Result<Vec<HeadBeaconBlock>, Error> {
        let client = self.0.clone();
        let url = self.url("heads")?;
        client.json_get(url, vec![]).await
    }

    /// Returns the block and block root at the given slot.
    pub async fn get_block_by_slot(
        &self,
        slot: Slot,
    ) -> Result<(SignedBeaconBlock<E>, Hash256), Error> {
        self.get_block("slot".to_string(), format!("{}", slot.as_u64()))
            .await
    }

    /// Returns the block and block root at the given root.
    pub async fn get_block_by_root(
        &self,
        root: Hash256,
    ) -> Result<(SignedBeaconBlock<E>, Hash256), Error> {
        self.get_block("root".to_string(), root_as_string(root))
            .await
    }

    /// Returns the block and block root at the given slot.
    async fn get_block(
        &self,
        query_key: String,
        query_param: String,
    ) -> Result<(SignedBeaconBlock<E>, Hash256), Error> {
        let client = self.0.clone();
        let url = self.url("block")?;
        client
            .json_get::<BlockResponse<E>>(url, vec![(query_key, query_param)])
            .await
            .map(|response| (response.beacon_block, response.root))
    }

    /// Returns the state and state root at the given slot.
    pub async fn get_state_by_slot(&self, slot: Slot) -> Result<(BeaconState<E>, Hash256), Error> {
        self.get_state("slot".to_string(), format!("{}", slot.as_u64()))
            .await
    }

    /// Returns the state and state root at the given root.
    pub async fn get_state_by_root(
        &self,
        root: Hash256,
    ) -> Result<(BeaconState<E>, Hash256), Error> {
        self.get_state("root".to_string(), root_as_string(root))
            .await
    }

    /// Returns the root of the state at the given slot.
    pub async fn get_state_root(&self, slot: Slot) -> Result<Hash256, Error> {
        let client = self.0.clone();
        let url = self.url("state_root")?;
        client
            .json_get(url, vec![("slot".into(), format!("{}", slot.as_u64()))])
            .await
    }

    /// Returns the root of the block at the given slot.
    pub async fn get_block_root(&self, slot: Slot) -> Result<Hash256, Error> {
        let client = self.0.clone();
        let url = self.url("block_root")?;
        client
            .json_get(url, vec![("slot".into(), format!("{}", slot.as_u64()))])
            .await
    }

    /// Returns the state and state root at the given slot.
    async fn get_state(
        &self,
        query_key: String,
        query_param: String,
    ) -> Result<(BeaconState<E>, Hash256), Error> {
        let client = self.0.clone();
        let url = self.url("state")?;
        client
            .json_get::<StateResponse<E>>(url, vec![(query_key, query_param)])
            .await
            .map(|response| (response.beacon_state, response.root))
    }

    /// Returns the block and block root at the given slot.
    ///
    /// If `state_root` is `Some`, the query will use the given state instead of the default
    /// canonical head state.
    pub async fn get_validators(
        &self,
        validator_pubkeys: Vec<PublicKey>,
        state_root: Option<Hash256>,
    ) -> Result<Vec<ValidatorResponse>, Error> {
        let client = self.0.clone();

        let bulk_request = ValidatorRequest {
            state_root,
            pubkeys: validator_pubkeys
                .iter()
                .map(|pubkey| pubkey.clone().into())
                .collect(),
        };

        let url = self.url("validators")?;
        let response = client.json_post::<_>(url, bulk_request).await?;
        let success = error_for_status(response).await.map_err(Error::from)?;
        success.json().await.map_err(Error::from)
    }

    /// Returns all validators.
    ///
    /// If `state_root` is `Some`, the query will use the given state instead of the default
    /// canonical head state.
    pub async fn get_all_validators(
        &self,
        state_root: Option<Hash256>,
    ) -> Result<Vec<ValidatorResponse>, Error> {
        let client = self.0.clone();

        let query_params = if let Some(state_root) = state_root {
            vec![("state_root".into(), root_as_string(state_root))]
        } else {
            vec![]
        };

        let url = self.url("validators/all")?;
        client.json_get(url, query_params).await
    }

    /// Returns the active validators.
    ///
    /// If `state_root` is `Some`, the query will use the given state instead of the default
    /// canonical head state.
    pub async fn get_active_validators(
        &self,
        state_root: Option<Hash256>,
    ) -> Result<Vec<ValidatorResponse>, Error> {
        let client = self.0.clone();

        let query_params = if let Some(state_root) = state_root {
            vec![("state_root".into(), root_as_string(state_root))]
        } else {
            vec![]
        };

        let url = self.url("validators/active")?;
        client.json_get(url, query_params).await
    }

    /// Returns committees at the given epoch.
    pub async fn get_committees(&self, epoch: Epoch) -> Result<Vec<Committee>, Error> {
        let client = self.0.clone();

        let url = self.url("committees")?;
        client
            .json_get(url, vec![("epoch".into(), format!("{}", epoch.as_u64()))])
            .await
    }

    pub async fn proposer_slashing(
        &self,
        proposer_slashing: ProposerSlashing,
    ) -> Result<bool, Error> {
        let client = self.0.clone();

        let url = self.url("proposer_slashing")?;
        let response = client.json_post::<_>(url, proposer_slashing).await?;
        let success = error_for_status(response).await.map_err(Error::from)?;
        success.json().await.map_err(Error::from)
    }

    pub async fn attester_slashing(
        &self,
        attester_slashing: AttesterSlashing<E>,
    ) -> Result<bool, Error> {
        let client = self.0.clone();

        let url = self.url("attester_slashing")?;
        let response = client.json_post::<_>(url, attester_slashing).await?;
        let success = error_for_status(response).await.map_err(Error::from)?;
        success.json().await.map_err(Error::from)
    }
}

/// Provides the functions on the `/spec` endpoint of the node.
#[derive(Clone)]
pub struct Spec<E>(HttpClient<E>);

impl<E: EthSpec> Spec<E> {
    fn url(&self, path: &str) -> Result<Url, Error> {
        self.0
            .url("spec/")
            .and_then(move |url| url.join(path).map_err(Error::from))
            .map_err(Into::into)
    }

    pub async fn get_eth2_config(&self) -> Result<Eth2Config, Error> {
        let client = self.0.clone();
        let url = self.url("eth2_config")?;
        client.json_get(url, vec![]).await
    }
}

/// Provides the functions on the `/node` endpoint of the node.
#[derive(Clone)]
pub struct Node<E>(HttpClient<E>);

impl<E: EthSpec> Node<E> {
    fn url(&self, path: &str) -> Result<Url, Error> {
        self.0
            .url("node/")
            .and_then(move |url| url.join(path).map_err(Error::from))
            .map_err(Into::into)
    }

    pub async fn get_version(&self) -> Result<String, Error> {
        let client = self.0.clone();
        let url = self.url("version")?;
        client.json_get(url, vec![]).await
    }

    pub async fn get_health(&self) -> Result<Health, Error> {
        let client = self.0.clone();
        let url = self.url("health")?;
        client.json_get(url, vec![]).await
    }

    pub async fn syncing_status(&self) -> Result<SyncingResponse, Error> {
        let client = self.0.clone();
        let url = self.url("syncing")?;
        client.json_get(url, vec![]).await
    }
}

/// Provides the functions on the `/advanced` endpoint of the node.
#[derive(Clone)]
pub struct Advanced<E>(HttpClient<E>);

impl<E: EthSpec> Advanced<E> {
    fn url(&self, path: &str) -> Result<Url, Error> {
        self.0
            .url("advanced/")
            .and_then(move |url| url.join(path).map_err(Error::from))
            .map_err(Into::into)
    }

    /// Gets the core `ProtoArray` struct from the node.
    pub async fn get_fork_choice(&self) -> Result<ProtoArray, Error> {
        let client = self.0.clone();
        let url = self.url("fork_choice")?;
        client.json_get(url, vec![]).await
    }

    /// Gets the core `PersistedOperationPool` struct from the node.
    pub async fn get_operation_pool(&self) -> Result<PersistedOperationPool<E>, Error> {
        let client = self.0.clone();
        let url = self.url("operation_pool")?;
        client.json_get(url, vec![]).await
    }
}

/// Provides the functions on the `/consensus` endpoint of the node.
#[derive(Clone)]
pub struct Consensus<E>(HttpClient<E>);

impl<E: EthSpec> Consensus<E> {
    fn url(&self, path: &str) -> Result<Url, Error> {
        self.0
            .url("consensus/")
            .and_then(move |url| url.join(path).map_err(Error::from))
            .map_err(Into::into)
    }

    /// Gets a `IndividualVote` for each of the given `pubkeys`.
    pub async fn get_individual_votes(
        &self,
        epoch: Epoch,
        pubkeys: Vec<PublicKeyBytes>,
    ) -> Result<IndividualVotesResponse, Error> {
        let client = self.0.clone();
        let req_body = IndividualVotesRequest { epoch, pubkeys };

        let url = self.url("individual_votes")?;
        let response = client.json_post::<_>(url, req_body).await?;
        let success = error_for_status(response).await.map_err(Error::from)?;
        success.json().await.map_err(Error::from)
    }

    /// Gets a `VoteCount` for the given `epoch`.
    pub async fn get_vote_count(&self, epoch: Epoch) -> Result<IndividualVotesResponse, Error> {
        let client = self.0.clone();
        let query_params = vec![("epoch".into(), format!("{}", epoch.as_u64()))];
        let url = self.url("vote_count")?;
        client.json_get(url, query_params).await
    }
}

#[derive(Deserialize)]
#[serde(bound = "T: EthSpec")]
pub struct BlockResponse<T: EthSpec> {
    pub beacon_block: SignedBeaconBlock<T>,
    pub root: Hash256,
}

#[derive(Deserialize)]
#[serde(bound = "T: EthSpec")]
pub struct StateResponse<T: EthSpec> {
    pub beacon_state: BeaconState<T>,
    pub root: Hash256,
}

fn root_as_string(root: Hash256) -> String {
    format!("0x{:?}", root)
}

fn as_ssz_hex_string<T: Encode>(item: &T) -> String {
    format!("0x{}", hex::encode(item.as_ssz_bytes()))
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Error {
        Error::ReqwestError(e)
    }
}

impl From<url::ParseError> for Error {
    fn from(e: url::ParseError) -> Error {
        Error::UrlParseError(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::SerdeJsonError(e)
    }
}
