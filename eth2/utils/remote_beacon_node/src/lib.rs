//! Provides a `RemoteBeaconNode` which interacts with a HTTP API on another Lighthouse (or
//! compatible) instance.
//!
//! Presently, this is only used for testing but it _could_ become a user-facing library.

use eth2_config::Eth2Config;
use futures::{future, Future, IntoFuture};
use reqwest::{
    r#async::{Client, ClientBuilder, Response},
    StatusCode,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use ssz::Encode;
use std::marker::PhantomData;
use std::time::Duration;
use types::{
    Attestation, BeaconBlock, BeaconState, CommitteeIndex, Epoch, EthSpec, Fork, Hash256,
    PublicKey, Signature, Slot,
};
use url::Url;

pub use rest_api::{
    CanonicalHeadResponse, Committee, HeadBeaconBlock, ValidatorDutiesRequest, ValidatorDuty,
    ValidatorRequest, ValidatorResponse,
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

    fn url(&self, path: &str) -> Result<Url, Error> {
        self.url.join(path).map_err(|e| e.into())
    }

    pub fn json_post<T: Serialize>(
        &self,
        url: Url,
        body: T,
    ) -> impl Future<Item = Response, Error = Error> {
        self.client
            .post(&url.to_string())
            .json(&body)
            .send()
            .map_err(Error::from)
    }

    pub fn json_get<T: DeserializeOwned>(
        &self,
        mut url: Url,
        query_pairs: Vec<(String, String)>,
    ) -> impl Future<Item = T, Error = Error> {
        query_pairs.into_iter().for_each(|(key, param)| {
            url.query_pairs_mut().append_pair(&key, &param);
        });

        self.client
            .get(&url.to_string())
            .send()
            .map_err(Error::from)
            .and_then(|response| error_for_status(response).map_err(Error::from))
            .and_then(|mut success| success.json::<T>().map_err(Error::from))
    }
}

/// Returns an `Error` (with a description) if the `response` was not a 200-type success response.
///
/// Distinct from `Response::error_for_status` because it includes the body of the response as
/// text. This ensures the error message from the server is not discarded.
fn error_for_status(
    mut response: Response,
) -> Box<dyn Future<Item = Response, Error = Error> + Send> {
    let status = response.status();

    if status.is_success() {
        Box::new(future::ok(response))
    } else {
        Box::new(response.text().then(move |text_result| match text_result {
            Err(e) => Err(Error::ReqwestError(e)),
            Ok(body) => Err(Error::DidNotSucceed { status, body }),
        }))
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum PublishStatus {
    /// The object was valid and has been published to the network.
    Valid,
    /// The object was not valid and may or may not have been published to the network.
    Invalid(String),
    /// The server responsed with an unknown status code. The object may or may not have been
    /// published to the network.
    Unknown,
}

impl PublishStatus {
    /// Returns `true` if `*self == PublishStatus::Valid`.
    pub fn is_valid(&self) -> bool {
        *self == PublishStatus::Valid
    }
}

/// Provides the functions on the `/beacon` endpoint of the node.
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
    pub fn produce_attestation(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> impl Future<Item = Attestation<E>, Error = Error> {
        let query_params = vec![
            ("slot".into(), format!("{}", slot)),
            ("committee_index".into(), format!("{}", committee_index)),
        ];

        let client = self.0.clone();
        self.url("attestation")
            .into_future()
            .and_then(move |url| client.json_get(url, query_params))
    }

    /// Posts an attestation to the beacon node, expecting it to verify it and publish it to the network.
    pub fn publish_attestation(
        &self,
        attestation: Attestation<E>,
    ) -> impl Future<Item = PublishStatus, Error = Error> {
        let client = self.0.clone();
        self.url("attestation")
            .into_future()
            .and_then(move |url| client.json_post::<_>(url, attestation))
            .and_then(|mut response| {
                response
                    .text()
                    .map(|text| (response, text))
                    .map_err(Error::from)
            })
            .and_then(|(response, text)| match response.status() {
                StatusCode::OK => Ok(PublishStatus::Valid),
                StatusCode::ACCEPTED => Ok(PublishStatus::Invalid(text)),
                _ => response
                    .error_for_status()
                    .map_err(Error::from)
                    .map(|_| PublishStatus::Unknown),
            })
    }

    /// Returns the duties required of the given validator pubkeys in the given epoch.
    pub fn get_duties(
        &self,
        epoch: Epoch,
        validator_pubkeys: &[PublicKey],
    ) -> impl Future<Item = Vec<ValidatorDuty>, Error = Error> {
        let client = self.0.clone();

        let bulk_request = ValidatorDutiesRequest {
            epoch,
            pubkeys: validator_pubkeys
                .iter()
                .map(|pubkey| pubkey.clone().into())
                .collect(),
        };

        self.url("duties")
            .into_future()
            .and_then(move |url| client.json_post::<_>(url, bulk_request))
            .and_then(|response| error_for_status(response).map_err(Error::from))
            .and_then(|mut success| success.json().map_err(Error::from))
    }

    /// Posts a block to the beacon node, expecting it to verify it and publish it to the network.
    pub fn publish_block(
        &self,
        block: BeaconBlock<E>,
    ) -> impl Future<Item = PublishStatus, Error = Error> {
        let client = self.0.clone();
        self.url("block")
            .into_future()
            .and_then(move |url| client.json_post::<_>(url, block))
            .and_then(|mut response| {
                response
                    .text()
                    .map(|text| (response, text))
                    .map_err(Error::from)
            })
            .and_then(|(response, text)| match response.status() {
                StatusCode::OK => Ok(PublishStatus::Valid),
                StatusCode::ACCEPTED => Ok(PublishStatus::Invalid(text)),
                _ => response
                    .error_for_status()
                    .map_err(Error::from)
                    .map(|_| PublishStatus::Unknown),
            })
    }

    /// Requests a new (unsigned) block from the beacon node.
    pub fn produce_block(
        &self,
        slot: Slot,
        randao_reveal: Signature,
    ) -> impl Future<Item = BeaconBlock<E>, Error = Error> {
        let client = self.0.clone();
        self.url("block").into_future().and_then(move |url| {
            client.json_get::<BeaconBlock<E>>(
                url,
                vec![
                    ("slot".into(), format!("{}", slot.as_u64())),
                    ("randao_reveal".into(), signature_as_string(&randao_reveal)),
                ],
            )
        })
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
    pub fn get_genesis_time(&self) -> impl Future<Item = u64, Error = Error> {
        let client = self.0.clone();
        self.url("genesis_time")
            .into_future()
            .and_then(move |url| client.json_get(url, vec![]))
    }

    /// Returns the fork at the head of the beacon chain.
    pub fn get_fork(&self) -> impl Future<Item = Fork, Error = Error> {
        let client = self.0.clone();
        self.url("fork")
            .into_future()
            .and_then(move |url| client.json_get(url, vec![]))
    }

    /// Returns info about the head of the canonical beacon chain.
    pub fn get_head(&self) -> impl Future<Item = CanonicalHeadResponse, Error = Error> {
        let client = self.0.clone();
        self.url("head")
            .into_future()
            .and_then(move |url| client.json_get::<CanonicalHeadResponse>(url, vec![]))
    }

    /// Returns the set of known beacon chain head blocks. One of these will be the canonical head.
    pub fn get_heads(&self) -> impl Future<Item = Vec<HeadBeaconBlock>, Error = Error> {
        let client = self.0.clone();
        self.url("heads")
            .into_future()
            .and_then(move |url| client.json_get(url, vec![]))
    }

    /// Returns the block and block root at the given slot.
    pub fn get_block_by_slot(
        &self,
        slot: Slot,
    ) -> impl Future<Item = (BeaconBlock<E>, Hash256), Error = Error> {
        self.get_block("slot".to_string(), format!("{}", slot.as_u64()))
    }

    /// Returns the block and block root at the given root.
    pub fn get_block_by_root(
        &self,
        root: Hash256,
    ) -> impl Future<Item = (BeaconBlock<E>, Hash256), Error = Error> {
        self.get_block("root".to_string(), root_as_string(root))
    }

    /// Returns the block and block root at the given slot.
    fn get_block(
        &self,
        query_key: String,
        query_param: String,
    ) -> impl Future<Item = (BeaconBlock<E>, Hash256), Error = Error> {
        let client = self.0.clone();
        self.url("block")
            .into_future()
            .and_then(move |url| {
                client.json_get::<BlockResponse<E>>(url, vec![(query_key, query_param)])
            })
            .map(|response| (response.beacon_block, response.root))
    }

    /// Returns the state and state root at the given slot.
    pub fn get_state_by_slot(
        &self,
        slot: Slot,
    ) -> impl Future<Item = (BeaconState<E>, Hash256), Error = Error> {
        self.get_state("slot".to_string(), format!("{}", slot.as_u64()))
    }

    /// Returns the state and state root at the given root.
    pub fn get_state_by_root(
        &self,
        root: Hash256,
    ) -> impl Future<Item = (BeaconState<E>, Hash256), Error = Error> {
        self.get_state("root".to_string(), root_as_string(root))
    }

    /// Returns the root of the state at the given slot.
    pub fn get_state_root(&self, slot: Slot) -> impl Future<Item = Hash256, Error = Error> {
        let client = self.0.clone();
        self.url("state_root").into_future().and_then(move |url| {
            client.json_get(url, vec![("slot".into(), format!("{}", slot.as_u64()))])
        })
    }

    /// Returns the root of the block at the given slot.
    pub fn get_block_root(&self, slot: Slot) -> impl Future<Item = Hash256, Error = Error> {
        let client = self.0.clone();
        self.url("block_root").into_future().and_then(move |url| {
            client.json_get(url, vec![("slot".into(), format!("{}", slot.as_u64()))])
        })
    }

    /// Returns the state and state root at the given slot.
    fn get_state(
        &self,
        query_key: String,
        query_param: String,
    ) -> impl Future<Item = (BeaconState<E>, Hash256), Error = Error> {
        let client = self.0.clone();
        self.url("state")
            .into_future()
            .and_then(move |url| {
                client.json_get::<StateResponse<E>>(url, vec![(query_key, query_param)])
            })
            .map(|response| (response.beacon_state, response.root))
    }

    /// Returns the block and block root at the given slot.
    ///
    /// If `state_root` is `Some`, the query will use the given state instead of the default
    /// canonical head state.
    pub fn get_validators(
        &self,
        validator_pubkeys: Vec<PublicKey>,
        state_root: Option<Hash256>,
    ) -> impl Future<Item = Vec<ValidatorResponse>, Error = Error> {
        let client = self.0.clone();

        let bulk_request = ValidatorRequest {
            state_root,
            pubkeys: validator_pubkeys
                .iter()
                .map(|pubkey| pubkey.clone().into())
                .collect(),
        };

        self.url("validators")
            .into_future()
            .and_then(move |url| client.json_post::<_>(url, bulk_request))
            .and_then(|response| error_for_status(response).map_err(Error::from))
            .and_then(|mut success| success.json().map_err(Error::from))
    }

    /// Returns all validators.
    ///
    /// If `state_root` is `Some`, the query will use the given state instead of the default
    /// canonical head state.
    pub fn get_all_validators(
        &self,
        state_root: Option<Hash256>,
    ) -> impl Future<Item = Vec<ValidatorResponse>, Error = Error> {
        let client = self.0.clone();

        let query_params = if let Some(state_root) = state_root {
            vec![("state_root".into(), root_as_string(state_root))]
        } else {
            vec![]
        };

        self.url("validators/all")
            .into_future()
            .and_then(move |url| client.json_get(url, query_params))
    }

    /// Returns the active validators.
    ///
    /// If `state_root` is `Some`, the query will use the given state instead of the default
    /// canonical head state.
    pub fn get_active_validators(
        &self,
        state_root: Option<Hash256>,
    ) -> impl Future<Item = Vec<ValidatorResponse>, Error = Error> {
        let client = self.0.clone();

        let query_params = if let Some(state_root) = state_root {
            vec![("state_root".into(), root_as_string(state_root))]
        } else {
            vec![]
        };

        self.url("validators/active")
            .into_future()
            .and_then(move |url| client.json_get(url, query_params))
    }

    /// Returns committees at the given epoch.
    pub fn get_committees(
        &self,
        epoch: Epoch,
    ) -> impl Future<Item = Vec<Committee>, Error = Error> {
        let client = self.0.clone();

        self.url("committees").into_future().and_then(move |url| {
            client.json_get(url, vec![("epoch".into(), format!("{}", epoch.as_u64()))])
        })
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

    pub fn get_eth2_config(&self) -> impl Future<Item = Eth2Config, Error = Error> {
        let client = self.0.clone();
        self.url("eth2_config")
            .into_future()
            .and_then(move |url| client.json_get(url, vec![]))
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

    pub fn get_version(&self) -> impl Future<Item = String, Error = Error> {
        let client = self.0.clone();
        self.url("version")
            .into_future()
            .and_then(move |url| client.json_get(url, vec![]))
    }
}

#[derive(Deserialize)]
#[serde(bound = "T: EthSpec")]
pub struct BlockResponse<T: EthSpec> {
    pub beacon_block: BeaconBlock<T>,
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

fn signature_as_string(signature: &Signature) -> String {
    format!("0x{}", hex::encode(signature.as_ssz_bytes()))
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
