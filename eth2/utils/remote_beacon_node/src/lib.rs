//! Provides a `RemoteBeaconNode` which interacts with a HTTP API on another Lighthouse (or
//! compatible) instance.
//!
//! Presently, this is only used for testing but it _could_ become a user-facing library.

use futures::{Future, IntoFuture};
use reqwest::{
    r#async::{Client, ClientBuilder, Response},
    StatusCode,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use ssz::Encode;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::time::Duration;
use types::{BeaconBlock, BeaconState, EthSpec, Signature};
use types::{Hash256, Slot};
use url::Url;

pub use rest_api::HeadResponse;

pub const REQUEST_TIMEOUT_SECONDS: u64 = 5;

/// Connects to a remote Lighthouse (or compatible) node via HTTP.
pub struct RemoteBeaconNode<E: EthSpec> {
    pub http: HttpClient<E>,
}

impl<E: EthSpec> RemoteBeaconNode<E> {
    pub fn new(http_endpoint: SocketAddr) -> Result<Self, String> {
        Ok(Self {
            http: HttpClient::new(format!("http://{}", http_endpoint.to_string()))
                .map_err(|e| format!("Unable to create http client: {:?}", e))?,
        })
    }
}

#[derive(Debug)]
pub enum Error {
    UrlParseError(url::ParseError),
    ReqwestError(reqwest::Error),
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
    ///
    /// The `timeout` is set to 15 seconds.
    pub fn new(server_url: String) -> Result<Self, Error> {
        Ok(Self {
            client: ClientBuilder::new()
                .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECONDS))
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
            .and_then(|response| response.error_for_status().map_err(Error::from))
            .and_then(|mut success| success.json::<T>().map_err(Error::from))
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum BeaconBlockPublishStatus {
    /// The block was valid and has been published to the network.
    Valid,
    /// The block was not valid and may or may not have been published to the network.
    Invalid(String),
    /// The server responsed with an unknown status code. The block may or may not have been
    /// published to the network.
    Unknown,
}

impl BeaconBlockPublishStatus {
    /// Returns `true` if `*self == BeaconBlockPublishStatus::Valid`.
    pub fn is_valid(&self) -> bool {
        *self == BeaconBlockPublishStatus::Valid
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

    /// Posts a block to the beacon node, expecting it to verify it and publish it to the network.
    pub fn publish_block(
        &self,
        block: BeaconBlock<E>,
    ) -> impl Future<Item = BeaconBlockPublishStatus, Error = Error> {
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
                StatusCode::OK => Ok(BeaconBlockPublishStatus::Valid),
                StatusCode::ACCEPTED => Ok(BeaconBlockPublishStatus::Invalid(text)),
                _ => response
                    .error_for_status()
                    .map_err(Error::from)
                    .map(|_| BeaconBlockPublishStatus::Unknown),
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

    pub fn get_head(&self) -> impl Future<Item = HeadResponse, Error = Error> {
        let client = self.0.clone();
        self.url("head")
            .into_future()
            .and_then(move |url| client.json_get::<HeadResponse>(url, vec![]))
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
