//! Provides a `RemoteBeaconNode` which interacts with a HTTP API on another Lighthouse (or
//! compatible) instance.
//!
//! Presently, this is only used for testing but it _could_ become a user-facing library.

use futures::{Future, IntoFuture};
use reqwest::r#async::{Client, RequestBuilder};
use serde::Deserialize;
use std::marker::PhantomData;
use std::net::SocketAddr;
use types::{BeaconBlock, BeaconState, EthSpec};
use types::{Hash256, Slot};
use url::Url;

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
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> HttpClient<E> {
    /// Creates a new instance (without connecting to the node).
    pub fn new(server_url: String) -> Result<Self, Error> {
        Ok(Self {
            client: Client::new(),
            url: Url::parse(&server_url)?,
            _phantom: PhantomData,
        })
    }

    pub fn beacon(&self) -> Beacon<E> {
        Beacon(self.clone())
    }

    fn url(&self, path: &str) -> Result<Url, Error> {
        self.url.join(path).map_err(|e| e.into())
    }

    pub fn get(&self, path: &str) -> Result<RequestBuilder, Error> {
        self.url(path)
            .map(|url| Client::new().get(&url.to_string()))
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

    /// Returns the block and block root at the given slot.
    pub fn block_at_slot(
        &self,
        slot: Slot,
    ) -> impl Future<Item = (BeaconBlock<E>, Hash256), Error = Error> {
        let client = self.0.clone();
        self.url("block")
            .into_future()
            .and_then(move |mut url| {
                url.query_pairs_mut()
                    .append_pair("slot", &format!("{}", slot.as_u64()));
                client.get(&url.to_string())
            })
            .and_then(|builder| builder.send().map_err(Error::from))
            .and_then(|response| response.error_for_status().map_err(Error::from))
            .and_then(|mut success| success.json::<BlockResponse<E>>().map_err(Error::from))
            .map(|response| (response.beacon_block, response.root))
    }

    /// Returns the state and state root at the given slot.
    pub fn state_at_slot(
        &self,
        slot: Slot,
    ) -> impl Future<Item = (BeaconState<E>, Hash256), Error = Error> {
        let client = self.0.clone();
        self.url("state")
            .into_future()
            .and_then(move |mut url| {
                url.query_pairs_mut()
                    .append_pair("slot", &format!("{}", slot.as_u64()));
                client.get(&url.to_string())
            })
            .and_then(|builder| builder.send().map_err(Error::from))
            .and_then(|response| response.error_for_status().map_err(Error::from))
            .and_then(|mut success| success.json::<StateResponse<E>>().map_err(Error::from))
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
