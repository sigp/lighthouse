//! HTTP client core functionality.

pub mod constants;
pub mod error;
pub mod timeouts;

pub use constants::*;
pub use error::Error;
pub use timeouts::Timeouts;

use crate::mixin::{RequestAccept, ResponseOptional};
use crate::types::{Accept, EndpointVersion};
use derivative::Derivative;
use futures::Future;
use pretty_reqwest_error::PrettyReqwestError;
use reqwest::{
    header::HeaderMap, Body, IntoUrl, RequestBuilder, Response, StatusCode, Url,
};
use sensitive_url::SensitiveUrl;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt;
use std::time::Duration;

/// HTTP client for interacting with a beacon node API.
#[derive(Clone, Debug, Derivative)]
#[derivative(PartialEq)]
pub struct BeaconNodeHttpClient {
    #[derivative(PartialEq = "ignore")]
    pub(crate) client: reqwest::Client,
    server: SensitiveUrl,
    timeouts: Timeouts,
}

impl Eq for BeaconNodeHttpClient {}

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
    /// Create a new HTTP client for the given server URL with the specified timeouts.
    pub fn new(server: SensitiveUrl, timeouts: Timeouts) -> Self {
        Self {
            client: reqwest::Client::new(),
            server,
            timeouts,
        }
    }

    /// Create a new HTTP client from individual components.
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
    pub fn eth_path(&self, version: EndpointVersion) -> Result<Url, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push(&version.to_string());

        Ok(path)
    }

    /// Get the server URL.
    pub fn server(&self) -> &SensitiveUrl {
        &self.server
    }

    /// Get the timeouts configuration.
    pub fn timeouts(&self) -> &Timeouts {
        &self.timeouts
    }

    /// Perform a HTTP GET request.
    pub async fn get<T: DeserializeOwned, U: IntoUrl>(&self, url: U) -> Result<T, Error> {
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
        self.ok_or_error(response).await
    }

    /// Perform a HTTP GET request with a custom timeout.
    pub async fn get_with_timeout<T: DeserializeOwned, U: IntoUrl>(
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
    pub async fn get_opt<T: DeserializeOwned, U: IntoUrl>(&self, url: U) -> Result<Option<T>, Error> {
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
    pub async fn get_opt_with_timeout<T: DeserializeOwned, U: IntoUrl>(
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

    /// Check if a response is successful or convert it to an error.
    pub async fn ok_or_error(&self, response: Response) -> Result<Response, Error> {
        let status = response.status();

        if status.is_success() {
            Ok(response)
        } else if let Ok(message) = response.json().await {
            match message {
                crate::types::Error::Indexed(indexed_error_message) => {
                    Err(Error::ServerIndexedMessage(indexed_error_message))
                }
                crate::types::Error::Message(error_message) => {
                    Err(Error::ServerMessage(error_message))
                }
            }
        } else {
            Err(Error::StatusCode(status))
        }
    }
}