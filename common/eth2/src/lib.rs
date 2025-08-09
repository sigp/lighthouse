//! This crate provides two major things:
//!
//! 1. The types served by the `http_api` crate.
//! 2. A wrapper around `reqwest` that forms a HTTP client, able of consuming the endpoints served
//!    by the `http_api` crate.
//!
//! Eventually it would be ideal to publish this crate on crates.io, however we have some local
//! dependencies preventing this presently.

// Core modules
pub mod client;
pub mod endpoints;
pub mod mixin;
pub mod types;

// Feature-gated modules
#[cfg(feature = "lighthouse")]
pub mod lighthouse;
#[cfg(feature = "lighthouse")]
pub mod lighthouse_vc;

// Re-exports for convenience
pub use client::{BeaconNodeHttpClient, Error, Timeouts};
pub use client::constants::*;
pub use types::*;

// External re-exports
pub use reqwest;
pub use reqwest::{StatusCode, Url};
pub use sensitive_url::{SensitiveError, SensitiveUrl};

// Import necessary items for the remaining implementation
use self::mixin::{RequestAccept, ResponseOptional};
use self::types::{Error as ResponseError, *};
use ::types::fork_versioned_response::ExecutionOptimisticFinalizedForkVersionedResponse;
use derivative::Derivative;
use either::Either;
use futures::Stream;
use futures_util::StreamExt;
use libp2p_identity::PeerId;
use pretty_reqwest_error::PrettyReqwestError;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Body, IntoUrl, RequestBuilder, Response,
};
use reqwest_eventsource::{Event, EventSource};
use serde::{de::DeserializeOwned, Serialize};
use ssz::Encode;
use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

/// Convert a `reqwest::Response` to either a success response or a structured error.
pub async fn ok_or_error(response: Response) -> Result<Response, Error> {
    let status = response.status();

    if status.is_success() {
        Ok(response)
    } else if let Ok(message) = response.json().await {
        match message {
            types::Error::Indexed(indexed_error_message) => {
                Err(Error::ServerIndexedMessage(indexed_error_message))
            }
            types::Error::Message(error_message) => Err(Error::ServerMessage(error_message)),
        }
    } else {
        Err(Error::StatusCode(status))
    }
}

// TODO: The remaining implementation from the original lib.rs needs to be moved to appropriate endpoint modules
// This is a large task that requires careful migration of each endpoint method to its respective module
// For now, this provides the modular structure foundation

impl BeaconNodeHttpClient {
    // POST methods
    pub(crate) async fn post<T: Serialize, U: IntoUrl>(&self, url: U, body: &T) -> Result<(), Error> {
        self.post_generic(url, body, None).await?;
        Ok(())
    }

    pub(crate) async fn post_with_response<T: Serialize, U: IntoUrl, R: DeserializeOwned>(
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

    pub(crate) async fn post_with_opt_response<T: Serialize, U: IntoUrl, R: DeserializeOwned>(
        &self,
        url: U,
        body: &T,
    ) -> Result<Option<R>, Error> {
        if let Some(response) = self.post_generic(url, body, None).await.optional()? {
            response.json().await.map(Some).map_err(Into::into)
        } else {
            Ok(None)
        }
    }

    pub(crate) async fn post_with_timeout<T: Serialize, U: IntoUrl>(
        &self,
        url: U,
        body: &T,
        timeout: Duration,
    ) -> Result<(), Error> {
        self.post_generic(url, body, Some(timeout)).await?;
        Ok(())
    }

    pub(crate) async fn post_with_timeout_and_response<T: Serialize, U: IntoUrl, R: DeserializeOwned>(
        &self,
        url: U,
        body: &T,
        timeout: Duration,
    ) -> Result<R, Error> {
        self.post_generic(url, body, Some(timeout))
            .await?
            .json()
            .await
            .map_err(Into::into)
    }

    /// Perform a HTTP POST request with a custom timeout and consensus header.
    pub(crate) async fn post_with_timeout_and_consensus_header<T: Serialize, U: IntoUrl>(
        &self,
        url: U,
        body: &T,
        timeout: Duration,
        fork_name: ForkName,
    ) -> Result<(), Error> {
        self.post_generic_with_consensus_version(url, body, Some(timeout), fork_name)
            .await?;
        Ok(())
    }

    /// Generic POST function supporting arbitrary responses and timeouts.
    pub(crate) async fn post_generic<T: Serialize, U: IntoUrl>(
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
    pub(crate) async fn post_generic_with_consensus_version<T: Serialize, U: IntoUrl>(
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

    /// Generic POST function that includes octet-stream content type header.
    pub(crate) async fn post_generic_with_ssz_header<T: Serialize, U: IntoUrl>(
        &self,
        url: U,
        body: &T,
    ) -> Result<Response, Error> {
        let builder = self.client.post(url);
        let mut headers = HeaderMap::new();

        headers.insert(
            "Content-Type",
            HeaderValue::from_static("application/octet-stream"),
        );
        let response = builder.headers(headers).json(body).send().await?;
        ok_or_error(response).await
    }

    /// Generic POST function supporting arbitrary responses and timeouts.
    pub(crate) async fn post_generic_with_consensus_version_and_ssz_body<T: Into<Body>, U: IntoUrl>(
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
}