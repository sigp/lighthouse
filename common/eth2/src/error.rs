//! Centralized error handling for eth2 API clients
//!
//! This module consolidates all error types, response processing,
//! and recovery logic for both beacon node and validator client APIs.

use pretty_reqwest_error::PrettyReqwestError;
use reqwest::{Response, StatusCode};
use sensitive_url::SensitiveUrl;
use serde::{Deserialize, Serialize};
use std::{fmt, path::PathBuf};

/// Main error type for eth2 API clients
#[derive(Debug)]
pub enum Error {
    /// The `reqwest` client raised an error.
    HttpClient(PrettyReqwestError),
    /// The `reqwest_eventsource` client raised an error.
    SseClient(Box<reqwest_eventsource::Error>),
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

/// An API error serializable to JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorMessage {
    pub code: u16,
    pub message: String,
    #[serde(default)]
    pub stacktraces: Vec<String>,
}

/// An indexed API error serializable to JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IndexedErrorMessage {
    pub code: u16,
    pub message: String,
    pub failures: Vec<Failure>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Failure {
    pub index: u64,
    pub message: String,
}

impl Failure {
    pub fn new(index: usize, message: String) -> Self {
        Self {
            index: index as u64,
            message,
        }
    }
}

/// Server error response variants
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseError {
    Indexed(IndexedErrorMessage),
    Message(ErrorMessage),
}

impl Error {
    /// If the error has a HTTP status code, return it.
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Error::HttpClient(error) => error.inner().status(),
            Error::SseClient(error) => {
                if let reqwest_eventsource::Error::InvalidStatusCode(status, _) = error.as_ref() {
                    Some(*status)
                } else {
                    None
                }
            }
            Error::ServerMessage(msg) => StatusCode::try_from(msg.code).ok(),
            Error::ServerIndexedMessage(msg) => StatusCode::try_from(msg.code).ok(),
            Error::StatusCode(status) => Some(*status),
            Error::InvalidUrl(_) => None,
            Error::InvalidSecret(_) => None,
            Error::InvalidSignatureHeader => None,
            Error::MissingSignatureHeader => None,
            Error::InvalidJson(_) => None,
            Error::InvalidSsz(_) => None,
            Error::InvalidServerSentEvent(_) => None,
            Error::InvalidHeaders(_) => None,
            Error::TokenReadError(..) => None,
            Error::NoServerPubkey | Error::NoToken => None,
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Error::HttpClient(error.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Returns `Ok(response)` if the response is a `200 OK`, `202 ACCEPTED`, or `204 NO_CONTENT`
/// Otherwise, creates an appropriate error message.
pub async fn ok_or_error(response: Response) -> Result<Response, Error> {
    let status = response.status();

    if status == StatusCode::OK
        || status == StatusCode::ACCEPTED
        || status == StatusCode::NO_CONTENT
    {
        Ok(response)
    } else if let Ok(message) = response.json::<ResponseError>().await {
        match message {
            ResponseError::Message(message) => Err(Error::ServerMessage(message)),
            ResponseError::Indexed(indexed) => Err(Error::ServerIndexedMessage(indexed)),
        }
    } else {
        Err(Error::StatusCode(status))
    }
}

/// Returns `Ok(response)` if the response is a success (2xx) response. Otherwise, creates an
/// appropriate error message.
pub async fn success_or_error(response: Response) -> Result<Response, Error> {
    let status = response.status();

    if status.is_success() {
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
