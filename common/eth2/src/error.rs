//! Centralized error handling for eth2 API clients
//!
//! This module consolidates all error types, response processing,
//! and recovery logic for both beacon node and validator client APIs.

use pretty_reqwest_error::PrettyReqwestError;
use reqwest::{Response, StatusCode};
use sensitive_url::SensitiveUrl;
use serde::{Deserialize, Serialize};
use std::{fmt, path::PathBuf, time::Duration};

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

/// A single failure in an index of API errors, serializable to JSON.
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

// === Error Classification and Recovery Logic ===

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

    /// Whether this error indicates a retryable condition
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::HttpClient(_) => true,
            Error::SseClient(_) => true,
            Error::StatusCode(status) => status.is_server_error() || *status == StatusCode::TOO_MANY_REQUESTS,
            Error::ServerMessage(msg) => {
                if let Ok(status) = StatusCode::try_from(msg.code) {
                    status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS
                } else {
                    false
                }
            }
            Error::ServerIndexedMessage(msg) => {
                if let Ok(status) = StatusCode::try_from(msg.code) {
                    status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Suggested backoff duration for retry
    pub fn suggested_backoff(&self) -> Option<Duration> {
        if !self.is_retryable() {
            return None;
        }

        match self.status() {
            Some(StatusCode::TOO_MANY_REQUESTS) => Some(Duration::from_secs(30)),
            Some(status) if status.is_server_error() => Some(Duration::from_secs(5)),
            _ => Some(Duration::from_secs(2)),
        }
    }

    /// Whether this is a 404 Not Found error
    pub fn is_not_found(&self) -> bool {
        self.status() == Some(StatusCode::NOT_FOUND)
    }
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Error::HttpClient(error.into())
    }
}

impl From<ssz::DecodeError> for Error {
    fn from(error: ssz::DecodeError) -> Self {
        Error::InvalidSsz(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Error::InvalidJson(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::HttpClient(error) => write!(f, "HTTP client error: {}", error),
            Error::SseClient(error) => write!(f, "SSE client error: {}", error),
            Error::ServerMessage(msg) => write!(f, "Server error {}: {}", msg.code, msg.message),
            Error::ServerIndexedMessage(msg) => {
                write!(f, "Server error {}: {} ({} failures)", msg.code, msg.message, msg.failures.len())
            }
            Error::StatusCode(status) => write!(f, "HTTP status error: {}", status),
            Error::InvalidUrl(url) => write!(f, "Invalid URL: {}", url),
            Error::InvalidSecret(_) => write!(f, "Invalid authentication secret"),
            Error::InvalidSignatureHeader => write!(f, "Invalid signature header"),
            Error::MissingSignatureHeader => write!(f, "Missing signature header"),
            Error::InvalidJson(error) => write!(f, "JSON parsing error: {}", error),
            Error::InvalidServerSentEvent(event) => write!(f, "Invalid server-sent event: {}", event),
            Error::InvalidHeaders(details) => write!(f, "Invalid response headers: {}", details),
            Error::InvalidSsz(error) => write!(f, "SSZ decoding error: {:?}", error),
            Error::TokenReadError(path, error) => write!(f, "Token read error from {}: {}", path.display(), error),
            Error::NoServerPubkey => write!(f, "Server public key required but not configured"),
            Error::NoToken => write!(f, "Authentication token required but not configured"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::SseClient(error) => Some(error.as_ref()),
            Error::InvalidJson(error) => Some(error),
            Error::TokenReadError(_, error) => Some(error),
            _ => None,
        }
    }
}

// === Response Processing ===

/// Centralized response processing for different API types
pub struct ResponseProcessor;

impl ResponseProcessor {
    /// Process beacon node API response (accepts 200 OK only)
    pub async fn process_beacon_response(response: Response) -> Result<Response, Error> {
        Self::process_response(response, &[StatusCode::OK]).await
    }

    /// Process validator client API response (accepts 200, 202, 204)
    pub async fn process_validator_response(response: Response) -> Result<Response, Error> {
        Self::process_response(
            response,
            &[StatusCode::OK, StatusCode::ACCEPTED, StatusCode::NO_CONTENT]
        ).await
    }

    async fn process_response(
        response: Response,
        success_codes: &[StatusCode],
    ) -> Result<Response, Error> {
        let status = response.status();

        if success_codes.contains(&status) {
            Ok(response)
        } else if let Ok(message) = response.json().await {
            match message {
                ResponseError::Message(msg) => Err(Error::ServerMessage(msg)),
                ResponseError::Indexed(msg) => Err(Error::ServerIndexedMessage(msg)),
            }
        } else {
            Err(Error::StatusCode(status))
        }
    }
}

/// Returns `Ok(response)` if the response is a `200 OK` response. Otherwise, creates an
/// appropriate error message.
pub async fn ok_or_error(response: Response) -> Result<Response, Error> {
    ResponseProcessor::process_beacon_response(response).await
}

/// Returns `Ok(response)` if the response is a `200 OK`, `202 Accepted`, or `204 No Content` response.
/// Otherwise, creates an appropriate error message.
pub async fn ok_or_error_validator(response: Response) -> Result<Response, Error> {
    ResponseProcessor::process_validator_response(response).await
}

// === Trait for Optional Responses ===

/// Trait for converting a 404 error into an `Option<Response>`.
pub trait ResponseOptional<T> {
    fn optional(self) -> Result<Option<T>, Error>;
}

impl ResponseOptional<Response> for Result<Response, Error> {
    fn optional(self) -> Result<Option<Response>, Error> {
        match self {
            Ok(response) => Ok(Some(response)),
            Err(error) if error.is_not_found() => Ok(None),
            Err(error) => Err(error),
        }
    }
}
