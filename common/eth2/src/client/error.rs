//! HTTP client error types and implementations.

use pretty_reqwest_error::PrettyReqwestError;
use reqwest::StatusCode;
use sensitive_url::SensitiveUrl;
use std::fmt;
use std::path::PathBuf;

use crate::types::{ErrorMessage, IndexedErrorMessage};

#[derive(Debug)]
pub enum Error {
    /// The `reqwest` client raised an error.
    HttpClient(PrettyReqwestError),
    /// The `reqwest_eventsource` client raised an error.
    SseClient(reqwest_eventsource::Error),
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

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Error::HttpClient(error.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::HttpClient(error) => write!(f, "HTTP client error: {}", error),
            Error::SseClient(error) => write!(f, "Server-sent events error: {}", error),
            Error::ServerMessage(msg) => write!(f, "Server error: {}", msg.message),
            Error::ServerIndexedMessage(msg) => write!(f, "Server error: {}", msg.message),
            Error::StatusCode(status) => write!(f, "HTTP error: {}", status),
            Error::InvalidUrl(url) => write!(f, "Invalid URL: {}", url),
            Error::InvalidSecret(_) => write!(f, "Invalid validator client secret"),
            Error::InvalidSignatureHeader => write!(f, "Invalid signature header"),
            Error::MissingSignatureHeader => write!(f, "Missing signature header"),
            Error::InvalidJson(error) => write!(f, "Invalid JSON: {}", error),
            Error::InvalidServerSentEvent(msg) => write!(f, "Invalid server-sent event: {}", msg),
            Error::InvalidHeaders(msg) => write!(f, "Invalid response headers: {}", msg),
            Error::InvalidSsz(error) => write!(f, "Invalid SSZ: {:?}", error),
            Error::TokenReadError(path, error) => write!(f, "Token read error at {}: {}", path.display(), error),
            Error::NoServerPubkey => write!(f, "No server public key configured"),
            Error::NoToken => write!(f, "No API token configured"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::SseClient(error) => Some(error),
            Error::InvalidJson(error) => Some(error),
            Error::TokenReadError(_, error) => Some(error),
            _ => None,
        }
    }
}

impl Error {
    /// If the error has a HTTP status code, return it.
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Error::HttpClient(error) => error.inner().status(),
            Error::SseClient(reqwest_eventsource::Error::InvalidStatusCode(status, _)) => {
                Some(*status)
            }
            Error::StatusCode(status) => Some(*status),
            _ => None,
        }
    }
}