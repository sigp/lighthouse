//! The error type for the Gloas [`BuilderHttpClient`](crate::BuilderHttpClient), aligned with the
//! Builder API spec (`builder-specs`).
//!
//! This is deliberately separate from `eth2::Error` (the beacon-node API client's error), which
//! carries beacon-node concerns irrelevant to a builder — API tokens, impostor-signature headers,
//! server-sent events — and collapses every builder-spec status (204 no-bid, 401 auth failed,
//! 406/415 negotiation) into an opaque status code. The pre-Gloas builder client still uses
//! `eth2::Error`.

use eth2::types::{BuilderUrlError, ErrorMessage};
use pretty_reqwest_error::PrettyReqwestError;
use reqwest::{Response, StatusCode};
use sensitive_url::SensitiveUrl;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// A transport-level failure sending the request or reading the response.
    Reqwest(PrettyReqwestError),
    /// A builder URL could not be turned into a request URL.
    InvalidUrl(SensitiveUrl),
    /// A `BuilderUrl` supplied in config did not parse as a URL.
    InvalidBuilderUrl(BuilderUrlError),
    /// The builder returned an error response with a parseable `{code, message}` body (the
    /// builder-specs `ErrorMessage`), e.g. 400 invalid request or 401 authentication failed.
    ServerMessage(ErrorMessage),
    /// The builder returned a non-success status whose body could not be parsed.
    StatusCode(StatusCode),
    /// The builder's JSON response could not be decoded.
    InvalidJson(serde_json::Error),
    /// The builder's SSZ response could not be decoded.
    InvalidSsz(ssz::DecodeError),
    /// Request headers could not be constructed.
    InvalidHeaders(String),
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Error::Reqwest(error.into())
    }
}

impl From<BuilderUrlError> for Error {
    fn from(error: BuilderUrlError) -> Self {
        Error::InvalidBuilderUrl(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Reqwest(e) => write!(f, "HTTP transport error: {e}"),
            Error::InvalidUrl(url) => write!(f, "invalid builder URL: {url:?}"),
            Error::InvalidBuilderUrl(e) => write!(f, "invalid builder URL: {e:?}"),
            Error::ServerMessage(m) => {
                write!(f, "builder returned error {}: {}", m.code, m.message)
            }
            Error::StatusCode(status) => write!(f, "builder returned unexpected status {status}"),
            Error::InvalidJson(e) => write!(f, "invalid JSON response: {e}"),
            Error::InvalidSsz(e) => write!(f, "invalid SSZ response: {e:?}"),
            Error::InvalidHeaders(e) => write!(f, "invalid response headers: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// Returns `Ok(response)` for a builder success status (200/202/204), otherwise parses the body
/// into an [`Error`]. Mirrors `eth2::ok_or_error` but produces the builder-spec [`Error`].
pub async fn ok_or_error(response: Response) -> Result<Response, Error> {
    let status = response.status();
    if matches!(
        status,
        StatusCode::OK | StatusCode::ACCEPTED | StatusCode::NO_CONTENT
    ) {
        Ok(response)
    } else if let Ok(message) = response.json::<ErrorMessage>().await {
        Err(Error::ServerMessage(message))
    } else {
        Err(Error::StatusCode(status))
    }
}

/// Like [`ok_or_error`] but accepts any 2xx status as success.
pub async fn success_or_error(response: Response) -> Result<Response, Error> {
    let status = response.status();
    if status.is_success() {
        Ok(response)
    } else if let Ok(message) = response.json::<ErrorMessage>().await {
        Err(Error::ServerMessage(message))
    } else {
        Err(Error::StatusCode(status))
    }
}
