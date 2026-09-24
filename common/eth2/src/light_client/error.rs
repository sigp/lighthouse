use reqwest::StatusCode;
use std::{error::Error, fmt, time::Duration};

/// A bounded request failure without provider-controlled text in its diagnostics.
#[derive(Debug)]
pub struct RequestError {
    pub kind: RequestErrorKind,
    /// The received HTTP status, never a status claimed by the response body.
    pub status: Option<StatusCode>,
    pub retry_after: Option<Duration>,
    /// Locally measured response bytes, including bytes consumed before failure.
    pub bytes_received: u64,
}

pub enum RequestErrorKind {
    InvalidLimits,
    InvalidRange,
    InvalidUrl,
    Http(reqwest::Error),
    Status,
    BodyTooLarge {
        limit: u64,
    },
    Timeout,
    InvalidJson {
        category: serde_json::error::Category,
        line: usize,
        column: usize,
    },
    InvalidRetryAfter,
    InvalidHeaders,
    RuntimeUnavailable,
    Worker(tokio::task::JoinError),
    AllocationFailed,
}

impl RequestError {
    pub(crate) fn new(kind: RequestErrorKind) -> Self {
        Self {
            kind,
            status: None,
            retry_after: None,
            bytes_received: 0,
        }
    }
}

impl fmt::Debug for RequestErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("InvalidLimits"),
            Self::InvalidRange => formatter.write_str("InvalidRange"),
            Self::InvalidUrl => formatter.write_str("InvalidUrl"),
            Self::Http(error) => formatter
                .debug_struct("Http")
                .field("timeout", &error.is_timeout())
                .field("connect", &error.is_connect())
                .field("body", &error.is_body())
                .field("decode", &error.is_decode())
                .finish(),
            Self::Status => formatter.write_str("Status"),
            Self::BodyTooLarge { limit } => formatter
                .debug_struct("BodyTooLarge")
                .field("limit", limit)
                .finish(),
            Self::Timeout => formatter.write_str("Timeout"),
            Self::InvalidJson {
                category,
                line,
                column,
            } => formatter
                .debug_struct("InvalidJson")
                .field("category", category)
                .field("line", line)
                .field("column", column)
                .finish(),
            Self::InvalidRetryAfter => formatter.write_str("InvalidRetryAfter"),
            Self::InvalidHeaders => formatter.write_str("InvalidHeaders"),
            Self::RuntimeUnavailable => formatter.write_str("RuntimeUnavailable"),
            Self::Worker(error) => formatter
                .debug_struct("Worker")
                .field("cancelled", &error.is_cancelled())
                .field("panic", &error.is_panic())
                .finish(),
            Self::AllocationFailed => formatter.write_str("AllocationFailed"),
        }
    }
}

impl fmt::Display for RequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "light-client request failed: {:?}", self.kind)?;
        if let Some(status) = self.status {
            write!(formatter, " (HTTP {status})")?;
        }
        write!(formatter, " after {} response bytes", self.bytes_received)
    }
}

// Do not expose raw HTTP errors or worker panic payloads through an error-chain logger.
impl Error for RequestError {}
