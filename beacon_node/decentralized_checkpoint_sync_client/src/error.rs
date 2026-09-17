use std::time::Duration;
use types::ForkName;

/// Configuration errors, separate from source failures and core verification errors.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("{0} must be non-zero")]
    ZeroLimit(&'static str),
    #[error("update count {count} exceeds request limit {maximum}")]
    TooManyUpdates { count: u64, maximum: u64 },
    #[error("update range overflows: start period {start_period}, count {count}")]
    RangeOverflow { start_period: u64, count: u64 },
    #[error("{smaller} must not exceed {larger}")]
    InconsistentLimits {
        smaller: &'static str,
        larger: &'static str,
    },
    #[error("timeout cannot be represented by the monotonic clock")]
    DeadlineOverflow,
}

/// The source's failure category, not the result of light-client verification.
///
/// Missing data does not prove invalidity. Transient failures may be retried within the caller's
/// budget, whereas invalid data must not be retried as an availability problem. Only transport
/// adapters classify HTTP status codes; core verification errors retain their own type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceErrorKind {
    #[error("requested light-client data is unavailable")]
    Unavailable,
    #[error("temporary source failure (retry after {retry_after:?})")]
    Transient { retry_after: Option<Duration> },
    #[error("malformed light-client response")]
    InvalidData,
    #[error("response exceeds byte limit {limit}")]
    ResponseTooLarge { limit: u64 },
    #[error("unsupported light-client data fork {0}")]
    UnsupportedFork(ForkName),
    #[error("invalid source configuration")]
    Configuration,
}

/// A source failure with accounting even when reception or decoding did not complete.
#[derive(Debug, thiserror::Error)]
#[error("{kind}")]
pub struct SourceError {
    pub kind: SourceErrorKind,
    /// Body bytes received before failure, including error responses. See [`crate::SourceResponse`].
    pub bytes_received: u64,
    /// Optional diagnostic cause. Adapters must redact credentials and not retain unbounded bodies.
    #[source]
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}
