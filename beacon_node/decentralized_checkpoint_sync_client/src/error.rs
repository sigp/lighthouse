use decentralized_checkpoint_sync::LightClientSyncError;
use std::time::Duration;
use types::{ForkName, Slot};

/// Acquisition failures retain the source and core verification error boundaries.
#[derive(Debug, thiserror::Error)]
pub enum ConsumerError {
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Source(#[from] SourceError),
    #[error(transparent)]
    Verification(#[from] LightClientSyncError),
    #[error(transparent)]
    Range(#[from] UpdateRangeError),
    #[error("slots per epoch and epochs per sync committee period must be non-zero")]
    InvalidPeriodConfiguration,
    #[error("store finalized slot {store_slot} exceeds local current slot {current_slot}")]
    FutureStore {
        store_slot: Slot,
        current_slot: Slot,
    },
    #[error("current slot is unavailable from the local clock")]
    ClockUnavailable,
    #[error("local clock moved backwards from slot {previous} to {current}")]
    ClockWentBackwards { previous: Slot, current: Slot },
    #[error("bootstrap slot {bootstrap_slot} exceeds local current slot {current_slot}")]
    FutureBootstrap {
        bootstrap_slot: Slot,
        current_slot: Slot,
    },
    #[error("light-client verification requires a Tokio runtime: {0}")]
    RuntimeUnavailable(#[from] tokio::runtime::TryCurrentError),
    #[error("light-client verification worker failed: {0}")]
    Worker(#[from] tokio::task::JoinError),
}

/// Compatibility name for bootstrap callers; all consumer steps share the same error boundary.
pub type BootstrapError = ConsumerError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncBudget {
    Requests,
    Updates,
    ResponseBytes,
}

/// Whole-task termination, distinct from a source's transport or core verification failure.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error(transparent)]
    Consumer(#[from] ConsumerError),
    #[error("synchronization {resource:?} limit exhausted ({limit})")]
    BudgetExceeded { resource: SyncBudget, limit: u64 },
    #[error("synchronization deadline exhausted")]
    DeadlineExceeded,
    #[error("no authenticated progress after {requests} consecutive requests")]
    NoProgress { requests: u64 },
    #[error("light-client request exhausted retries after {attempts} attempts: {source}")]
    RetriesExhausted {
        attempts: u64,
        #[source]
        source: SourceError,
    },
    #[error("required retry delay {requested:?} exceeds local maximum {maximum:?}")]
    RetryDelayExceeded {
        requested: Duration,
        maximum: Duration,
    },
}

/// Range-envelope errors are distinct from cryptographic verification failures.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum UpdateRangeError {
    #[error("received {actual} updates, requested at most {maximum}")]
    TooManyUpdates { actual: usize, maximum: u64 },
    #[error("attested period {period} is outside requested range [{start}, {end})")]
    OutsideRange { period: u64, start: u64, end: u64 },
    /// A provider may only retain later history. This is missing data, not proof of invalidity.
    #[error("needed period {expected} is unavailable; response starts at {actual}")]
    MissingStartPeriod { expected: u64, actual: u64 },
    #[error("non-consecutive update periods: expected {expected}, received {actual}")]
    NonConsecutivePeriods { expected: u64, actual: u64 },
}

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
    /// A local runtime, worker or allocation failure, not evidence about the provider's data.
    #[error("local source execution failed")]
    LocalFailure,
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
