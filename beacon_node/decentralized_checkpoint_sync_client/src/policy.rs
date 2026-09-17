use crate::PolicyError;
use std::time::{Duration, Instant};
use types::light_client::consts::MAX_REQUEST_LIGHT_CLIENT_UPDATES;

/// A non-empty range of committee periods, with a representable exclusive end.
///
/// These are attested periods, not signature periods. Construction only checks arithmetic and
/// the protocol count limit; the caller must also bound the range by its local current period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateRange {
    start_period: u64,
    count: u64,
    end_period: u64,
}

impl UpdateRange {
    pub fn new(start_period: u64, count: u64) -> Result<Self, PolicyError> {
        validate_update_count(count)?;
        let end_period = start_period
            .checked_add(count)
            .ok_or(PolicyError::RangeOverflow {
                start_period,
                count,
            })?;
        Ok(Self {
            start_period,
            count,
            end_period,
        })
    }

    pub fn start_period(self) -> u64 {
        self.start_period
    }

    pub fn count(self) -> u64 {
        self.count
    }

    pub fn end_period(self) -> u64 {
        self.end_period
    }
}

/// Limits for a single request, including reception of its success or error body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLimits {
    timeout: Duration,
    max_response_bytes: u64,
}

impl RequestLimits {
    pub fn new(timeout: Duration, max_response_bytes: u64) -> Result<Self, PolicyError> {
        non_zero_duration(timeout, "request timeout")?;
        non_zero(max_response_bytes, "response byte limit")?;
        Instant::now()
            .checked_add(timeout)
            .ok_or(PolicyError::DeadlineOverflow)?;
        Ok(Self {
            timeout,
            max_response_bytes,
        })
    }

    pub fn timeout(self) -> Duration {
        self.timeout
    }

    pub fn max_response_bytes(self) -> u64 {
        self.max_response_bytes
    }
}

/// Explicit local policy for a single synchronization task.
///
/// Validate after configuring and before starting work. These limits do not enforce themselves:
/// a driver must track cumulative usage and reduce per-request limits to the remaining budget.
/// There is deliberately no default freshness policy or provider-derived notion of "recent".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncPolicy {
    /// Maximum age of the verified checkpoint at return time, measured in local slots.
    /// Zero is valid and requires a header at the current slot; it may be unattainable.
    pub max_finalized_lag_slots: u64,
    pub max_updates_per_request: u64,
    pub request_limits: RequestLimits,
    pub sync_timeout: Duration,
    pub max_requests: u64,
    pub max_updates: u64,
    pub max_total_response_bytes: u64,
    /// Consecutive requests without checkpoint or authenticated committee progress.
    pub max_no_progress_requests: u64,
    /// Maximum retries for one request. Zero disables retries; total requests remain bounded.
    pub max_retries: u64,
    pub initial_retry_delay: Duration,
    pub max_retry_delay: Duration,
}

impl SyncPolicy {
    pub fn validate(&self) -> Result<(), PolicyError> {
        validate_update_count(self.max_updates_per_request)?;
        non_zero_duration(self.sync_timeout, "sync timeout")?;
        non_zero_duration(self.initial_retry_delay, "initial retry delay")?;
        non_zero_duration(self.max_retry_delay, "maximum retry delay")?;
        non_zero(self.max_requests, "request limit")?;
        non_zero(self.max_updates, "update limit")?;
        non_zero(self.max_total_response_bytes, "total response byte limit")?;
        non_zero(self.max_no_progress_requests, "no-progress request limit")?;

        for (ordered, smaller, larger) in [
            (
                self.request_limits.timeout <= self.sync_timeout,
                "request timeout",
                "sync timeout",
            ),
            (
                self.initial_retry_delay <= self.max_retry_delay,
                "initial retry delay",
                "maximum retry delay",
            ),
            (
                self.max_retry_delay <= self.sync_timeout,
                "maximum retry delay",
                "sync timeout",
            ),
            (
                self.max_updates_per_request <= self.max_updates,
                "updates per request",
                "update limit",
            ),
            (
                self.request_limits.max_response_bytes <= self.max_total_response_bytes,
                "response byte limit",
                "total response byte limit",
            ),
            (
                self.max_no_progress_requests <= self.max_requests,
                "no-progress request limit",
                "request limit",
            ),
        ] {
            if !ordered {
                return Err(PolicyError::InconsistentLimits { smaller, larger });
            }
        }
        // Checking Duration alone is insufficient: a later Instant + timeout could still panic.
        self.deadline(Instant::now())?;
        Ok(())
    }

    /// Compute the task deadline without overflowing the platform's monotonic clock.
    pub fn deadline(&self, started_at: Instant) -> Result<Instant, PolicyError> {
        started_at
            .checked_add(self.sync_timeout)
            .ok_or(PolicyError::DeadlineOverflow)
    }
}

fn validate_update_count(count: u64) -> Result<(), PolicyError> {
    non_zero(count, "update count")?;
    if count > MAX_REQUEST_LIGHT_CLIENT_UPDATES {
        return Err(PolicyError::TooManyUpdates {
            count,
            maximum: MAX_REQUEST_LIGHT_CLIENT_UPDATES,
        });
    }
    Ok(())
}

fn non_zero(value: u64, name: &'static str) -> Result<(), PolicyError> {
    if value == 0 {
        return Err(PolicyError::ZeroLimit(name));
    }
    Ok(())
}

fn non_zero_duration(value: Duration, name: &'static str) -> Result<(), PolicyError> {
    if value.is_zero() {
        return Err(PolicyError::ZeroLimit(name));
    }
    Ok(())
}
