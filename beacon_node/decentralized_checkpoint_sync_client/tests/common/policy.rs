use decentralized_checkpoint_sync_client::{RequestLimits, SyncPolicy};
use std::time::Duration;

pub fn policy() -> SyncPolicy {
    SyncPolicy {
        max_finalized_lag_slots: 64,
        max_updates_per_request: 8,
        request_limits: RequestLimits::new(Duration::from_secs(5), 1_024).unwrap(),
        sync_timeout: Duration::from_secs(60),
        max_requests: 32,
        max_updates: 256,
        max_total_response_bytes: 32_768,
        max_no_progress_requests: 4,
        max_retries: 2,
        initial_retry_delay: Duration::from_millis(100),
        max_retry_delay: Duration::from_secs(2),
    }
}
