pub use metrics::*;
use std::sync::LazyLock;

/* Block Processing Metrics (shared names with beacon node / Zeam) */
pub static BLOCK_PROCESSING_DURATION_SECONDS: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "block_processing_duration_seconds",
        "Time taken to process a block in the state transition function.",
    )
});

pub static CHAIN_ONBLOCK_DURATION_SECONDS: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "chain_onblock_duration_seconds",
        "Time taken to process a block in the chain's onBlock function.",
    )
});

pub static LEAN_PQ_SIGNATURE_ATTESTATION_SIGNING_TIME: LazyLock<Result<Histogram>> =
    LazyLock::new(|| {
        try_create_histogram(
            "lean_pq_signature_attestation_signing_time_seconds",
            "Time taken to sign an attestation",
        )
    });

pub static LEAN_PQ_SIGNATURE_ATTESTATION_VERIFICATION_TIME: LazyLock<Result<Histogram>> =
    LazyLock::new(|| {
        try_create_histogram(
            "lean_pq_signature_attestation_verification_time_seconds",
            "Time taken to verify an attestation signature",
        )
    });

/* Chain Status Metrics */
pub static LEAN_HEAD_SLOT: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge("lean_head_slot", "Slot of the head block")
});

pub static LEAN_LATEST_JUSTIFIED_SLOT: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge("lean_latest_justified_slot", "Slot of the latest justified checkpoint")
});

pub static LEAN_LATEST_FINALIZED_SLOT: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge("lean_latest_finalized_slot", "Slot of the latest finalized checkpoint")
});

pub static LEAN_LATEST_SAFE_SLOT: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge("lean_latest_safe_slot", "Slot of the latest safe target checkpoint")
});


pub static LEAN_VALIDATORS_COUNT: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge("lean_validators_count", "Total number of active validators")
});

/* Fork Choice Metrics */
pub static LEAN_FORK_CHOICE_BLOCK_PROCESSING_TIME: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "lean_fork_choice_block_processing_time_seconds",
        "Time taken to process a block in fork choice",
    )
});

/* Attestation Metrics */
pub static LEAN_ATTESTATIONS_VALID_TOTAL: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "lean_attestations_valid_total",
        "Total number of valid attestations processed",
    )
});

#[allow(dead_code)]
pub static LEAN_ATTESTATIONS_INVALID_TOTAL: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "lean_attestations_invalid_total",
        "Total number of invalid attestations processed",
    )
});

pub static LEAN_ATTESTATION_VALIDATION_TIME: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "lean_attestation_validation_time_seconds",
        "Time taken to validate an attestation",
    )
});

/* State Transition Metrics */
pub static LEAN_STATE_TRANSITION_TIME: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "lean_state_transition_time_seconds",
        "Total time taken for state transition",
    )
});

pub static LEAN_STATE_TRANSITION_BLOCK_PROCESSING_TIME: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "lean_state_transition_block_processing_time_seconds",
        "Time taken to process block in state transition",
    )
});

pub static LEAN_STATE_TRANSITION_SLOTS_PROCESSED_TOTAL: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "lean_state_transition_slots_processed_total",
        "Total number of slots processed in state transition",
    )
});

pub static LEAN_STATE_TRANSITION_SLOTS_PROCESSING_TIME: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "lean_state_transition_slots_processing_time_seconds",
        "Time taken to process slots in state transition",
    )
});

pub static LEAN_STATE_TRANSITION_ATTESTATIONS_PROCESSED_TOTAL: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "lean_state_transition_attestations_processed_total",
        "Total number of attestations processed in state transition",
    )
});

#[allow(dead_code)]
pub static LEAN_STATE_TRANSITION_ATTESTATIONS_PROCESSING_TIME: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "lean_state_transition_attestations_processing_time_seconds",
        "Time taken to process attestations in state transition",
    )
});

/// Initialize all validator service metrics so they are registered in the
/// Prometheus registry even before they are first used.
///
/// This ensures metrics expected by the Zeam Grafana dashboards are always
/// present (with zero values) on the Lighthouse lean client endpoint.
pub fn init() {
    // PQ signature metrics
    let _ = LEAN_PQ_SIGNATURE_ATTESTATION_SIGNING_TIME.as_ref();
    let _ = LEAN_PQ_SIGNATURE_ATTESTATION_VERIFICATION_TIME.as_ref();

    // Chain status metrics
    let _ = LEAN_HEAD_SLOT.as_ref();
    let _ = LEAN_LATEST_JUSTIFIED_SLOT.as_ref();
    let _ = LEAN_LATEST_FINALIZED_SLOT.as_ref();
    let _ = LEAN_LATEST_SAFE_SLOT.as_ref();
    let _ = LEAN_VALIDATORS_COUNT.as_ref();

    // Fork choice metrics
    let _ = LEAN_FORK_CHOICE_BLOCK_PROCESSING_TIME.as_ref();

    // Attestation metrics
    let _ = LEAN_ATTESTATIONS_VALID_TOTAL.as_ref();
    let _ = LEAN_ATTESTATIONS_INVALID_TOTAL.as_ref();
    let _ = LEAN_ATTESTATION_VALIDATION_TIME.as_ref();

    // State transition metrics
    let _ = LEAN_STATE_TRANSITION_TIME.as_ref();
    let _ = LEAN_STATE_TRANSITION_BLOCK_PROCESSING_TIME.as_ref();
    let _ = LEAN_STATE_TRANSITION_SLOTS_PROCESSED_TOTAL.as_ref();
    let _ = LEAN_STATE_TRANSITION_SLOTS_PROCESSING_TIME.as_ref();
    let _ = LEAN_STATE_TRANSITION_ATTESTATIONS_PROCESSED_TOTAL.as_ref();
    let _ = LEAN_STATE_TRANSITION_ATTESTATIONS_PROCESSING_TIME.as_ref();

    // Shared Zeam / beacon-node style block processing metrics
    let _ = BLOCK_PROCESSING_DURATION_SECONDS.as_ref();
    let _ = CHAIN_ONBLOCK_DURATION_SECONDS.as_ref();
}

