pub use metrics::*;
use std::sync::LazyLock;
use types::EthSpec;

use crate::{ForkChoice, ForkChoiceStore};

pub static FORK_CHOICE_QUEUED_ATTESTATIONS: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "fork_choice_queued_attestations",
        "Current count of queued attestations",
    )
});
pub static FORK_CHOICE_NODES: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge("fork_choice_nodes", "Current count of proto array nodes")
});
pub static FORK_CHOICE_INDICES: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "fork_choice_indices",
        "Current count of proto array indices",
    )
});
pub static FORK_CHOICE_DEQUEUED_ATTESTATIONS: LazyLock<Result<IntCounter>> = LazyLock::new(|| {
    try_create_int_counter(
        "fork_choice_dequeued_attestations_total",
        "Total count of dequeued attestations",
    )
});
pub static FORK_CHOICE_ON_BLOCK_TIMES: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "beacon_fork_choice_process_block_seconds",
        "The duration in seconds of on_block runs",
    )
});
pub static FORK_CHOICE_ON_ATTESTATION_TIMES: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram(
        "beacon_fork_choice_process_attestation_seconds",
        "The duration in seconds of on_attestation runs",
    )
});
pub static FORK_CHOICE_ON_ATTESTER_SLASHING_TIMES: LazyLock<Result<Histogram>> =
    LazyLock::new(|| {
        try_create_histogram(
            "beacon_fork_choice_on_attester_slashing_seconds",
            "The duration in seconds on on_attester_slashing runs",
        )
    });

/// Update the global metrics `DEFAULT_REGISTRY` with info from the fork choice.
pub fn scrape_for_metrics<T: ForkChoiceStore<E>, E: EthSpec>(fork_choice: &ForkChoice<T, E>) {
    set_gauge(
        &FORK_CHOICE_QUEUED_ATTESTATIONS,
        fork_choice.queued_attestations().len() as i64,
    );
    set_gauge(
        &FORK_CHOICE_NODES,
        fork_choice.proto_array().core_proto_array().nodes.len() as i64,
    );
    set_gauge(
        &FORK_CHOICE_INDICES,
        fork_choice.proto_array().core_proto_array().indices.len() as i64,
    );
}
