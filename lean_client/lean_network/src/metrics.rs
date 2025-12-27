pub use metrics::*;
use std::sync::LazyLock;

/* P2P Metrics */
pub static LEAN_P2P_PEERS: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge("lean_p2p_peers", "Total number of connected peers")
});

pub static LEAN_P2P_MESSAGES_RECEIVED_TOTAL: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "lean_p2p_messages_received_total",
        "Total number of gossip messages received",
        &["topic"],
    )
});

pub static LEAN_P2P_MESSAGES_PUBLISHED_TOTAL: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "lean_p2p_messages_published_total",
        "Total number of gossip messages published",
        &["topic"],
    )
});
