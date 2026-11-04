pub use metrics::*;
use std::sync::LazyLock;

pub static BUILDER_BID_STREAM_HANDSHAKES: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "beacon_builder_bid_stream_handshakes_total",
        "Count of builder bid stream connection attempts, by handshake outcome",
        &["outcome"],
    )
});

pub static BUILDER_BID_STREAMS_ACTIVE: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "beacon_builder_bid_streams_active",
        "Number of builder bid stream connections currently open",
    )
});

pub static BUILDER_BID_STREAM_FRAMES: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "beacon_builder_bid_stream_frames_total",
        "Count of messages received on builder bid streams, by outcome",
        &["outcome"],
    )
});

pub static BUILDER_BID_SOURCE: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "beacon_builder_bid_source_total",
        "Count of direct builder bids that passed validation at block production, by source",
        &["source"],
    )
});

pub static BUILDER_BID_STREAM_FALLBACKS: LazyLock<Result<IntCounterVec>> = LazyLock::new(|| {
    try_create_int_counter_vec(
        "beacon_builder_bid_stream_fallbacks_total",
        "Count of builder entries without a usable stream bid at block production while bid \
         streams are enabled, by reason",
        &["reason"],
    )
});

pub static BUILDER_BID_STREAM_BID_AGE: LazyLock<Result<Histogram>> = LazyLock::new(|| {
    try_create_histogram_with_buckets(
        "beacon_builder_bid_stream_bid_age_seconds",
        "Time between receiving a streamed builder bid and the bid passing validation at block \
         production",
        Ok(vec![
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 12.0,
        ]),
    )
});
