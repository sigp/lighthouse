use metrics::*;
use std::sync::LazyLock;

pub static NAT_OPEN: LazyLock<Result<IntGaugeVec>> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "nat_open",
        "An estimate indicating if the local node is reachable from external nodes",
        &["protocol"],
    )
});
pub static DISCOVERY_BYTES: LazyLock<Result<IntGaugeVec>> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "discovery_bytes",
        "The number of bytes sent and received in discovery",
        &["direction"],
    )
});
pub static DISCOVERY_QUEUE: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "discovery_queue_size",
        "The number of discovery queries awaiting execution",
    )
});
pub static DISCOVERY_REQS: LazyLock<Result<Gauge>> = LazyLock::new(|| {
    try_create_float_gauge(
        "discovery_requests",
        "The number of unsolicited discovery requests per second",
    )
});
pub static DISCOVERY_SESSIONS: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "discovery_sessions",
        "The number of active discovery sessions with peers",
    )
});

pub fn scrape_discovery_metrics() {
    let metrics = discv5::metrics::Metrics::from(discv5::Discv5::raw_metrics());
    set_float_gauge(&DISCOVERY_REQS, metrics.unsolicited_requests_per_second);
    set_gauge(&DISCOVERY_SESSIONS, metrics.active_sessions as i64);
    set_gauge_vec(&DISCOVERY_BYTES, &["inbound"], metrics.bytes_recv as i64);
    set_gauge_vec(&DISCOVERY_BYTES, &["outbound"], metrics.bytes_sent as i64);
    set_gauge_vec(&NAT_OPEN, &["discv5_ipv4"], metrics.ipv4_contactable as i64);
    set_gauge_vec(&NAT_OPEN, &["discv5_ipv6"], metrics.ipv6_contactable as i64);
}
