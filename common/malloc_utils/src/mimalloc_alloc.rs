//! Set the allocator to `mimalloc`.
//!
//! Unlike `jemalloc`, `mimalloc` needs no compile-time or start-up configuration, so this module
//! only installs the allocator and exposes its process statistics.

use libmimalloc_sys::mi_process_info;
use metrics::{IntGauge, set_gauge, try_create_int_gauge};
use std::sync::LazyLock;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

// Metrics for mimalloc. These mirror the `jemalloc_*` gauges so that a dashboard can chart either
// allocator, but the underlying quantities are the ones mimalloc itself reports: resident set size
// and committed memory, rather than jemalloc's arena accounting.
pub static CURRENT_RSS: LazyLock<metrics::Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "mimalloc_current_rss_bytes",
        "Resident set size of the process, as reported by mi_process_info",
    )
});
pub static PEAK_RSS: LazyLock<metrics::Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "mimalloc_peak_rss_bytes",
        "Peak resident set size of the process, as reported by mi_process_info",
    )
});
pub static CURRENT_COMMIT: LazyLock<metrics::Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "mimalloc_current_commit_bytes",
        "Memory currently committed by mimalloc. Comparable to jemalloc_bytes_mapped",
    )
});
pub static PEAK_COMMIT: LazyLock<metrics::Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "mimalloc_peak_commit_bytes",
        "Peak memory committed by mimalloc",
    )
});
pub static PAGE_FAULTS: LazyLock<metrics::Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "mimalloc_page_faults",
        "Number of hard page faults incurred by the process",
    )
});

pub fn scrape_mimalloc_metrics() {
    // `mi_process_info` also reports elapsed wall-clock time and process user/system CPU time.
    // Those are not exported here: they measure the whole process, not time spent in the
    // allocator, and Prometheus already collects them via the process collector.
    let mut elapsed_msecs = 0;
    let mut user_msecs = 0;
    let mut system_msecs = 0;
    let mut current_rss = 0;
    let mut peak_rss = 0;
    let mut current_commit = 0;
    let mut peak_commit = 0;
    let mut page_faults = 0;

    // SAFETY: every argument is a valid, non-null pointer to a `usize` that outlives the call, and
    // `mi_process_info` only writes through them.
    unsafe {
        mi_process_info(
            &mut elapsed_msecs,
            &mut user_msecs,
            &mut system_msecs,
            &mut current_rss,
            &mut peak_rss,
            &mut current_commit,
            &mut peak_commit,
            &mut page_faults,
        );
    }

    set_gauge(&CURRENT_RSS, current_rss as i64);
    set_gauge(&PEAK_RSS, peak_rss as i64);
    set_gauge(&CURRENT_COMMIT, current_commit as i64);
    set_gauge(&PEAK_COMMIT, peak_commit as i64);
    set_gauge(&PAGE_FAULTS, page_faults as i64);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn scrape_reports_non_zero_rss() {
        scrape_mimalloc_metrics();
        assert!(CURRENT_RSS.as_ref().unwrap().get() > 0);
    }
}
