//! Contains functions for tuning and controlling "The GNU Allocator", included in the `glibc`
//! library.
//!
//! https://www.gnu.org/software/libc/manual/html_node/The-GNU-Allocator.html
//!
//! These functions are generally only suitable for Linux systems.
use lazy_static::lazy_static;
use lighthouse_metrics::*;
use parking_lot::Mutex;
use std::env;
use std::os::raw::c_int;
use std::result::Result;

/// The value to be provided to `malloc_mmap_threshold`.
///
/// Value chosen so that values of the validators tree hash cache will *not* be allocated via
/// `mmap`.
///
/// The size of a single chunk is:
///
/// NODES_PER_VALIDATOR * VALIDATORS_PER_ARENA * 32 = 15 * 4096 * 32 = 1.875 MiB
const OPTIMAL_MMAP_THRESHOLD: c_int = 2 * 1_024 * 1_024;

/// Constants used to configure malloc internals.
///
/// Source:
///
/// https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/malloc/malloc.h#L115-L123
const M_MMAP_THRESHOLD: c_int = -4;

/// Environment variables used to configure malloc.
///
/// Source:
///
/// https://man7.org/linux/man-pages/man3/mallopt.3.html
const ENV_VAR_MMAP_THRESHOLD: &str = "MALLOC_MMAP_THRESHOLD_";

lazy_static! {
    pub static ref GLOBAL_LOCK: Mutex<()> = <_>::default();
}

// Metrics for the malloc. For more information, see:
//
// https://man7.org/linux/man-pages/man3/mallinfo.3.html
lazy_static! {
    pub static ref MALLINFO_ARENA: lighthouse_metrics::Result<IntGauge> = try_create_int_gauge(
        "mallinfo_arena",
        "The total amount of memory allocated by means other than mmap(2). \
            This figure includes both in-use blocks and blocks on the free list.",
    );
    pub static ref MALLINFO_ORDBLKS: lighthouse_metrics::Result<IntGauge> = try_create_int_gauge(
        "mallinfo_ordblks",
        "The number of ordinary (i.e., non-fastbin) free blocks.",
    );
    pub static ref MALLINFO_SMBLKS: lighthouse_metrics::Result<IntGauge> =
        try_create_int_gauge("mallinfo_smblks", "The number of fastbin free blocks.",);
    pub static ref MALLINFO_HBLKS: lighthouse_metrics::Result<IntGauge> = try_create_int_gauge(
        "mallinfo_hblks",
        "The number of blocks currently allocated using mmap.",
    );
    pub static ref MALLINFO_HBLKHD: lighthouse_metrics::Result<IntGauge> = try_create_int_gauge(
        "mallinfo_hblkhd",
        "The number of bytes in blocks currently allocated using mmap.",
    );
    pub static ref MALLINFO_FSMBLKS: lighthouse_metrics::Result<IntGauge> = try_create_int_gauge(
        "mallinfo_fsmblks",
        "The total number of bytes in fastbin free blocks.",
    );
    pub static ref MALLINFO_UORDBLKS: lighthouse_metrics::Result<IntGauge> = try_create_int_gauge(
        "mallinfo_uordblks",
        "The total number of bytes used by in-use allocations.",
    );
    pub static ref MALLINFO_FORDBLKS: lighthouse_metrics::Result<IntGauge> = try_create_int_gauge(
        "mallinfo_fordblks",
        "The total number of bytes in free blocks.",
    );
    pub static ref MALLINFO_KEEPCOST: lighthouse_metrics::Result<IntGauge> = try_create_int_gauge(
        "mallinfo_keepcost",
        "The total amount of releasable free space at the top of the heap..",
    );
}

/// Calls `mallinfo` and updates Prometheus metrics with the results.
pub fn scrape_mallinfo_metrics() {
    // The docs for this function say it is thread-unsafe since it may return inconsistent results.
    // Since these are just metrics it's not a concern to us if they're sometimes inconsistent.
    //
    // There exists a `malloc2` function, however it was release in February 2021 and this seems too
    // recent to rely on.
    //
    // Docs:
    //
    // https://man7.org/linux/man-pages/man3/mallinfo.3.html
    let mallinfo = mallinfo();

    set_gauge(&MALLINFO_ARENA, mallinfo.arena as i64);
    set_gauge(&MALLINFO_ORDBLKS, mallinfo.ordblks as i64);
    set_gauge(&MALLINFO_SMBLKS, mallinfo.smblks as i64);
    set_gauge(&MALLINFO_HBLKS, mallinfo.hblks as i64);
    set_gauge(&MALLINFO_HBLKHD, mallinfo.hblkhd as i64);
    set_gauge(&MALLINFO_FSMBLKS, mallinfo.fsmblks as i64);
    set_gauge(&MALLINFO_UORDBLKS, mallinfo.uordblks as i64);
    set_gauge(&MALLINFO_FORDBLKS, mallinfo.fordblks as i64);
    set_gauge(&MALLINFO_KEEPCOST, mallinfo.keepcost as i64);
}

/// Perform all configuration routines.
pub fn configure_glibc_malloc() -> Result<(), String> {
    if !env_var_present(ENV_VAR_MMAP_THRESHOLD) {
        if let Err(e) = malloc_mmap_threshold(OPTIMAL_MMAP_THRESHOLD) {
            return Err(format!("failed (code {}) to set malloc mmap threshold", e));
        }
    }

    Ok(())
}

/// Returns `true` if an environment variable is present.
fn env_var_present(name: &str) -> bool {
    env::var(name) != Err(env::VarError::NotPresent)
}

/// Uses `mallopt` to set the `M_MMAP_THRESHOLD` value, specifying the threshold where objects of this
/// size or larger are allocated via an `mmap`.
///
/// ## Resources
///
/// - https://man7.org/linux/man-pages/man3/mallopt.3.html
fn malloc_mmap_threshold(num_arenas: c_int) -> Result<(), c_int> {
    into_result(mallopt(M_MMAP_THRESHOLD, num_arenas))
}

fn mallopt(param: c_int, val: c_int) -> c_int {
    // Prevent this function from being called in parallel with any other non-thread-safe function.
    let _lock = GLOBAL_LOCK.lock();
    unsafe { libc::mallopt(param, val) }
}

fn mallinfo() -> libc::mallinfo {
    // Prevent this function from being called in parallel with any other non-thread-safe function.
    let _lock = GLOBAL_LOCK.lock();
    unsafe { libc::mallinfo() }
}

fn into_result(result: c_int) -> Result<(), c_int> {
    if result == 1 {
        Ok(())
    } else {
        Err(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malloc_mmap_threshold_does_not_panic() {
        malloc_mmap_threshold(OPTIMAL_MMAP_THRESHOLD).unwrap();
    }
}
