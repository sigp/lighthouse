//! Set the allocator to `jemalloc`.
//!
//! Due to `jemalloc` requiring configuration at compile time or immediately upon runtime
//! initialisation it is configured via a Cargo config file in `.cargo/config.toml`.
//!
//! The `jemalloc` tuning can be overridden by:
//!
//! A) `JEMALLOC_SYS_WITH_MALLOC_CONF` at compile-time.
//! B) `_RJEM_MALLOC_CONF` at runtime.

use metrics::{
    set_gauge, set_gauge_vec, try_create_int_gauge, try_create_int_gauge_vec, IntGauge, IntGaugeVec,
};
use std::ffi::{c_char, c_int};
use std::sync::LazyLock;
use std::{mem, ptr};
use tikv_jemalloc_ctl::{arenas, epoch, raw, stats, Access, AsName, Error};

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// Metrics for jemalloc.
pub static NUM_ARENAS: LazyLock<metrics::Result<IntGauge>> =
    LazyLock::new(|| try_create_int_gauge("jemalloc_num_arenas", "The number of arenas in use"));
pub static BYTES_ALLOCATED: LazyLock<metrics::Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge("jemalloc_bytes_allocated", "Equivalent to stats.allocated")
});
pub static BYTES_ACTIVE: LazyLock<metrics::Result<IntGauge>> =
    LazyLock::new(|| try_create_int_gauge("jemalloc_bytes_active", "Equivalent to stats.active"));
pub static BYTES_MAPPED: LazyLock<metrics::Result<IntGauge>> =
    LazyLock::new(|| try_create_int_gauge("jemalloc_bytes_mapped", "Equivalent to stats.mapped"));
pub static BYTES_METADATA: LazyLock<metrics::Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge("jemalloc_bytes_metadata", "Equivalent to stats.metadata")
});
pub static BYTES_RESIDENT: LazyLock<metrics::Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge("jemalloc_bytes_resident", "Equivalent to stats.resident")
});
pub static BYTES_RETAINED: LazyLock<metrics::Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge("jemalloc_bytes_retained", "Equivalent to stats.retained")
});
pub static JEMALLOC_ARENAS_SMALL_NMALLOC: LazyLock<metrics::Result<IntGaugeVec>> =
    LazyLock::new(|| {
        try_create_int_gauge_vec(
            "jemalloc_arenas_small_nmalloc",
            "Equivalent to stats.arenas.<i>.small.nmalloc",
            &["arena"],
        )
    });
pub static JEMALLOC_ARENAS_SMALL_NDALLOC: LazyLock<metrics::Result<IntGaugeVec>> =
    LazyLock::new(|| {
        try_create_int_gauge_vec(
            "jemalloc_arenas_small_ndalloc",
            "Equivalent to stats.arenas.<i>.small.ndalloc",
            &["arena"],
        )
    });
pub static JEMALLOC_ARENAS_LARGE_NMALLOC: LazyLock<metrics::Result<IntGaugeVec>> =
    LazyLock::new(|| {
        try_create_int_gauge_vec(
            "jemalloc_arenas_large_nmalloc",
            "Equivalent to stats.arenas.<i>.large.nmalloc",
            &["arena"],
        )
    });
pub static JEMALLOC_ARENAS_LARGE_NDALLOC: LazyLock<metrics::Result<IntGaugeVec>> =
    LazyLock::new(|| {
        try_create_int_gauge_vec(
            "jemalloc_arenas_large_ndalloc",
            "Equivalent to stats.arenas.<i>.large.ndalloc",
            &["arena"],
        )
    });

pub fn scrape_jemalloc_metrics() {
    scrape_jemalloc_metrics_fallible().unwrap()
}

pub fn scrape_jemalloc_metrics_fallible() -> Result<(), Error> {
    // Advance the epoch so that the underlying statistics are updated.
    epoch::advance()?;

    let num_arenas = arenas::narenas::read()?;
    set_gauge(&NUM_ARENAS, num_arenas as i64);
    set_gauge(&BYTES_ALLOCATED, stats::allocated::read()? as i64);
    set_gauge(&BYTES_ACTIVE, stats::active::read()? as i64);
    set_gauge(&BYTES_MAPPED, stats::mapped::read()? as i64);
    set_gauge(&BYTES_METADATA, stats::metadata::read()? as i64);
    set_gauge(&BYTES_RESIDENT, stats::resident::read()? as i64);
    set_gauge(&BYTES_RETAINED, stats::retained::read()? as i64);

    for arena in 0..num_arenas {
        unsafe {
            set_stats_gauge(
                &JEMALLOC_ARENAS_SMALL_NMALLOC,
                arena,
                &format!("stats.arenas.{arena}.small.nmalloc\0"),
            );
            set_stats_gauge(
                &JEMALLOC_ARENAS_SMALL_NDALLOC,
                arena,
                &format!("stats.arenas.{arena}.small.ndalloc\0"),
            );
            set_stats_gauge(
                &JEMALLOC_ARENAS_LARGE_NMALLOC,
                arena,
                &format!("stats.arenas.{arena}.large.nmalloc\0"),
            );
            set_stats_gauge(
                &JEMALLOC_ARENAS_LARGE_NDALLOC,
                arena,
                &format!("stats.arenas.{arena}.large.ndalloc\0"),
            );
        }
    }

    Ok(())
}

unsafe fn set_stats_gauge(metric: &metrics::Result<IntGaugeVec>, arena: u32, stat: &str) {
    if let Ok(val) = raw::read::<usize>(stat.as_bytes()) {
        set_gauge_vec(metric, &[&format!("arena_{arena}")], val as i64);
    }
}

pub fn page_size() -> Result<usize, Error> {
    // Full list of keys: https://jemalloc.net/jemalloc.3.html
    "arenas.page\0".name().read()
}

/// A convenience wrapper around `mallctl` for writing `value` to `name`.
///
/// # Safety
///
/// - `name` must be a valid, null-terminated jemalloc control name.
/// - `value` must match the expected type for the specified control.
/// - The jemalloc allocator must be initialised.
///
/// Incorrect usage may cause undefined behaviour or allocator corruption.
unsafe fn mallctl_write<T>(name: &[u8], mut value: T) -> Result<(), c_int> {
    // Use `tikv_jemalloc_sys::mallctl` directly since the `jemalloc_ctl::raw`
    // functions artifically limit the `name` values.
    let status = tikv_jemalloc_sys::mallctl(
        name as *const _ as *const c_char,
        ptr::null_mut(),
        ptr::null_mut(),
        &mut value as *mut _ as *mut _,
        mem::size_of::<T>(),
    );

    if status == 0 {
        Ok(())
    } else {
        Err(status)
    }
}

/// Add a C-style `0x00` terminator to the string and return it as a `Vec` of
/// bytes.
#[allow(dead_code)]
fn terminate_string_for_c(s: &str) -> Vec<u8> {
    let mut terminated = vec![0x00_u8; s.len() + 1];
    terminated[..s.len()].copy_from_slice(s.as_ref());
    terminated
}

/// Uses `mallctl` to call `"prof.dump"`.
///
/// This generates a heap profile at `filename`.
#[allow(dead_code)]
pub fn prof_dump(filename: &str) -> Result<(), String> {
    let terminated_filename = terminate_string_for_c(filename);

    unsafe {
        mallctl_write(
            "prof.dump\0".as_ref(),
            terminated_filename.as_ptr() as *const c_char,
        )
    }
    .map_err(|e| format!("Failed to call prof.dump on mallctl: {e:?}"))
}

/// Uses `mallctl` to call `"prof.enable"`.
///
/// Controls whether profile sampling is active.
#[allow(dead_code)]
pub fn prof_active(enable: bool) -> Result<(), String> {
    unsafe { mallctl_write("prof.active\0".as_ref(), enable) }
        .map_err(|e| format!("Failed to call prof.active on mallctl with code {e:?}"))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn page_size_ok() {
        assert!(page_size().is_ok());
    }
}
