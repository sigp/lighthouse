//! Set the allocator to `jemalloc`.
//!
//! Due to `jemalloc` requiring configuration at compile time or immediately upon runtime
//! initialisation it is configured via a Cargo config file in `.cargo/config.toml`.
//!
//! The `jemalloc` tuning can be overriden by:
//!
//! A) `JEMALLOC_SYS_WITH_MALLOC_CONF` at compile-time.
//! B) `_RJEM_MALLOC_CONF` at runtime.
use jemalloc_ctl::{arenas, epoch, stats, Error};
use lazy_static::lazy_static;
use lighthouse_metrics::{set_gauge, try_create_int_gauge, IntGauge};
use std::ffi::{c_char, c_int};
use std::mem;
use std::ptr;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

// Metrics for jemalloc.
lazy_static! {
    pub static ref NUM_ARENAS: lighthouse_metrics::Result<IntGauge> =
        try_create_int_gauge("jemalloc_num_arenas", "The number of arenas in use");
    pub static ref BYTES_ALLOCATED: lighthouse_metrics::Result<IntGauge> =
        try_create_int_gauge("jemalloc_bytes_allocated", "Equivalent to stats.allocated");
    pub static ref BYTES_ACTIVE: lighthouse_metrics::Result<IntGauge> =
        try_create_int_gauge("jemalloc_bytes_active", "Equivalent to stats.active");
    pub static ref BYTES_MAPPED: lighthouse_metrics::Result<IntGauge> =
        try_create_int_gauge("jemalloc_bytes_mapped", "Equivalent to stats.mapped");
    pub static ref BYTES_METADATA: lighthouse_metrics::Result<IntGauge> =
        try_create_int_gauge("jemalloc_bytes_metadata", "Equivalent to stats.metadata");
    pub static ref BYTES_RESIDENT: lighthouse_metrics::Result<IntGauge> =
        try_create_int_gauge("jemalloc_bytes_resident", "Equivalent to stats.resident");
    pub static ref BYTES_RETAINED: lighthouse_metrics::Result<IntGauge> =
        try_create_int_gauge("jemalloc_bytes_retained", "Equivalent to stats.retained");
}

pub fn scrape_jemalloc_metrics() {
    scrape_jemalloc_metrics_fallible().unwrap()
}

pub fn scrape_jemalloc_metrics_fallible() -> Result<(), Error> {
    // Advance the epoch so that the underlying statistics are updated.
    epoch::advance()?;

    set_gauge(&NUM_ARENAS, arenas::narenas::read()? as i64);
    set_gauge(&BYTES_ALLOCATED, stats::allocated::read()? as i64);
    set_gauge(&BYTES_ACTIVE, stats::active::read()? as i64);
    set_gauge(&BYTES_MAPPED, stats::mapped::read()? as i64);
    set_gauge(&BYTES_METADATA, stats::metadata::read()? as i64);
    set_gauge(&BYTES_RESIDENT, stats::resident::read()? as i64);
    set_gauge(&BYTES_RETAINED, stats::retained::read()? as i64);

    Ok(())
}

/// A convenience wrapper around `mallctl` for writing `value` to `name`.
pub unsafe fn mallctl_write<T>(name: &[u8], mut value: T) -> Result<(), c_int> {
    // Use `jemalloc_sys::mallctl` directly since the `jemalloc_ctl::raw`
    // functions artifically limit the `name` values.
    let status = jemalloc_sys::mallctl(
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
/// Controls wether profile sampling is active.
#[allow(dead_code)]
pub fn prof_active(enable: bool) -> Result<(), String> {
    unsafe { mallctl_write("prof.active\0".as_ref(), enable) }
        .map_err(|e| format!("Failed to call prof.active on mallctl with code {e:?}"))
}
