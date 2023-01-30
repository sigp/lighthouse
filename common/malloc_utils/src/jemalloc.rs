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
