//! A wrapper around the `prometheus` crate that provides a global, `lazy_static` metrics registry
//! and functions to add and use the following components (more info at
//! [Prometheus docs](https://prometheus.io/docs/concepts/metric_types/)):
//!
//! - `Histogram`: used with `start_timer(..)` and `stop_timer(..)` to record durations (e.g.,
//! block processing time).
//! - `IncCounter`: used to represent an ideally ever-growing, never-shrinking integer (e.g.,
//! number of block processing requests).
//! - `IntGauge`: used to represent an varying integer (e.g., number of attestations per block).
//!
//! ## Important
//!
//! Metrics will fail if two items have the same `name`. All metrics must have a unique `name`.
//! Because we use a global registry there is no namespace per crate, it's one big global space.
//!
//! See the [Prometheus naming best practices](https://prometheus.io/docs/practices/naming/) when
//! choosing metric names.
//!
//! ## Example
//!
//! ```rust
//! #[macro_use]
//! extern crate lazy_static;
//! use lighthouse_metrics::*;
//!
//! // These metrics are "magically" linked to the global registry defined in `lighthouse_metrics`.
//! lazy_static! {
//!     pub static ref RUN_COUNT: Result<IntCounter> = try_create_int_counter(
//!         "runs_total",
//!         "Total number of runs"
//!     );
//!     pub static ref CURRENT_VALUE: Result<IntGauge> = try_create_int_gauge(
//!         "current_value",
//!         "The current value"
//!     );
//!     pub static ref RUN_TIME: Result<Histogram> =
//!         try_create_histogram("run_seconds", "Time taken (measured to high precision)");
//! }
//!
//!
//! fn main() {
//!     for i in 0..100 {
//!         inc_counter(&RUN_COUNT);
//!         let timer = start_timer(&RUN_TIME);
//!
//!         for j in 0..10 {
//!             set_gauge(&CURRENT_VALUE, j);
//!             println!("Howdy partner");
//!         }
//!
//!         stop_timer(timer);
//!     }
//! }
//! ```

use prometheus::{HistogramOpts, HistogramTimer, Opts};

pub use prometheus::{Encoder, Histogram, IntCounter, IntGauge, Result, TextEncoder};

/// Collect all the metrics for reporting.
pub fn gather() -> Vec<prometheus::proto::MetricFamily> {
    prometheus::gather()
}

/// Attempts to crate an `IntCounter`, returning `Err` if the registry does not accept the counter
/// (potentially due to naming conflict).
pub fn try_create_int_counter(name: &str, help: &str) -> Result<IntCounter> {
    let opts = Opts::new(name, help);
    let counter = IntCounter::with_opts(opts)?;
    prometheus::register(Box::new(counter.clone()))?;
    Ok(counter)
}

/// Attempts to crate an `IntGauge`, returning `Err` if the registry does not accept the counter
/// (potentially due to naming conflict).
pub fn try_create_int_gauge(name: &str, help: &str) -> Result<IntGauge> {
    let opts = Opts::new(name, help);
    let gauge = IntGauge::with_opts(opts)?;
    prometheus::register(Box::new(gauge.clone()))?;
    Ok(gauge)
}

/// Attempts to crate a `Histogram`, returning `Err` if the registry does not accept the counter
/// (potentially due to naming conflict).
pub fn try_create_histogram(name: &str, help: &str) -> Result<Histogram> {
    let opts = HistogramOpts::new(name, help);
    let histogram = Histogram::with_opts(opts)?;
    prometheus::register(Box::new(histogram.clone()))?;
    Ok(histogram)
}

/// Starts a timer for the given `Histogram`, stopping when it gets dropped or given to `stop_timer(..)`.
pub fn start_timer(histogram: &Result<Histogram>) -> Option<HistogramTimer> {
    if let Ok(histogram) = histogram {
        Some(histogram.start_timer())
    } else {
        None
    }
}

/// Stops a timer created with `start_timer(..)`.
pub fn stop_timer(timer: Option<HistogramTimer>) {
    if let Some(t) = timer {
        t.observe_duration()
    }
}

pub fn inc_counter(counter: &Result<IntCounter>) {
    if let Ok(counter) = counter {
        counter.inc();
    }
}

pub fn inc_counter_by(counter: &Result<IntCounter>, value: i64) {
    if let Ok(counter) = counter {
        counter.inc_by(value);
    }
}

pub fn set_gauge(gauge: &Result<IntGauge>, value: i64) {
    if let Ok(gauge) = gauge {
        gauge.set(value);
    }
}

/// Sets the value of a `Histogram` manually.
pub fn observe(histogram: &Result<Histogram>, value: f64) {
    if let Ok(histogram) = histogram {
        histogram.observe(value);
    }
}
