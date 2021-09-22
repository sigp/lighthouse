#![allow(clippy::needless_doctest_main)]
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

use prometheus::{HistogramOpts, Opts};
use std::time::Duration;

use prometheus::core::{Atomic, GenericGauge, GenericGaugeVec};
pub use prometheus::{
    proto::{Metric, MetricFamily, MetricType},
    Encoder, Gauge, GaugeVec, Histogram, HistogramTimer, HistogramVec, IntCounter, IntCounterVec,
    IntGauge, IntGaugeVec, Result, TextEncoder,
};

/// Collect all the metrics for reporting.
pub fn gather() -> Vec<prometheus::proto::MetricFamily> {
    prometheus::gather()
}

/// Attempts to create an `IntCounter`, returning `Err` if the registry does not accept the counter
/// (potentially due to naming conflict).
pub fn try_create_int_counter(name: &str, help: &str) -> Result<IntCounter> {
    let opts = Opts::new(name, help);
    let counter = IntCounter::with_opts(opts)?;
    prometheus::register(Box::new(counter.clone()))?;
    Ok(counter)
}

/// Attempts to create an `IntGauge`, returning `Err` if the registry does not accept the counter
/// (potentially due to naming conflict).
pub fn try_create_int_gauge(name: &str, help: &str) -> Result<IntGauge> {
    let opts = Opts::new(name, help);
    let gauge = IntGauge::with_opts(opts)?;
    prometheus::register(Box::new(gauge.clone()))?;
    Ok(gauge)
}

/// Attempts to create a `Gauge`, returning `Err` if the registry does not accept the counter
/// (potentially due to naming conflict).
pub fn try_create_float_gauge(name: &str, help: &str) -> Result<Gauge> {
    let opts = Opts::new(name, help);
    let gauge = Gauge::with_opts(opts)?;
    prometheus::register(Box::new(gauge.clone()))?;
    Ok(gauge)
}

/// Attempts to create a `Histogram`, returning `Err` if the registry does not accept the counter
/// (potentially due to naming conflict).
pub fn try_create_histogram(name: &str, help: &str) -> Result<Histogram> {
    let opts = HistogramOpts::new(name, help);
    let histogram = Histogram::with_opts(opts)?;
    prometheus::register(Box::new(histogram.clone()))?;
    Ok(histogram)
}

/// Attempts to create a `HistogramVec`, returning `Err` if the registry does not accept the counter
/// (potentially due to naming conflict).
pub fn try_create_histogram_vec(
    name: &str,
    help: &str,
    label_names: &[&str],
) -> Result<HistogramVec> {
    let opts = HistogramOpts::new(name, help);
    let histogram_vec = HistogramVec::new(opts, label_names)?;
    prometheus::register(Box::new(histogram_vec.clone()))?;
    Ok(histogram_vec)
}

/// Attempts to create a `IntGaugeVec`, returning `Err` if the registry does not accept the gauge
/// (potentially due to naming conflict).
pub fn try_create_int_gauge_vec(
    name: &str,
    help: &str,
    label_names: &[&str],
) -> Result<IntGaugeVec> {
    let opts = Opts::new(name, help);
    let counter_vec = IntGaugeVec::new(opts, label_names)?;
    prometheus::register(Box::new(counter_vec.clone()))?;
    Ok(counter_vec)
}

/// Attempts to create a `GaugeVec`, returning `Err` if the registry does not accept the gauge
/// (potentially due to naming conflict).
pub fn try_create_float_gauge_vec(
    name: &str,
    help: &str,
    label_names: &[&str],
) -> Result<GaugeVec> {
    let opts = Opts::new(name, help);
    let counter_vec = GaugeVec::new(opts, label_names)?;
    prometheus::register(Box::new(counter_vec.clone()))?;
    Ok(counter_vec)
}

/// Attempts to create a `IntCounterVec`, returning `Err` if the registry does not accept the gauge
/// (potentially due to naming conflict).
pub fn try_create_int_counter_vec(
    name: &str,
    help: &str,
    label_names: &[&str],
) -> Result<IntCounterVec> {
    let opts = Opts::new(name, help);
    let counter_vec = IntCounterVec::new(opts, label_names)?;
    prometheus::register(Box::new(counter_vec.clone()))?;
    Ok(counter_vec)
}

/// If `int_gauge_vec.is_ok()`, returns a gauge with the given `name`.
pub fn get_int_gauge(int_gauge_vec: &Result<IntGaugeVec>, name: &[&str]) -> Option<IntGauge> {
    if let Ok(int_gauge_vec) = int_gauge_vec {
        Some(int_gauge_vec.get_metric_with_label_values(name).ok()?)
    } else {
        None
    }
}

pub fn get_gauge<P: Atomic>(
    gauge_vec: &Result<GenericGaugeVec<P>>,
    name: &[&str],
) -> Option<GenericGauge<P>> {
    if let Ok(gauge_vec) = gauge_vec {
        Some(gauge_vec.get_metric_with_label_values(name).ok()?)
    } else {
        None
    }
}

pub fn set_gauge_entry<P: Atomic>(
    gauge_vec: &Result<GenericGaugeVec<P>>,
    name: &[&str],
    value: P::T,
) {
    if let Some(v) = get_gauge(gauge_vec, name) {
        v.set(value)
    };
}

/// If `int_gauge_vec.is_ok()`, sets the gauge with the given `name` to the given `value`
/// otherwise returns false.
pub fn set_int_gauge(int_gauge_vec: &Result<IntGaugeVec>, name: &[&str], value: i64) -> bool {
    if let Ok(int_gauge_vec) = int_gauge_vec {
        int_gauge_vec
            .get_metric_with_label_values(name)
            .map(|v| {
                v.set(value);
                true
            })
            .unwrap_or_else(|_| false)
    } else {
        false
    }
}

/// If `int_counter_vec.is_ok()`, returns a counter with the given `name`.
pub fn get_int_counter(
    int_counter_vec: &Result<IntCounterVec>,
    name: &[&str],
) -> Option<IntCounter> {
    if let Ok(int_counter_vec) = int_counter_vec {
        Some(int_counter_vec.get_metric_with_label_values(name).ok()?)
    } else {
        None
    }
}

/// Increments the `int_counter_vec` with the given `name`.
pub fn inc_counter_vec(int_counter_vec: &Result<IntCounterVec>, name: &[&str]) {
    if let Some(counter) = get_int_counter(int_counter_vec, name) {
        counter.inc()
    }
}

pub fn inc_counter_vec_by(int_counter_vec: &Result<IntCounterVec>, name: &[&str], amount: u64) {
    if let Some(counter) = get_int_counter(int_counter_vec, name) {
        counter.inc_by(amount);
    }
}

/// If `histogram_vec.is_ok()`, returns a histogram with the given `name`.
pub fn get_histogram(histogram_vec: &Result<HistogramVec>, name: &[&str]) -> Option<Histogram> {
    if let Ok(histogram_vec) = histogram_vec {
        Some(histogram_vec.get_metric_with_label_values(name).ok()?)
    } else {
        None
    }
}

/// Starts a timer on `vec` with the given `name`.
pub fn start_timer_vec(vec: &Result<HistogramVec>, name: &[&str]) -> Option<HistogramTimer> {
    get_histogram(vec, name).map(|h| h.start_timer())
}

/// Starts a timer for the given `Histogram`, stopping when it gets dropped or given to `stop_timer(..)`.
pub fn start_timer(histogram: &Result<Histogram>) -> Option<HistogramTimer> {
    if let Ok(histogram) = histogram {
        Some(histogram.start_timer())
    } else {
        None
    }
}

/// Starts a timer on `vec` with the given `name`.
pub fn observe_timer_vec(vec: &Result<HistogramVec>, name: &[&str], duration: Duration) {
    if let Some(h) = get_histogram(vec, name) {
        h.observe(duration_to_f64(duration))
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

pub fn inc_counter_by(counter: &Result<IntCounter>, value: u64) {
    if let Ok(counter) = counter {
        counter.inc_by(value);
    }
}

pub fn set_gauge_vec(int_gauge_vec: &Result<IntGaugeVec>, name: &[&str], value: i64) {
    if let Some(gauge) = get_int_gauge(int_gauge_vec, name) {
        gauge.set(value);
    }
}

pub fn inc_gauge_vec(int_gauge_vec: &Result<IntGaugeVec>, name: &[&str]) {
    if let Some(gauge) = get_int_gauge(int_gauge_vec, name) {
        gauge.inc();
    }
}

pub fn dec_gauge_vec(int_gauge_vec: &Result<IntGaugeVec>, name: &[&str]) {
    if let Some(gauge) = get_int_gauge(int_gauge_vec, name) {
        gauge.dec();
    }
}

pub fn set_gauge(gauge: &Result<IntGauge>, value: i64) {
    if let Ok(gauge) = gauge {
        gauge.set(value);
    }
}

pub fn set_float_gauge(gauge: &Result<Gauge>, value: f64) {
    if let Ok(gauge) = gauge {
        gauge.set(value);
    }
}

pub fn inc_gauge(gauge: &Result<IntGauge>) {
    if let Ok(gauge) = gauge {
        gauge.inc();
    }
}

pub fn dec_gauge(gauge: &Result<IntGauge>) {
    if let Ok(gauge) = gauge {
        gauge.dec();
    }
}

pub fn maybe_set_gauge(gauge: &Result<IntGauge>, value_opt: Option<i64>) {
    if let Some(value) = value_opt {
        set_gauge(gauge, value)
    }
}

pub fn maybe_set_float_gauge(gauge: &Result<Gauge>, value_opt: Option<f64>) {
    if let Some(value) = value_opt {
        set_float_gauge(gauge, value)
    }
}

/// Sets the value of a `Histogram` manually.
pub fn observe(histogram: &Result<Histogram>, value: f64) {
    if let Ok(histogram) = histogram {
        histogram.observe(value);
    }
}

pub fn observe_duration(histogram: &Result<Histogram>, duration: Duration) {
    if let Ok(histogram) = histogram {
        histogram.observe(duration_to_f64(duration))
    }
}

fn duration_to_f64(duration: Duration) -> f64 {
    // This conversion was taken from here:
    //
    // https://docs.rs/prometheus/0.5.0/src/prometheus/histogram.rs.html#550-555
    let nanos = f64::from(duration.subsec_nanos()) / 1e9;
    duration.as_secs() as f64 + nanos
}
