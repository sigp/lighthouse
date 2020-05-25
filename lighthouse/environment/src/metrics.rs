/// Handles async task metrics
use lazy_static::lazy_static;
pub use lighthouse_metrics::*;

lazy_static! {
    pub static ref ASYNC_TASKS_COUNT: Result<IntGauge> = try_create_int_gauge(
        "async_tasks_count",
        "Total number of async tasks spawned using spawn"
    );
    pub static ref BLOCKING_TASKS_COUNT: Result<IntGauge> = try_create_int_gauge(
        "blocking_tasks_count",
        "Total number of async tasks spawned using spawn_blocking"
    );
    pub static ref ASYNC_TASKS_HISTOGRAM: Result<HistogramVec> = try_create_histogram_vec(
        "async_tasks_histogram",
        "Time taken by async tasks",
        &["task"]
    );
    pub static ref BLOCKING_TASKS_HISTOGRAM: Result<HistogramVec> = try_create_histogram_vec(
        "blocking_tasks_histogram",
        "Time taken by blocking tasks",
        &["task"]
    );
}
