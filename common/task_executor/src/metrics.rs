/// Handles async task metrics
use lazy_static::lazy_static;
pub use lighthouse_metrics::*;

lazy_static! {
    pub static ref ASYNC_TASKS_COUNT: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "async_tasks_count",
        "Total number of async tasks spawned using spawn",
        &["async_task_count"]
    );
    pub static ref BLOCKING_TASKS_COUNT: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "blocking_tasks_count",
        "Total number of async tasks spawned using spawn_blocking",
        &["blocking_task_count"]
    );
    pub static ref BLOCKING_TASKS_HISTOGRAM: Result<HistogramVec> = try_create_histogram_vec(
        "blocking_tasks_histogram",
        "Time taken by blocking tasks",
        &["blocking_task_hist"]
    );
    pub static ref TASKS_HISTOGRAM: Result<HistogramVec> = try_create_histogram_vec(
        "async_tasks_time_histogram",
        "Time taken by async tasks",
        &["async_task_hist"]
    );
}
