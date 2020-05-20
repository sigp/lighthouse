/// Handles async task metrics
use lazy_static::lazy_static;
pub use lighthouse_metrics::*;

lazy_static! {
    pub static ref ASYNC_TASKS_COUNT: Result<IntCounter> = try_create_int_counter(
        "async_tasks",
        "Total number of async tasks spawned using spawn"
    );
    pub static ref BLOCKING_TASKS_COUNT: Result<IntCounter> = try_create_int_counter(
        "blocking_tasks",
        "Total number of async tasks spawned using spawn_blocking"
    );
}
