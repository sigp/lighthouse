use lighthouse_version::VERSION;
pub use metrics::*;
use slog::{error, Logger};
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub static PROCESS_START_TIME_SECONDS: LazyLock<Result<IntGauge>> = LazyLock::new(|| {
    try_create_int_gauge(
        "process_start_time_seconds",
        "The unix timestamp at which the process was started",
    )
});

pub static LIGHTHOUSE_VERSION: LazyLock<Result<IntGaugeVec>> = LazyLock::new(|| {
    try_create_int_gauge_vec(
        "lighthouse_info",
        "The build of Lighthouse running on the server",
        &["version"],
    )
});

pub fn expose_process_start_time(log: &Logger) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => set_gauge(&PROCESS_START_TIME_SECONDS, duration.as_secs() as i64),
        Err(e) => error!(
            log,
            "Failed to read system time";
            "error" => %e
        ),
    }
}

pub fn expose_lighthouse_version() {
    set_gauge_vec(&LIGHTHOUSE_VERSION, &[VERSION], 1);
}
