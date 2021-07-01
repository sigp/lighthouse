use lazy_static::lazy_static;
pub use lighthouse_metrics::*;
use lighthouse_version::VERSION;
use slog::{error, Logger};
use std::time::{SystemTime, UNIX_EPOCH};

lazy_static! {
    pub static ref PROCESS_START_TIME_SECONDS: Result<IntGauge> = try_create_int_gauge(
        "process_start_time_seconds",
        "The unix timestamp at which the process was started"
    );
}

lazy_static! {
    pub static ref LIGHTHOUSE_VERSION: Result<IntGaugeVec> = try_create_int_gauge_vec(
        "lighthouse_info",
        "The build of Lighthouse running on the server",
        &["version"],
    );
}

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
