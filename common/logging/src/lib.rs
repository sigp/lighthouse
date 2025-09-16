use std::time::{Duration, Instant};
use tracing_subscriber::EnvFilter;

pub const MAX_MESSAGE_WIDTH: usize = 40;

pub mod macros;
mod sse_logging_components;
mod tracing_libp2p_discv5_logging_layer;
pub mod tracing_logging_layer;
mod tracing_metrics_layer;
mod utils;

pub use sse_logging_components::SSELoggingComponents;
pub use tracing_libp2p_discv5_logging_layer::{
    Libp2pDiscv5TracingLayer, create_libp2p_discv5_tracing_layer,
};
pub use tracing_logging_layer::LoggingLayer;
pub use tracing_metrics_layer::MetricsLayer;
pub use utils::build_workspace_filter;

/// The minimum interval between log messages indicating that a queue is full.
const LOG_DEBOUNCE_INTERVAL: Duration = Duration::from_secs(30);

/// Provides de-bounce functionality for logging.
#[derive(Default)]
pub struct TimeLatch(Option<Instant>);

impl TimeLatch {
    /// Only returns true once every `LOG_DEBOUNCE_INTERVAL`.
    pub fn elapsed(&mut self) -> bool {
        let now = Instant::now();

        let is_elapsed = self.0.is_some_and(|elapse_time| now > elapse_time);

        if is_elapsed || self.0.is_none() {
            self.0 = Some(now + LOG_DEBOUNCE_INTERVAL);
        }

        is_elapsed
    }
}

/// Return a tracing subscriber suitable for test usage.
///
/// By default no logs will be printed, but they can be enabled via
/// the `test_logger` feature.  This feature can be enabled for any
/// dependent crate by passing `--features logging/test_logger`, e.g.
/// ```bash
/// cargo test -p beacon_chain --features logging/test_logger
/// ```
pub fn create_test_tracing_subscriber() {
    if cfg!(feature = "test_logger") {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::try_new("debug").unwrap())
            .try_init();
    }
}
