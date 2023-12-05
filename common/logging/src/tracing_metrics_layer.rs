//! Exposes [`MetricsLayer`]: A tracing layer that registers metrics of logging events.

use lighthouse_metrics as metrics;

lazy_static! {
    /// Count of `INFO` logs registered per enabled dependency.
    pub static ref DEP_INFOS_TOTAL: metrics::Result<metrics::IntCounterVec> =
        metrics::try_create_int_counter_vec(
            "dep_info_total",
            "Count of infos logged per enabled dependency",
            &["target"]
        );
    /// Count of `WARN` logs registered per enabled dependency.
    pub static ref DEP_WARNS_TOTAL: metrics::Result<metrics::IntCounterVec> =
        metrics::try_create_int_counter_vec(
            "dep_warn_total",
            "Count of warns logged per enabled dependency",
            &["target"]
        );
    /// Count of `ERROR` logs registered per enabled dependency.
    pub static ref DEP_ERRORS_TOTAL: metrics::Result<metrics::IntCounterVec> =
        metrics::try_create_int_counter_vec(
            "dep_error_total",
            "Count of errors logged per enabled dependency",
            &["target"]
        );
}

/// Layer that registers Prometheus metrics for `INFO`, `WARN` and `ERROR` logs emitted per dependency.
/// Dependencies are enabled via the `RUST_LOG` env flag.
pub struct MetricsLayer {}

impl<S: tracing_core::Subscriber> tracing_subscriber::layer::Layer<S> for MetricsLayer {
    fn on_event(
        &self,
        event: &tracing_core::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let meta = event.metadata();
        if !meta.is_event() {
            // ignore tracing span events
            return;
        }
        let target = match meta.target().split_once("::") {
            Some((crate_name, _)) => crate_name,
            None => "unknown",
        };
        let target = &[target];
        match *meta.level() {
            tracing_core::Level::INFO => metrics::inc_counter_vec(&DEP_INFOS_TOTAL, target),
            tracing_core::Level::WARN => metrics::inc_counter_vec(&DEP_WARNS_TOTAL, target),
            tracing_core::Level::ERROR => metrics::inc_counter_vec(&DEP_ERRORS_TOTAL, target),
            _ => {}
        }
    }
}
