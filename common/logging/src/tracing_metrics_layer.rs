//! Exposes [`MetricsLayer`]: A tracing layer that registers metrics of logging events.

use std::sync::LazyLock;
use tracing_log::NormalizeEvent;

/// Count of `INFO` logs registered per enabled dependency.
pub static DEP_INFOS_TOTAL: LazyLock<metrics::Result<metrics::IntCounterVec>> =
    LazyLock::new(|| {
        metrics::try_create_int_counter_vec(
            "dep_info_total",
            "Count of infos logged per enabled dependency",
            &["target"],
        )
    });
/// Count of `WARN` logs registered per enabled dependency.
pub static DEP_WARNS_TOTAL: LazyLock<metrics::Result<metrics::IntCounterVec>> =
    LazyLock::new(|| {
        metrics::try_create_int_counter_vec(
            "dep_warn_total",
            "Count of warns logged per enabled dependency",
            &["target"],
        )
    });
/// Count of `ERROR` logs registered per enabled dependency.
pub static DEP_ERRORS_TOTAL: LazyLock<metrics::Result<metrics::IntCounterVec>> =
    LazyLock::new(|| {
        metrics::try_create_int_counter_vec(
            "dep_error_total",
            "Count of errors logged per enabled dependency",
            &["target"],
        )
    });

/// Layer that registers Prometheus metrics for `INFO`, `WARN` and `ERROR` logs emitted per dependency.
/// Dependencies are enabled via the `RUST_LOG` env flag.
pub struct MetricsLayer;

impl<S: tracing_core::Subscriber> tracing_subscriber::layer::Layer<S> for MetricsLayer {
    fn on_event(
        &self,
        event: &tracing_core::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        // get the event's normalized metadata
        // this is necessary to get the correct module path for libp2p events
        let normalized_meta = event.normalized_metadata();
        let meta = normalized_meta.as_ref().unwrap_or_else(|| event.metadata());

        if !meta.is_event() {
            // ignore tracing span events
            return;
        }

        let full_target = meta.module_path().unwrap_or_else(|| meta.target());
        let target = full_target
            .split_once("::")
            .map(|(name, _rest)| name)
            .unwrap_or(full_target);
        let target = &[target];
        match *meta.level() {
            tracing_core::Level::INFO => metrics::inc_counter_vec(&DEP_INFOS_TOTAL, target),
            tracing_core::Level::WARN => metrics::inc_counter_vec(&DEP_WARNS_TOTAL, target),
            tracing_core::Level::ERROR => metrics::inc_counter_vec(&DEP_ERRORS_TOTAL, target),
            _ => {}
        }
    }
}
