//! Exposes [`MetricsLayer`]: A tracing layer that registers metrics of logging events.

use lighthouse_metrics as metrics;

lazy_static! {
    pub static ref DEP_INFOS_TOTAL: metrics::Result<metrics::IntCounterVec> =
        metrics::try_create_int_counter_vec(
            "dep_info_total",
            "Count of infos logged per enabled dependecy",
            &["target"]
        );
    pub static ref DEP_WARNS_TOTAL: metrics::Result<metrics::IntCounterVec> =
        metrics::try_create_int_counter_vec(
            "dep_warn_total",
            "Count of warns logged per enabled dependecy",
            &["target"]
        );
    pub static ref DEP_ERRORS_TOTAL: metrics::Result<metrics::IntCounterVec> =
        metrics::try_create_int_counter_vec(
            "dep_error_total",
            "Count of errors logged per enabled dependecy",
            &["target"]
        );
}

pub struct MetricsLayer {}

impl<S: tracing_core::Subscriber> tracing_subscriber::layer::Layer<S> for MetricsLayer {
    fn on_event(
        &self,
        event: &tracing_core::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let meta = event.metadata();
        if !meta.is_event() {
            return;
        }
        let target = match meta.target().split_once("::") {
            Some((crate_name, _)) => crate_name,
            None => "unknown" /* TODO(@divma): not sure if leaving here the full target is a good idea, maybe? maybe not?*/,
        };
        let target = &[target];
        match meta.level() {
            &tracing_core::Level::INFO => metrics::inc_counter_vec(&DEP_INFOS_TOTAL, target),
            &tracing_core::Level::WARN => metrics::inc_counter_vec(&DEP_WARNS_TOTAL, target),
            &tracing_core::Level::ERROR => metrics::inc_counter_vec(&DEP_ERRORS_TOTAL, target),
            _ => {}
        }
    }
}
