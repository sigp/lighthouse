use beacon_chain::BeaconChain;
use iron::{status::Status, Handler, IronResult, Request, Response};
use prometheus::{IntCounter, Encoder, Opts, Registry, TextEncoder};
use std::sync::Arc;
use types::EthSpec;

pub struct PrometheusHandler<T, U, F, E: EthSpec> {
    pub beacon_chain: Arc<BeaconChain<T, U, F, E>>,
}

impl<T, U, F, E> PrometheusHandler<T, U, F, E> where E: EthSpec {}

impl<T, U, F, E> Handler for PrometheusHandler<T, U, F, E>
where
    E: EthSpec + 'static,
    U: slot_clock::SlotClock + Send + Sync + 'static,
    T: Send + Sync + 'static,
    F: Send + Sync + 'static,
{
    fn handle(&self, _: &mut Request) -> IronResult<Response> {
        // Create a Counter.
        let counter_opts = Opts::new("present_slot", "direct_slot_clock_reading");
        let counter = IntCounter::with_opts(counter_opts).unwrap();

        // Create a Registry and register Counter.
        let r = Registry::new();
        r.register(Box::new(counter.clone())).unwrap();

        if let Ok(Some(slot)) = self.beacon_chain.slot_clock.present_slot() {
            counter.inc_by(slot.as_u64() as i64);
        }

        // Gather the metrics.
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        let metric_families = r.gather();
        encoder.encode(&metric_families, &mut buffer).unwrap();

        let prom_string = String::from_utf8(buffer).unwrap();

        Ok(Response::with((Status::Ok, prom_string)))
    }
}
