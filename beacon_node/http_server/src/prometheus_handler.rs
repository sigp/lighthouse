use beacon_chain::BeaconChain;
use iron::{status::Status, Handler, IronResult, Request, Response};
use prometheus::{Encoder, IntCounter, Opts, Registry, TextEncoder};
use std::sync::Arc;
use types::{EthSpec, Slot};

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
        let r = Registry::new();

        let present_slot = if let Ok(Some(slot)) = self.beacon_chain.slot_clock.present_slot() {
            slot
        } else {
            Slot::new(0)
        };
        register_and_set_slot(
            &r,
            "present_slot",
            "direct_slock_clock_reading",
            present_slot,
        );

        // Gather the metrics.
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        let metric_families = r.gather();
        encoder.encode(&metric_families, &mut buffer).unwrap();

        let prom_string = String::from_utf8(buffer).unwrap();

        Ok(Response::with((Status::Ok, prom_string)))
    }
}

fn register_and_set_slot(registry: &Registry, name: &str, help: &str, slot: Slot) {
    let counter_opts = Opts::new(name, help);
    let counter = IntCounter::with_opts(counter_opts).unwrap();
    registry.register(Box::new(counter.clone())).unwrap();
    counter.inc_by(slot.as_u64() as i64);
}
