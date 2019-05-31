use beacon_chain::{BeaconChain, BeaconChainTypes};
use prometheus::{IntGauge, Opts, Registry};
use slot_clock::SlotClock;
use types::Slot;

// If set to `true` will iterate and sum the balances of all validators in the state for each
// scrape.
const SHOULD_SUM_VALIDATOR_BALANCES: bool = true;

pub struct LocalMetrics {
    present_slot: IntGauge,
    best_slot: IntGauge,
    validator_count: IntGauge,
    justified_epoch: IntGauge,
    finalized_epoch: IntGauge,
    validator_balances_sum: IntGauge,
}

impl LocalMetrics {
    /// Create a new instance.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            present_slot: {
                let opts = Opts::new("present_slot", "slot_at_time_of_scrape");
                IntGauge::with_opts(opts)?
            },
            best_slot: {
                let opts = Opts::new("best_slot", "slot_of_block_at_chain_head");
                IntGauge::with_opts(opts)?
            },
            validator_count: {
                let opts = Opts::new("validator_count", "number_of_validators");
                IntGauge::with_opts(opts)?
            },
            justified_epoch: {
                let opts = Opts::new("justified_epoch", "state_justified_epoch");
                IntGauge::with_opts(opts)?
            },
            finalized_epoch: {
                let opts = Opts::new("finalized_epoch", "state_finalized_epoch");
                IntGauge::with_opts(opts)?
            },
            validator_balances_sum: {
                let opts = Opts::new("validator_balances_sum", "sum_of_all_validator_balances");
                IntGauge::with_opts(opts)?
            },
        })
    }

    /// Registry this instance with the `registry`.
    pub fn register(&self, registry: &Registry) -> Result<(), prometheus::Error> {
        registry.register(Box::new(self.present_slot.clone()))?;
        registry.register(Box::new(self.best_slot.clone()))?;
        registry.register(Box::new(self.validator_count.clone()))?;
        registry.register(Box::new(self.finalized_epoch.clone()))?;
        registry.register(Box::new(self.justified_epoch.clone()))?;
        registry.register(Box::new(self.validator_balances_sum.clone()))?;

        Ok(())
    }

    /// Update the metrics in `self` to the latest values.
    pub fn update<T: BeaconChainTypes>(&self, beacon_chain: &BeaconChain<T>) {
        let state = &beacon_chain.head().beacon_state;

        let present_slot = beacon_chain
            .slot_clock
            .present_slot()
            .unwrap_or_else(|_| None)
            .unwrap_or_else(|| Slot::new(0));
        self.present_slot.set(present_slot.as_u64() as i64);

        self.best_slot.set(state.slot.as_u64() as i64);
        self.validator_count.set(state.validator_registry.len() as i64);
        self.justified_epoch.set(state.current_justified_epoch.as_u64() as i64);
        self.finalized_epoch.set(state.finalized_epoch.as_u64() as i64);
        if SHOULD_SUM_VALIDATOR_BALANCES {
            self.validator_balances_sum.set(state.validator_balances.iter().sum::<u64>() as i64);
        }
    }
}
