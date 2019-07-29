use beacon_chain::{BeaconChain, BeaconChainTypes};
use prometheus::{IntGauge, Opts, Registry};
use slot_clock::SlotClock;
use std::fs;
use std::path::PathBuf;
use types::{EthSpec, Slot};

// If set to `true` will iterate and sum the balances of all validators in the state for each
// scrape.
const SHOULD_SUM_VALIDATOR_BALANCES: bool = true;

pub struct LocalMetrics {
    present_slot: IntGauge,
    present_epoch: IntGauge,
    best_slot: IntGauge,
    best_beacon_block_root: IntGauge,
    justified_beacon_block_root: IntGauge,
    finalized_beacon_block_root: IntGauge,
    validator_count: IntGauge,
    justified_epoch: IntGauge,
    finalized_epoch: IntGauge,
    validator_balances_sum: IntGauge,
    database_size: IntGauge,
}

impl LocalMetrics {
    /// Create a new instance.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            present_slot: {
                let opts = Opts::new("present_slot", "slot_at_time_of_scrape");
                IntGauge::with_opts(opts)?
            },
            present_epoch: {
                let opts = Opts::new("present_epoch", "epoch_at_time_of_scrape");
                IntGauge::with_opts(opts)?
            },
            best_slot: {
                let opts = Opts::new("best_slot", "slot_of_block_at_chain_head");
                IntGauge::with_opts(opts)?
            },
            best_beacon_block_root: {
                let opts = Opts::new("best_beacon_block_root", "root_of_block_at_chain_head");
                IntGauge::with_opts(opts)?
            },
            justified_beacon_block_root: {
                let opts = Opts::new(
                    "justified_beacon_block_root",
                    "root_of_block_at_justified_head",
                );
                IntGauge::with_opts(opts)?
            },
            finalized_beacon_block_root: {
                let opts = Opts::new(
                    "finalized_beacon_block_root",
                    "root_of_block_at_finalized_head",
                );
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
            database_size: {
                let opts = Opts::new("database_size", "size_of_on_disk_db_in_mb");
                IntGauge::with_opts(opts)?
            },
        })
    }

    /// Registry this instance with the `registry`.
    pub fn register(&self, registry: &Registry) -> Result<(), prometheus::Error> {
        registry.register(Box::new(self.present_slot.clone()))?;
        registry.register(Box::new(self.present_epoch.clone()))?;
        registry.register(Box::new(self.best_slot.clone()))?;
        registry.register(Box::new(self.best_beacon_block_root.clone()))?;
        registry.register(Box::new(self.justified_beacon_block_root.clone()))?;
        registry.register(Box::new(self.finalized_beacon_block_root.clone()))?;
        registry.register(Box::new(self.validator_count.clone()))?;
        registry.register(Box::new(self.finalized_epoch.clone()))?;
        registry.register(Box::new(self.justified_epoch.clone()))?;
        registry.register(Box::new(self.validator_balances_sum.clone()))?;
        registry.register(Box::new(self.database_size.clone()))?;

        Ok(())
    }

    /// Update the metrics in `self` to the latest values.
    pub fn update<T: BeaconChainTypes>(&self, beacon_chain: &BeaconChain<T>, db_path: &PathBuf) {
        let state = &beacon_chain.head().beacon_state;

        let present_slot = beacon_chain
            .slot_clock
            .present_slot()
            .unwrap_or_else(|_| None)
            .unwrap_or_else(|| Slot::new(0));
        self.present_slot.set(present_slot.as_u64() as i64);
        self.present_epoch
            .set(present_slot.epoch(T::EthSpec::slots_per_epoch()).as_u64() as i64);

        self.best_slot.set(state.slot.as_u64() as i64);
        self.best_beacon_block_root
            .set(beacon_chain.head().beacon_block_root.to_low_u64_le() as i64);
        self.justified_beacon_block_root.set(
            beacon_chain
                .head()
                .beacon_state
                .current_justified_root
                .to_low_u64_le() as i64,
        );
        self.finalized_beacon_block_root.set(
            beacon_chain
                .head()
                .beacon_state
                .finalized_root
                .to_low_u64_le() as i64,
        );
        self.validator_count
            .set(state.validator_registry.len() as i64);
        self.justified_epoch
            .set(state.current_justified_epoch.as_u64() as i64);
        self.finalized_epoch
            .set(state.finalized_epoch.as_u64() as i64);
        if SHOULD_SUM_VALIDATOR_BALANCES {
            self.validator_balances_sum
                .set(state.balances.iter().sum::<u64>() as i64);
        }
        let db_size = if let Ok(iter) = fs::read_dir(db_path) {
            iter.filter_map(Result::ok)
                .map(size_of_dir_entry)
                .fold(0_u64, |sum, val| sum + val)
        } else {
            0
        };
        self.database_size.set(db_size as i64);
    }
}

fn size_of_dir_entry(dir: fs::DirEntry) -> u64 {
    dir.metadata().map(|m| m.len()).unwrap_or(0)
}
