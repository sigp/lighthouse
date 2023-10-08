use slog::{debug, Logger};
use std::cmp;
use std::collections::BTreeMap;
use types::{Checkpoint, Epoch, Eth1Data, Hash256 as Root};

/// The default size of the cache.
/// The beacon chain only looks at the last 4 epochs for finalization.
/// Add 1 for current epoch and 4 earlier epochs.
pub const DEFAULT_ETH1_CACHE_SIZE: usize = 5;

/// These fields are named the same as the corresponding fields in the `BeaconState`
/// as this structure stores these values from the `BeaconState` at a `Checkpoint`
#[derive(Clone)]
pub struct Eth1FinalizationData {
    pub eth1_data: Eth1Data,
    pub eth1_deposit_index: u64,
}

impl Eth1FinalizationData {
    /// Ensures the deposit finalization conditions have been met. See:
    /// https://eips.ethereum.org/EIPS/eip-4881#deposit-finalization-conditions
    fn fully_imported(&self) -> bool {
        self.eth1_deposit_index >= self.eth1_data.deposit_count
    }
}

/// Implements map from Checkpoint -> Eth1CacheData
pub struct CheckpointMap {
    capacity: usize,
    // There shouldn't be more than a couple of potential checkpoints at the same
    // epoch. Searching through a vector for the matching Root should be faster
    // than using another map from Root->Eth1CacheData
    store: BTreeMap<Epoch, Vec<(Root, Eth1FinalizationData)>>,
}

impl Default for CheckpointMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Provides a map of `Eth1CacheData` referenced by `Checkpoint`
///
/// ## Cache Queuing
///
/// The cache keeps a maximum number of (`capacity`) epochs. Because there may be
/// forks at the epoch boundary, it's possible that there exists more than one
/// `Checkpoint` for the same `Epoch`. This cache will store all checkpoints for
/// a given `Epoch`. When adding data for a new `Checkpoint` would cause the number
/// of `Epoch`s stored to exceed `capacity`, the data for oldest `Epoch` is dropped
impl CheckpointMap {
    pub fn new() -> Self {
        CheckpointMap {
            capacity: DEFAULT_ETH1_CACHE_SIZE,
            store: BTreeMap::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        CheckpointMap {
            capacity: cmp::max(1, capacity),
            store: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, checkpoint: Checkpoint, eth1_finalization_data: Eth1FinalizationData) {
        self.store
            .entry(checkpoint.epoch)
            .or_default()
            .push((checkpoint.root, eth1_finalization_data));

        // faster to reduce size after the fact than do pre-checking to see
        // if the current data would increase the size of the BTreeMap
        while self.store.len() > self.capacity {
            let oldest_stored_epoch = self.store.keys().next().cloned().unwrap();
            self.store.remove(&oldest_stored_epoch);
        }
    }

    pub fn get(&self, checkpoint: &Checkpoint) -> Option<&Eth1FinalizationData> {
        match self.store.get(&checkpoint.epoch) {
            Some(vec) => {
                for (root, data) in vec {
                    if *root == checkpoint.root {
                        return Some(data);
                    }
                }
                None
            }
            None => None,
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.store.len()
    }
}

/// This cache stores `Eth1CacheData` that could potentially be finalized within 4
/// future epochs.
pub struct Eth1FinalizationCache {
    by_checkpoint: CheckpointMap,
    pending_eth1: BTreeMap<u64, Eth1Data>,
    last_finalized: Option<Eth1Data>,
    log: Logger,
}

/// Provides a cache of `Eth1CacheData` at epoch boundaries. This is used to
/// finalize deposits when a new epoch is finalized.
///
impl Eth1FinalizationCache {
    pub fn new(log: Logger) -> Self {
        Eth1FinalizationCache {
            by_checkpoint: CheckpointMap::new(),
            pending_eth1: BTreeMap::new(),
            last_finalized: None,
            log,
        }
    }

    pub fn with_capacity(log: Logger, capacity: usize) -> Self {
        Eth1FinalizationCache {
            by_checkpoint: CheckpointMap::with_capacity(capacity),
            pending_eth1: BTreeMap::new(),
            last_finalized: None,
            log,
        }
    }

    pub fn insert(&mut self, checkpoint: Checkpoint, eth1_finalization_data: Eth1FinalizationData) {
        if !eth1_finalization_data.fully_imported() {
            self.pending_eth1.insert(
                eth1_finalization_data.eth1_data.deposit_count,
                eth1_finalization_data.eth1_data.clone(),
            );
            debug!(
                self.log,
                "Eth1Cache: inserted pending eth1";
                "eth1_data.deposit_count" => eth1_finalization_data.eth1_data.deposit_count,
                "eth1_deposit_index" => eth1_finalization_data.eth1_deposit_index,
            );
        }
        self.by_checkpoint
            .insert(checkpoint, eth1_finalization_data);
    }

    pub fn finalize(&mut self, checkpoint: &Checkpoint) -> Option<Eth1Data> {
        if let Some(eth1_finalized_data) = self.by_checkpoint.get(checkpoint) {
            let finalized_deposit_index = eth1_finalized_data.eth1_deposit_index;
            let mut result = None;
            while let Some(pending_count) = self.pending_eth1.keys().next().cloned() {
                if finalized_deposit_index >= pending_count {
                    result = self.pending_eth1.remove(&pending_count);
                    debug!(
                        self.log,
                        "Eth1Cache: dropped pending eth1";
                        "pending_count" => pending_count,
                        "finalized_deposit_index" => finalized_deposit_index,
                    );
                } else {
                    break;
                }
            }
            if eth1_finalized_data.fully_imported() {
                result = Some(eth1_finalized_data.eth1_data.clone())
            }
            if result.is_some() {
                self.last_finalized = result;
            }
            self.last_finalized.clone()
        } else {
            debug!(
                self.log,
                "Eth1Cache: cache miss";
                "epoch" => checkpoint.epoch,
            );
            None
        }
    }

    #[cfg(test)]
    pub fn by_checkpoint(&self) -> &CheckpointMap {
        &self.by_checkpoint
    }

    #[cfg(test)]
    pub fn pending_eth1(&self) -> &BTreeMap<u64, Eth1Data> {
        &self.pending_eth1
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use sloggers::null::NullLoggerBuilder;
    use sloggers::Build;
    use std::collections::HashMap;

    const SLOTS_PER_EPOCH: u64 = 32;
    const MAX_DEPOSITS: u64 = 16;
    const EPOCHS_PER_ETH1_VOTING_PERIOD: u64 = 64;

    fn eth1cache() -> Eth1FinalizationCache {
        let log_builder = NullLoggerBuilder;
        Eth1FinalizationCache::new(log_builder.build().expect("should build log"))
    }

    fn random_eth1_data(deposit_count: u64) -> Eth1Data {
        Eth1Data {
            deposit_root: Root::random(),
            deposit_count,
            block_hash: Root::random(),
        }
    }

    fn random_checkpoint(epoch: u64) -> Checkpoint {
        Checkpoint {
            epoch: epoch.into(),
            root: Root::random(),
        }
    }

    fn random_checkpoints(n: usize) -> Vec<Checkpoint> {
        let mut result = Vec::with_capacity(n);
        for epoch in 0..n {
            result.push(random_checkpoint(epoch as u64))
        }
        result
    }

    #[test]
    fn fully_imported_deposits() {
        let epochs = 16;
        let deposits_imported = 128;

        let eth1data = random_eth1_data(deposits_imported);
        let checkpoints = random_checkpoints(epochs as usize);
        let mut eth1cache = eth1cache();

        for epoch in 4..epochs {
            assert_eq!(
                eth1cache.by_checkpoint().len(),
                cmp::min((epoch - 4) as usize, DEFAULT_ETH1_CACHE_SIZE),
                "Unexpected cache size"
            );

            let checkpoint = checkpoints
                .get(epoch as usize)
                .expect("should get checkpoint");
            eth1cache.insert(
                *checkpoint,
                Eth1FinalizationData {
                    eth1_data: eth1data.clone(),
                    eth1_deposit_index: deposits_imported,
                },
            );

            let finalized_checkpoint = checkpoints
                .get((epoch - 4) as usize)
                .expect("should get finalized checkpoint");
            assert!(
                eth1cache.pending_eth1().is_empty(),
                "Deposits are fully imported so pending cache should be empty"
            );
            if epoch < 8 {
                assert_eq!(
                    eth1cache.finalize(finalized_checkpoint),
                    None,
                    "Should have cache miss"
                );
            } else {
                assert_eq!(
                    eth1cache.finalize(finalized_checkpoint),
                    Some(eth1data.clone()),
                    "Should have cache hit"
                )
            }
        }
    }

    #[test]
    fn partially_imported_deposits() {
        let epochs = 16;
        let initial_deposits_imported = 1024;
        let deposits_imported_per_epoch = MAX_DEPOSITS * SLOTS_PER_EPOCH;
        let full_import_epoch = 13;
        let total_deposits =
            initial_deposits_imported + deposits_imported_per_epoch * full_import_epoch;

        let eth1data = random_eth1_data(total_deposits);
        let checkpoints = random_checkpoints(epochs as usize);
        let mut eth1cache = eth1cache();

        for epoch in 0..epochs {
            assert_eq!(
                eth1cache.by_checkpoint().len(),
                cmp::min(epoch as usize, DEFAULT_ETH1_CACHE_SIZE),
                "Unexpected cache size"
            );

            let checkpoint = checkpoints
                .get(epoch as usize)
                .expect("should get checkpoint");
            let deposits_imported = cmp::min(
                total_deposits,
                initial_deposits_imported + deposits_imported_per_epoch * epoch,
            );
            eth1cache.insert(
                *checkpoint,
                Eth1FinalizationData {
                    eth1_data: eth1data.clone(),
                    eth1_deposit_index: deposits_imported,
                },
            );

            if epoch >= 4 {
                let finalized_epoch = epoch - 4;
                let finalized_checkpoint = checkpoints
                    .get(finalized_epoch as usize)
                    .expect("should get finalized checkpoint");
                if finalized_epoch < full_import_epoch {
                    assert_eq!(
                        eth1cache.finalize(finalized_checkpoint),
                        None,
                        "Deposits not fully finalized so cache should return no Eth1Data",
                    );
                    assert_eq!(
                        eth1cache.pending_eth1().len(),
                        1,
                        "Deposits not fully finalized. Pending eth1 cache should have 1 entry"
                    );
                } else {
                    assert_eq!(
                        eth1cache.finalize(finalized_checkpoint),
                        Some(eth1data.clone()),
                        "Deposits fully imported and finalized. Cache should return Eth1Data. finalized_deposits[{}]",
                        (initial_deposits_imported + deposits_imported_per_epoch * finalized_epoch),
                    );
                    assert!(
                        eth1cache.pending_eth1().is_empty(),
                        "Deposits fully imported and finalized. Pending cache should be empty"
                    );
                }
            }
        }
    }

    #[test]
    fn fork_at_epoch_boundary() {
        let epochs = 12;
        let deposits_imported = 128;

        let eth1data = random_eth1_data(deposits_imported);
        let checkpoints = random_checkpoints(epochs as usize);
        let mut forks = HashMap::new();
        let mut eth1cache = eth1cache();

        for epoch in 0..epochs {
            assert_eq!(
                eth1cache.by_checkpoint().len(),
                cmp::min(epoch as usize, DEFAULT_ETH1_CACHE_SIZE),
                "Unexpected cache size"
            );

            let checkpoint = checkpoints
                .get(epoch as usize)
                .expect("should get checkpoint");
            eth1cache.insert(
                *checkpoint,
                Eth1FinalizationData {
                    eth1_data: eth1data.clone(),
                    eth1_deposit_index: deposits_imported,
                },
            );
            // lets put a fork at every third epoch
            if epoch % 3 == 0 {
                let fork = random_checkpoint(epoch);
                eth1cache.insert(
                    fork,
                    Eth1FinalizationData {
                        eth1_data: eth1data.clone(),
                        eth1_deposit_index: deposits_imported,
                    },
                );
                forks.insert(epoch as usize, fork);
            }

            assert!(
                eth1cache.pending_eth1().is_empty(),
                "Deposits are fully imported so pending cache should be empty"
            );
            if epoch >= 4 {
                let finalized_epoch = (epoch - 4) as usize;
                let finalized_checkpoint = if finalized_epoch % 3 == 0 {
                    forks.get(&finalized_epoch).expect("should get fork")
                } else {
                    checkpoints
                        .get(finalized_epoch)
                        .expect("should get checkpoint")
                };
                assert_eq!(
                    eth1cache.finalize(finalized_checkpoint),
                    Some(eth1data.clone()),
                    "Should have cache hit"
                );
                if finalized_epoch >= 3 {
                    let dropped_epoch = finalized_epoch - 3;
                    if let Some(dropped_checkpoint) = forks.get(&dropped_epoch) {
                        // got checkpoint for an old fork that should no longer
                        // be in the cache because it is from too long ago
                        assert_eq!(
                            eth1cache.finalize(dropped_checkpoint),
                            None,
                            "Should have cache miss"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn massive_deposit_queue() {
        // Simulating a situation where deposits don't get imported within an eth1 voting period
        let eth1_voting_periods = 8;
        let initial_deposits_imported = 1024;
        let deposits_imported_per_epoch = MAX_DEPOSITS * SLOTS_PER_EPOCH;
        let initial_deposit_queue =
            deposits_imported_per_epoch * EPOCHS_PER_ETH1_VOTING_PERIOD * 2 + 32;
        let new_deposits_per_voting_period =
            EPOCHS_PER_ETH1_VOTING_PERIOD * deposits_imported_per_epoch / 2;

        let mut epoch_data = BTreeMap::new();
        let mut eth1s_by_count = BTreeMap::new();
        let mut eth1cache = eth1cache();
        let mut last_period_deposits = initial_deposits_imported;
        for period in 0..eth1_voting_periods {
            let period_deposits = initial_deposits_imported
                + initial_deposit_queue
                + period * new_deposits_per_voting_period;
            let period_eth1_data = random_eth1_data(period_deposits);
            eth1s_by_count.insert(period_eth1_data.deposit_count, period_eth1_data.clone());

            for epoch_mod_period in 0..EPOCHS_PER_ETH1_VOTING_PERIOD {
                let epoch = period * EPOCHS_PER_ETH1_VOTING_PERIOD + epoch_mod_period;
                let checkpoint = random_checkpoint(epoch);
                let deposits_imported = cmp::min(
                    period_deposits,
                    last_period_deposits + deposits_imported_per_epoch * epoch_mod_period,
                );
                eth1cache.insert(
                    checkpoint,
                    Eth1FinalizationData {
                        eth1_data: period_eth1_data.clone(),
                        eth1_deposit_index: deposits_imported,
                    },
                );
                epoch_data.insert(epoch, (checkpoint, deposits_imported));

                if epoch >= 4 {
                    let finalized_epoch = epoch - 4;
                    let (finalized_checkpoint, finalized_deposits) = epoch_data
                        .get(&finalized_epoch)
                        .expect("should get epoch data");

                    let pending_eth1s = eth1s_by_count.range((finalized_deposits + 1)..).count();
                    let last_finalized_eth1 = eth1s_by_count
                        .range(0..(finalized_deposits + 1))
                        .map(|(_, eth1)| eth1)
                        .last()
                        .cloned();
                    assert_eq!(
                        eth1cache.finalize(finalized_checkpoint),
                        last_finalized_eth1,
                        "finalized checkpoint mismatch",
                    );
                    assert_eq!(
                        eth1cache.pending_eth1().len(),
                        pending_eth1s,
                        "pending eth1 mismatch"
                    );
                }
            }

            // remove unneeded stuff from old epochs
            while epoch_data.len() > DEFAULT_ETH1_CACHE_SIZE {
                let oldest_stored_epoch = epoch_data
                    .keys()
                    .next()
                    .cloned()
                    .expect("should get oldest epoch");
                epoch_data.remove(&oldest_stored_epoch);
            }
            last_period_deposits = period_deposits;
        }
    }
}
