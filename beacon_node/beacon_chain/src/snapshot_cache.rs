use crate::BeaconSnapshot;
use std::cmp;
use types::{
    beacon_state::CloneConfig, BeaconState, Epoch, EthSpec, Hash256, SignedBeaconBlock, Slot,
};

/// The default size of the cache.
pub const DEFAULT_SNAPSHOT_CACHE_SIZE: usize = 4;

/// This snapshot is to be used for verifying a child of `self.beacon_block`.
#[derive(Debug)]
pub struct PreProcessingSnapshot<T: EthSpec> {
    /// This state is equivalent to the `self.beacon_block.state_root()` state that has been
    /// advanced forward one slot using `per_slot_processing`. This state is "primed and ready" for
    /// the application of another block.
    pub pre_state: BeaconState<T>,
    /// This value is only set to `Some` if the `pre_state` was *not* advanced forward.
    pub beacon_state_root: Option<Hash256>,
    pub beacon_block: SignedBeaconBlock<T>,
    pub beacon_block_root: Hash256,
}

impl<T: EthSpec> From<BeaconSnapshot<T>> for PreProcessingSnapshot<T> {
    fn from(snapshot: BeaconSnapshot<T>) -> Self {
        let beacon_state_root = Some(snapshot.beacon_state_root());
        Self {
            pre_state: snapshot.beacon_state,
            beacon_state_root,
            beacon_block: snapshot.beacon_block,
            beacon_block_root: snapshot.beacon_block_root,
        }
    }
}

impl<T: EthSpec> CacheItem<T> {
    pub fn new_without_pre_state(snapshot: BeaconSnapshot<T>) -> Self {
        Self {
            beacon_block: snapshot.beacon_block,
            beacon_block_root: snapshot.beacon_block_root,
            beacon_state: snapshot.beacon_state,
            pre_state: None,
        }
    }

    fn clone_to_snapshot_with(&self, clone_config: CloneConfig) -> BeaconSnapshot<T> {
        BeaconSnapshot {
            beacon_state: self.beacon_state.clone_with(clone_config),
            beacon_block: self.beacon_block.clone(),
            beacon_block_root: self.beacon_block_root,
        }
    }

    pub fn into_pre_state(self) -> PreProcessingSnapshot<T> {
        // Do not include the beacon state root if the state has been advanced.
        let beacon_state_root =
            Some(self.beacon_block.state_root()).filter(|_| self.pre_state.is_none());

        PreProcessingSnapshot {
            beacon_block: self.beacon_block,
            beacon_block_root: self.beacon_block_root,
            pre_state: self.pre_state.unwrap_or(self.beacon_state),
            beacon_state_root,
        }
    }
}

/// The information required for block production.
pub struct BlockProductionPreState<T: EthSpec> {
    /// This state may or may not have been advanced forward a single slot.
    ///
    /// See the documentation in the `crate::state_advance_timer` module for more information.
    pub pre_state: BeaconState<T>,
    /// This value will only be `Some` if `self.pre_state` was **not** advanced forward a single
    /// slot.
    ///
    /// This value can be used to avoid tree-hashing the state during the first call to
    /// `per_slot_processing`.
    pub state_root: Option<Hash256>,
}

pub enum StateAdvance<T: EthSpec> {
    /// The cache does not contain the supplied block root.
    BlockNotFound,
    /// The cache contains the supplied block root but the state has already been advanced.
    AlreadyAdvanced,
    /// The cache contains the supplied block root and the state has not yet been advanced.
    State {
        state: Box<BeaconState<T>>,
        state_root: Hash256,
        block_slot: Slot,
    },
}

/// The item stored in the `SnapshotCache`.
pub struct CacheItem<T: EthSpec> {
    beacon_block: SignedBeaconBlock<T>,
    beacon_block_root: Hash256,
    /// This state is equivalent to `self.beacon_block.state_root()`.
    beacon_state: BeaconState<T>,
    /// This state is equivalent to `self.beacon_state` that has had `per_slot_processing` applied
    /// to it. This state assists in optimizing block processing.
    pre_state: Option<BeaconState<T>>,
}

impl<T: EthSpec> Into<BeaconSnapshot<T>> for CacheItem<T> {
    fn into(self) -> BeaconSnapshot<T> {
        BeaconSnapshot {
            beacon_state: self.beacon_state,
            beacon_block: self.beacon_block,
            beacon_block_root: self.beacon_block_root,
        }
    }
}

/// Provides a cache of `BeaconSnapshot` that is intended primarily for block processing.
///
/// ## Cache Queuing
///
/// The cache has a non-standard queue mechanism (specifically, it is not LRU).
///
/// The cache has a max number of elements (`max_len`). Until `max_len` is achieved, all snapshots
/// are simply added to the queue. Once `max_len` is achieved, adding a new snapshot will cause an
/// existing snapshot to be ejected. The ejected snapshot will:
///
/// - Never be the `head_block_root`.
/// - Be the snapshot with the lowest `state.slot` (ties broken arbitrarily).
pub struct SnapshotCache<T: EthSpec> {
    max_len: usize,
    head_block_root: Hash256,
    snapshots: Vec<CacheItem<T>>,
}

impl<T: EthSpec> SnapshotCache<T> {
    /// Instantiate a new cache which contains the `head` snapshot.
    ///
    /// Setting `max_len = 0` is equivalent to setting `max_len = 1`.
    pub fn new(max_len: usize, head: BeaconSnapshot<T>) -> Self {
        Self {
            max_len: cmp::max(max_len, 1),
            head_block_root: head.beacon_block_root,
            snapshots: vec![CacheItem::new_without_pre_state(head)],
        }
    }

    /// Insert a snapshot, potentially removing an existing snapshot if `self` is at capacity (see
    /// struct-level documentation for more info).
    pub fn insert(&mut self, snapshot: BeaconSnapshot<T>, pre_state: Option<BeaconState<T>>) {
        let item = CacheItem {
            beacon_block: snapshot.beacon_block,
            beacon_block_root: snapshot.beacon_block_root,
            beacon_state: snapshot.beacon_state,
            pre_state,
        };

        if self.snapshots.len() < self.max_len {
            self.snapshots.push(item);
        } else {
            let insert_at = self
                .snapshots
                .iter()
                .enumerate()
                .filter_map(|(i, snapshot)| {
                    if snapshot.beacon_block_root != self.head_block_root {
                        Some((i, snapshot.beacon_state.slot()))
                    } else {
                        None
                    }
                })
                .min_by_key(|(_i, slot)| *slot)
                .map(|(i, _slot)| i);

            if let Some(i) = insert_at {
                self.snapshots[i] = item;
            }
        }
    }

    /// If available, returns a `CacheItem` that should be used for importing/processing a block.
    /// The method will remove the block from `self`, carrying across any caches that may or may not
    /// be built.
    pub fn get_state_for_block_processing(&mut self, block_root: Hash256) -> Option<CacheItem<T>> {
        self.snapshots
            .iter()
            .position(|snapshot| snapshot.beacon_block_root == block_root)
            .map(|i| self.snapshots.remove(i))
    }

    /// If available, obtains a clone of a `BeaconState` that should be used for block production.
    /// The clone will use `CloneConfig:all()`, ensuring any tree-hash cache is cloned too.
    ///
    /// ## Note
    ///
    /// This method clones the `BeaconState` (instead of removing it) since we assume that any block
    /// we produce will soon be pushed to the `BeaconChain` for importing/processing. Keeping a copy
    /// of that `BeaconState` in `self` will greatly help with import times.
    pub fn get_state_for_block_production(
        &self,
        block_root: Hash256,
    ) -> Option<BlockProductionPreState<T>> {
        self.snapshots
            .iter()
            .find(|snapshot| snapshot.beacon_block_root == block_root)
            .map(|snapshot| {
                if let Some(pre_state) = &snapshot.pre_state {
                    BlockProductionPreState {
                        pre_state: pre_state.clone_with(CloneConfig::all()),
                        state_root: None,
                    }
                } else {
                    BlockProductionPreState {
                        pre_state: snapshot.beacon_state.clone_with(CloneConfig::all()),
                        state_root: Some(snapshot.beacon_block.state_root()),
                    }
                }
            })
    }

    /// If there is a snapshot with `block_root`, clone it and return the clone.
    pub fn get_cloned(
        &self,
        block_root: Hash256,
        clone_config: CloneConfig,
    ) -> Option<BeaconSnapshot<T>> {
        self.snapshots
            .iter()
            .find(|snapshot| snapshot.beacon_block_root == block_root)
            .map(|snapshot| snapshot.clone_to_snapshot_with(clone_config))
    }

    pub fn get_for_state_advance(&mut self, block_root: Hash256) -> StateAdvance<T> {
        if let Some(snapshot) = self
            .snapshots
            .iter_mut()
            .find(|snapshot| snapshot.beacon_block_root == block_root)
        {
            if snapshot.pre_state.is_some() {
                StateAdvance::AlreadyAdvanced
            } else {
                let cloned = snapshot
                    .beacon_state
                    .clone_with(CloneConfig::committee_caches_only());

                StateAdvance::State {
                    state: Box::new(std::mem::replace(&mut snapshot.beacon_state, cloned)),
                    state_root: snapshot.beacon_block.state_root(),
                    block_slot: snapshot.beacon_block.slot(),
                }
            }
        } else {
            StateAdvance::BlockNotFound
        }
    }

    pub fn update_pre_state(&mut self, block_root: Hash256, state: BeaconState<T>) -> Option<()> {
        self.snapshots
            .iter_mut()
            .find(|snapshot| snapshot.beacon_block_root == block_root)
            .map(|snapshot| {
                snapshot.pre_state = Some(state);
            })
    }

    /// Removes all snapshots from the queue that are less than or equal to the finalized epoch.
    pub fn prune(&mut self, finalized_epoch: Epoch) {
        self.snapshots.retain(|snapshot| {
            snapshot.beacon_state.slot() > finalized_epoch.start_slot(T::slots_per_epoch())
        })
    }

    /// Inform the cache that the head of the beacon chain has changed.
    ///
    /// The snapshot that matches this `head_block_root` will never be ejected from the cache
    /// during `Self::insert`.
    pub fn update_head(&mut self, head_block_root: Hash256) {
        self.head_block_root = head_block_root
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::{BeaconChainHarness, EphemeralHarnessType};
    use types::{
        test_utils::generate_deterministic_keypair, BeaconBlock, Epoch, MainnetEthSpec,
        SignedBeaconBlock, Slot,
    };

    fn get_harness() -> BeaconChainHarness<EphemeralHarnessType<MainnetEthSpec>> {
        let harness = BeaconChainHarness::builder(MainnetEthSpec)
            .default_spec()
            .deterministic_keypairs(1)
            .fresh_ephemeral_store()
            .build();

        harness.advance_slot();

        harness
    }

    const CACHE_SIZE: usize = 4;

    fn get_snapshot(i: u64) -> BeaconSnapshot<MainnetEthSpec> {
        let spec = MainnetEthSpec::default_spec();

        let beacon_state = get_harness().chain.head_beacon_state().unwrap();

        let signed_beacon_block = SignedBeaconBlock::from_block(
            BeaconBlock::empty(&spec),
            generate_deterministic_keypair(0)
                .sk
                .sign(Hash256::from_low_u64_be(42)),
        );

        BeaconSnapshot {
            beacon_state,
            beacon_block: signed_beacon_block,
            beacon_block_root: Hash256::from_low_u64_be(i),
        }
    }

    #[test]
    fn insert_get_prune_update() {
        let mut cache = SnapshotCache::new(CACHE_SIZE, get_snapshot(0));

        // Insert a bunch of entries in the cache. It should look like this:
        //
        // Index    Root
        // 0        0     <--head
        // 1        1
        // 2        2
        // 3        3
        for i in 1..CACHE_SIZE as u64 {
            let mut snapshot = get_snapshot(i);

            // Each snapshot should be one slot into an epoch, with each snapshot one epoch apart.
            *snapshot.beacon_state.slot_mut() =
                Slot::from(i * MainnetEthSpec::slots_per_epoch() + 1);

            cache.insert(snapshot, None);

            assert_eq!(
                cache.snapshots.len(),
                i as usize + 1,
                "cache length should be as expected"
            );
            assert_eq!(cache.head_block_root, Hash256::from_low_u64_be(0));
        }

        // Insert a new value in the cache. Afterwards it should look like:
        //
        // Index    Root
        // 0        0     <--head
        // 1        42
        // 2        2
        // 3        3
        assert_eq!(cache.snapshots.len(), CACHE_SIZE);
        cache.insert(get_snapshot(42), None);
        assert_eq!(cache.snapshots.len(), CACHE_SIZE);

        assert!(
            cache
                .get_state_for_block_processing(Hash256::from_low_u64_be(1))
                .is_none(),
            "the snapshot with the lowest slot should have been removed during the insert function"
        );
        assert!(cache
            .get_cloned(Hash256::from_low_u64_be(1), CloneConfig::none())
            .is_none());

        assert_eq!(
            cache
                .get_cloned(Hash256::from_low_u64_be(0), CloneConfig::none())
                .expect("the head should still be in the cache")
                .beacon_block_root,
            Hash256::from_low_u64_be(0),
            "get_cloned should get the correct snapshot"
        );
        assert_eq!(
            cache
                .get_state_for_block_processing(Hash256::from_low_u64_be(0))
                .expect("the head should still be in the cache")
                .beacon_block_root,
            Hash256::from_low_u64_be(0),
            "get_state_for_block_processing should get the correct snapshot"
        );

        assert_eq!(
            cache.snapshots.len(),
            CACHE_SIZE - 1,
            "get_state_for_block_processing should shorten the cache"
        );

        // Prune the cache. Afterwards it should look like:
        //
        // Index    Root
        // 0        2
        // 1        3
        cache.prune(Epoch::new(2));

        assert_eq!(cache.snapshots.len(), 2);

        cache.update_head(Hash256::from_low_u64_be(2));

        // Over-fill the cache so it needs to eject some old values on insert.
        for i in 0..CACHE_SIZE as u64 {
            cache.insert(get_snapshot(u64::max_value() - i), None);
        }

        // Ensure that the new head value was not removed from the cache.
        assert_eq!(
            cache
                .get_state_for_block_processing(Hash256::from_low_u64_be(2))
                .expect("the new head should still be in the cache")
                .beacon_block_root,
            Hash256::from_low_u64_be(2),
            "get_state_for_block_processing should get the correct snapshot"
        );
    }
}
