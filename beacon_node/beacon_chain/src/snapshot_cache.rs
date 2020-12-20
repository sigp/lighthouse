use crate::BeaconSnapshot;
use std::cmp;
use types::{beacon_state::CloneConfig, Epoch, EthSpec, Hash256};

/// The default size of the cache.
pub const DEFAULT_SNAPSHOT_CACHE_SIZE: usize = 4;

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
    snapshots: Vec<BeaconSnapshot<T>>,
}

impl<T: EthSpec> SnapshotCache<T> {
    /// Instantiate a new cache which contains the `head` snapshot.
    ///
    /// Setting `max_len = 0` is equivalent to setting `max_len = 1`.
    pub fn new(max_len: usize, head: BeaconSnapshot<T>) -> Self {
        Self {
            max_len: cmp::max(max_len, 1),
            head_block_root: head.beacon_block_root,
            snapshots: vec![head],
        }
    }

    /// Insert a snapshot, potentially removing an existing snapshot if `self` is at capacity (see
    /// struct-level documentation for more info).
    pub fn insert(&mut self, snapshot: BeaconSnapshot<T>) {
        if self.snapshots.len() < self.max_len {
            self.snapshots.push(snapshot);
        } else {
            let insert_at = self
                .snapshots
                .iter()
                .enumerate()
                .filter_map(|(i, snapshot)| {
                    if snapshot.beacon_block_root != self.head_block_root {
                        Some((i, snapshot.beacon_state.slot))
                    } else {
                        None
                    }
                })
                .min_by_key(|(_i, slot)| *slot)
                .map(|(i, _slot)| i);

            if let Some(i) = insert_at {
                self.snapshots[i] = snapshot;
            }
        }
    }

    /// If there is a snapshot with `block_root`, remove and return it.
    pub fn try_remove(&mut self, block_root: Hash256) -> Option<BeaconSnapshot<T>> {
        self.snapshots
            .iter()
            .position(|snapshot| snapshot.beacon_block_root == block_root)
            .map(|i| self.snapshots.remove(i))
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
            .map(|snapshot| snapshot.clone_with(clone_config))
    }

    /// Removes all snapshots from the queue that are less than or equal to the finalized epoch.
    pub fn prune(&mut self, finalized_epoch: Epoch) {
        self.snapshots.retain(|snapshot| {
            snapshot.beacon_state.slot > finalized_epoch.start_slot(T::slots_per_epoch())
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
    use types::{
        test_utils::{generate_deterministic_keypair, TestingBeaconStateBuilder},
        BeaconBlock, Epoch, MainnetEthSpec, SignedBeaconBlock, Slot,
    };

    const CACHE_SIZE: usize = 4;

    fn get_snapshot(i: u64) -> BeaconSnapshot<MainnetEthSpec> {
        let spec = MainnetEthSpec::default_spec();

        let state_builder = TestingBeaconStateBuilder::from_deterministic_keypairs(1, &spec);
        let (beacon_state, _keypairs) = state_builder.build();

        BeaconSnapshot {
            beacon_state,
            beacon_state_root: Hash256::from_low_u64_be(i),
            beacon_block: SignedBeaconBlock {
                message: BeaconBlock::empty(&spec),
                signature: generate_deterministic_keypair(0)
                    .sk
                    .sign(Hash256::from_low_u64_be(42)),
            },
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
            snapshot.beacon_state.slot = Slot::from(i * MainnetEthSpec::slots_per_epoch() + 1);

            cache.insert(snapshot);

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
        cache.insert(get_snapshot(42));
        assert_eq!(cache.snapshots.len(), CACHE_SIZE);

        assert!(
            cache.try_remove(Hash256::from_low_u64_be(1)).is_none(),
            "the snapshot with the lowest slot should have been removed during the insert function"
        );
        assert!(cache
            .get_cloned(Hash256::from_low_u64_be(1), CloneConfig::none())
            .is_none());

        assert!(
            cache
                .get_cloned(Hash256::from_low_u64_be(0), CloneConfig::none())
                .expect("the head should still be in the cache")
                .beacon_block_root
                == Hash256::from_low_u64_be(0),
            "get_cloned should get the correct snapshot"
        );
        assert!(
            cache
                .try_remove(Hash256::from_low_u64_be(0))
                .expect("the head should still be in the cache")
                .beacon_block_root
                == Hash256::from_low_u64_be(0),
            "try_remove should get the correct snapshot"
        );

        assert_eq!(
            cache.snapshots.len(),
            CACHE_SIZE - 1,
            "try_remove should shorten the cache"
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
            cache.insert(get_snapshot(u64::max_value() - i));
        }

        // Ensure that the new head value was not removed from the cache.
        assert!(
            cache
                .try_remove(Hash256::from_low_u64_be(2))
                .expect("the new head should still be in the cache")
                .beacon_block_root
                == Hash256::from_low_u64_be(2),
            "try_remove should get the correct snapshot"
        );
    }
}
