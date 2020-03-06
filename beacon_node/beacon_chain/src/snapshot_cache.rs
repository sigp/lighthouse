use crate::BeaconSnapshot;
use types::{Epoch, EthSpec, Hash256};

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
    /// Must be greater than zero. Should be greater than one.
    max_len: usize,
    head_block_root: Hash256,
    snapshots: Vec<BeaconSnapshot<T>>,
}

impl<T: EthSpec> SnapshotCache<T> {
    /// Instantiate a new cache which contains the `head` snapshot.
    pub fn new(head: BeaconSnapshot<T>) -> Self {
        Self {
            max_len: 4,
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

    /// If there is a snapshot with `block_root`, clone it (with only the committee caches) and
    /// return the clone.
    pub fn get_cloned(&self, block_root: Hash256) -> Option<BeaconSnapshot<T>> {
        self.snapshots
            .iter()
            .find(|snapshot| snapshot.beacon_block_root == block_root)
            .map(|snapshot| snapshot.clone_with_only_committee_caches())
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
