use crate::BeaconSnapshot;
use types::{Epoch, EthSpec, Hash256};

pub struct SnapshotCache<T: EthSpec> {
    max_len: usize,
    head_block_root: Hash256,
    checkpoints: Vec<BeaconSnapshot<T>>,
}

impl<T: EthSpec> SnapshotCache<T> {
    pub fn new(head: BeaconSnapshot<T>) -> Self {
        Self {
            max_len: 4,
            head_block_root: head.beacon_block_root,
            checkpoints: vec![head],
        }
    }

    pub fn insert(&mut self, checkpoint: BeaconSnapshot<T>) {
        if self.checkpoints.len() < self.max_len {
            self.checkpoints.push(checkpoint);
        } else {
            let insert_at = self
                .checkpoints
                .iter()
                .enumerate()
                .filter_map(|(i, checkpoint)| {
                    if checkpoint.beacon_block_root != self.head_block_root {
                        Some((i, checkpoint.beacon_state.slot))
                    } else {
                        None
                    }
                })
                .min_by_key(|(_i, slot)| *slot)
                .map(|(i, _slot)| i);

            if let Some(i) = insert_at {
                self.checkpoints[i] = checkpoint;
            }
        }
    }

    pub fn get(&mut self, block_root: Hash256) -> Option<BeaconSnapshot<T>> {
        self.checkpoints
            .iter()
            .position(|checkpoint| checkpoint.beacon_block_root == block_root)
            .map(|i| self.checkpoints.remove(i))
    }

    pub fn prune(&mut self, finalized_epoch: Epoch) {
        self.checkpoints.retain(|checkpoint| {
            checkpoint.beacon_state.slot > finalized_epoch.start_slot(T::slots_per_epoch())
        })
    }

    pub fn update_head(&mut self, head_block_root: Hash256) {
        self.head_block_root = head_block_root
    }
}
