use state_processing::SigVerifiedOp;
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::sync::Arc;
use types::{
    AbstractExecPayload, BeaconState, ChainSpec, EthSpec, SignedBeaconBlock,
    SignedBlsToExecutionChange,
};

/// Indicates if a `BlsToExecutionChange` was received before or after the
/// Capella fork. This is used to know which messages we should broadcast at the
/// Capella fork epoch.
#[derive(Copy, Clone)]
pub enum ReceivedPreCapella {
    Yes,
    No,
}

/// Pool of BLS to execution changes that maintains a LIFO queue and an index by validator.
///
/// Using the LIFO queue for block production disincentivises spam on P2P at the Capella fork,
/// and is less-relevant after that.
#[derive(Debug, Default)]
pub struct BlsToExecutionChanges<T: EthSpec> {
    /// Map from validator index to BLS to execution change.
    by_validator_index: HashMap<u64, Arc<SigVerifiedOp<SignedBlsToExecutionChange, T>>>,
    /// Last-in-first-out (LIFO) queue of verified messages.
    queue: Vec<Arc<SigVerifiedOp<SignedBlsToExecutionChange, T>>>,
    /// Contains a set of validator indices which need to have their changes
    /// broadcast at the capella epoch.
    received_pre_capella_indices: HashSet<u64>,
}

impl<T: EthSpec> BlsToExecutionChanges<T> {
    pub fn existing_change_equals(
        &self,
        address_change: &SignedBlsToExecutionChange,
    ) -> Option<bool> {
        self.by_validator_index
            .get(&address_change.message.validator_index)
            .map(|existing| existing.as_inner() == address_change)
    }

    pub fn insert(
        &mut self,
        verified_change: SigVerifiedOp<SignedBlsToExecutionChange, T>,
        received_pre_capella: ReceivedPreCapella,
    ) -> bool {
        let validator_index = verified_change.as_inner().message.validator_index;
        // Wrap in an `Arc` once on insert.
        let verified_change = Arc::new(verified_change);
        match self.by_validator_index.entry(validator_index) {
            Entry::Vacant(entry) => {
                self.queue.push(verified_change.clone());
                entry.insert(verified_change);
                if matches!(received_pre_capella, ReceivedPreCapella::Yes) {
                    self.received_pre_capella_indices.insert(validator_index);
                }
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    /// FIFO ordering, used for persistence to disk.
    pub fn iter_fifo(
        &self,
    ) -> impl Iterator<Item = &Arc<SigVerifiedOp<SignedBlsToExecutionChange, T>>> {
        self.queue.iter()
    }

    /// LIFO ordering, used for block packing.
    pub fn iter_lifo(
        &self,
    ) -> impl Iterator<Item = &Arc<SigVerifiedOp<SignedBlsToExecutionChange, T>>> {
        self.queue.iter().rev()
    }

    /// Returns only those which are flagged for broadcasting at the Capella
    /// fork. Uses FIFO ordering, although we expect this list to be shuffled by
    /// the caller.
    pub fn iter_received_pre_capella(
        &self,
    ) -> impl Iterator<Item = &Arc<SigVerifiedOp<SignedBlsToExecutionChange, T>>> {
        self.queue.iter().filter(|address_change| {
            self.received_pre_capella_indices
                .contains(&address_change.as_inner().message.validator_index)
        })
    }

    /// Returns the set of indicies which should have their address changes
    /// broadcast at the Capella fork.
    pub fn iter_pre_capella_indices(&self) -> impl Iterator<Item = &u64> {
        self.received_pre_capella_indices.iter()
    }

    /// Prune BLS to execution changes that have been applied to the state more than 1 block ago.
    ///
    /// The block check is necessary to avoid pruning too eagerly and losing the ability to include
    /// address changes during re-orgs. This is isn't *perfect* so some address changes could
    /// still get stuck if there are gnarly re-orgs and the changes can't be widely republished
    /// due to the gossip duplicate rules.
    pub fn prune<Payload: AbstractExecPayload<T>>(
        &mut self,
        head_block: &SignedBeaconBlock<T, Payload>,
        head_state: &BeaconState<T>,
        spec: &ChainSpec,
    ) {
        let mut validator_indices_pruned = vec![];

        self.queue.retain(|address_change| {
            let validator_index = address_change.as_inner().message.validator_index;
            head_state
                .validators()
                .get(validator_index as usize)
                .map_or(true, |validator| {
                    let prune = validator.has_eth1_withdrawal_credential(spec)
                        && head_block
                            .message()
                            .body()
                            .bls_to_execution_changes()
                            .map_or(true, |recent_changes| {
                                !recent_changes
                                    .iter()
                                    .any(|c| c.message.validator_index == validator_index)
                            });
                    if prune {
                        validator_indices_pruned.push(validator_index);
                    }
                    !prune
                })
        });

        for validator_index in validator_indices_pruned {
            self.by_validator_index.remove(&validator_index);
        }
    }

    /// Removes `broadcasted` validators from the set of validators that should
    /// have their BLS changes broadcast at the Capella fork boundary.
    pub fn register_indices_broadcasted_at_capella(&mut self, broadcasted: &HashSet<u64>) {
        self.received_pre_capella_indices = self
            .received_pre_capella_indices
            .difference(broadcasted)
            .copied()
            .collect();
    }
}
