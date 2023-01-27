use state_processing::SigVerifiedOp;
use std::collections::{hash_map::Entry, HashMap};
use std::sync::Arc;
use types::{
    AbstractExecPayload, BeaconState, ChainSpec, EthSpec, SignedBeaconBlock,
    SignedBlsToExecutionChange,
};

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
    ) -> bool {
        // Wrap in an `Arc` once on insert.
        let verified_change = Arc::new(verified_change);
        match self
            .by_validator_index
            .entry(verified_change.as_inner().message.validator_index)
        {
            Entry::Vacant(entry) => {
                self.queue.push(verified_change.clone());
                entry.insert(verified_change);
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
}
