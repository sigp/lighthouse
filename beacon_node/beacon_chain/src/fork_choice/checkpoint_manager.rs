use super::Error;
use crate::{metrics, BeaconChain, BeaconChainTypes};
use proto_array_fork_choice::ProtoArrayForkChoice;
use ssz_derive::{Decode, Encode};
use types::{BeaconState, Checkpoint, Epoch, EthSpec, Hash256, Slot};

const MAX_BALANCE_CACHE_SIZE: usize = 4;

#[derive(PartialEq, Clone, Encode, Decode)]
struct CacheItem {
    block_root: Hash256,
    balances: Vec<u64>,
}

#[derive(PartialEq, Clone, Default, Encode, Decode)]
struct BalancesCache {
    items: Vec<CacheItem>,
}

impl BalancesCache {
    pub fn process_state<E: EthSpec>(
        &mut self,
        block_root: Hash256,
        state: &BeaconState<E>,
    ) -> Result<(), Error> {
        let epoch_boundary_slot = state.current_epoch().start_slot(E::slots_per_epoch());
        let epoch_boundary_root = if epoch_boundary_slot == state.slot {
            block_root
        } else {
            *state.get_block_root(epoch_boundary_slot)?
        };

        if self.position(epoch_boundary_root).is_none() {
            let item = CacheItem {
                block_root: epoch_boundary_root,
                balances: state.balances.clone().into(),
            };

            if self.items.len() == MAX_BALANCE_CACHE_SIZE {
                self.items.remove(0);
            }

            self.items.push(item);
        }

        Ok(())
    }

    fn position(&self, block_root: Hash256) -> Option<usize> {
        self.items
            .iter()
            .position(|item| item.block_root == block_root)
    }

    pub fn get(&mut self, block_root: Hash256) -> Option<Vec<u64>> {
        let i = self.position(block_root)?;
        Some(self.items.remove(i).balances)
    }
}

/// A `types::Checkpoint` that also stores the validator balances from a `BeaconState`.
///
/// Useful because we need to track the justified checkpoint balances.
#[derive(PartialEq, Clone, Encode, Decode)]
pub struct CheckpointWithBalances {
    pub epoch: Epoch,
    pub root: Hash256,
    /// These are the balances of the state with `self.root`.
    ///
    /// Importantly, these are _not_ the balances of the first state that we saw with a matching
    /// `state.current_justified_checkpoint`.
    pub balances: Vec<u64>,
}

impl Into<Checkpoint> for CheckpointWithBalances {
    fn into(self) -> Checkpoint {
        Checkpoint {
            epoch: self.epoch,
            root: self.root,
        }
    }
}

#[derive(PartialEq, Clone, Encode, Decode)]
pub struct FFGCheckpoints {
    pub justified: CheckpointWithBalances,
    pub finalized: Checkpoint,
}

#[derive(PartialEq, Clone, Encode, Decode)]
pub struct CheckpointManager {
    pub current: FFGCheckpoints,
    best: FFGCheckpoints,
    update_at: Option<Epoch>,
    balances_cache: BalancesCache,
}

impl CheckpointManager {
    pub fn new(genesis_checkpoint: CheckpointWithBalances) -> Self {
        let ffg_checkpoint = FFGCheckpoints {
            justified: genesis_checkpoint.clone(),
            finalized: genesis_checkpoint.into(),
        };
        Self {
            current: ffg_checkpoint.clone(),
            best: ffg_checkpoint,
            update_at: None,
            balances_cache: BalancesCache::default(),
        }
    }

    pub fn update<T: BeaconChainTypes>(&mut self, chain: &BeaconChain<T>) -> Result<(), Error> {
        if self.best.justified.epoch > self.current.justified.epoch {
            let current_slot = chain.slot()?;
            let current_epoch = current_slot.epoch(T::EthSpec::slots_per_epoch());

            match self.update_at {
                None => {
                    if self.best.justified.epoch > self.current.justified.epoch {
                        if Self::compute_slots_since_epoch_start::<T>(current_slot)
                            < chain.spec.safe_slots_to_update_justified
                        {
                            self.current = self.best.clone();
                        } else {
                            self.update_at = Some(current_epoch + 1)
                        }
                    }
                }
                Some(epoch) if epoch <= current_epoch => {
                    self.current = self.best.clone();
                    self.update_at = None
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Checks the given `state` (must correspond to the given `block_root`) to see if it contains
    /// a `current_justified_checkpoint` that is better than `self.best_justified_checkpoint`. If
    /// so, the value is updated.
    ///
    /// Note: this does not update `self.justified_checkpoint`.
    pub fn process_state<T: BeaconChainTypes>(
        &mut self,
        block_root: Hash256,
        state: &BeaconState<T::EthSpec>,
        chain: &BeaconChain<T>,
        proto_array: &ProtoArrayForkChoice,
    ) -> Result<(), Error> {
        // Only proceed if the new checkpoint is better than our current checkpoint.
        if state.current_justified_checkpoint.epoch > self.current.justified.epoch
            && state.finalized_checkpoint.epoch >= self.current.finalized.epoch
        {
            let candidate = FFGCheckpoints {
                justified: CheckpointWithBalances {
                    epoch: state.current_justified_checkpoint.epoch,
                    root: state.current_justified_checkpoint.root,
                    balances: self
                        .get_balances_for_block(state.current_justified_checkpoint.root, chain)?,
                },
                finalized: state.finalized_checkpoint.clone(),
            };

            // From the given state, read the block root at first slot of
            // `self.justified_checkpoint.epoch`. If that root matches, then
            // `new_justified_checkpoint` is a descendant of `self.justified_checkpoint` and we may
            // proceed (see next `if` statement).
            let new_checkpoint_ancestor = Self::get_block_root_at_slot(
                state,
                chain,
                candidate.justified.root,
                self.current
                    .justified
                    .epoch
                    .start_slot(T::EthSpec::slots_per_epoch()),
            )?;

            let candidate_justified_block_slot = proto_array
                .block_slot(&candidate.justified.root)
                .ok_or_else(|| Error::UnknownBlockSlot(candidate.justified.root))?;

            // If the new justified checkpoint is an ancestor of the current justified checkpoint,
            // it is always safe to change it.
            if new_checkpoint_ancestor == Some(self.current.justified.root)
                && candidate_justified_block_slot
                    >= candidate
                        .justified
                        .epoch
                        .start_slot(T::EthSpec::slots_per_epoch())
            {
                self.current = candidate.clone()
            }

            if candidate.justified.epoch > self.best.justified.epoch {
                // Always update the best checkpoint, if it's better.
                self.best = candidate;
            }

            // Add the state's balances to the balances cache to avoid a state read later.
            self.balances_cache.process_state(block_root, state)?;
        }

        Ok(())
    }

    fn get_balances_for_block<T: BeaconChainTypes>(
        &mut self,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Result<Vec<u64>, Error> {
        if let Some(balances) = self.balances_cache.get(block_root) {
            metrics::inc_counter(&metrics::BALANCES_CACHE_HITS);

            Ok(balances)
        } else {
            metrics::inc_counter(&metrics::BALANCES_CACHE_MISSES);

            let block = chain
                .get_block_caching(&block_root)?
                .ok_or_else(|| Error::UnknownJustifiedBlock(block_root))?;

            let state = chain
                .get_state_caching_only_with_committee_caches(&block.state_root, Some(block.slot))?
                .ok_or_else(|| Error::UnknownJustifiedState(block.state_root))?;

            Ok(state.balances.into())
        }
    }

    /// Attempts to get the block root for the given `slot`.
    ///
    /// First, the `state` is used to see if the slot is within the distance of its historical
    /// lists. Then, the `chain` is used which will anchor the search at the given
    /// `justified_root`.
    fn get_block_root_at_slot<T: BeaconChainTypes>(
        state: &BeaconState<T::EthSpec>,
        chain: &BeaconChain<T>,
        justified_root: Hash256,
        slot: Slot,
    ) -> Result<Option<Hash256>, Error> {
        match state.get_block_root(slot) {
            Ok(root) => Ok(Some(*root)),
            Err(_) => chain
                .get_ancestor_block_root(justified_root, slot)
                .map_err(Into::into),
        }
    }

    /// Calculate how far `slot` lies from the start of its epoch.
    fn compute_slots_since_epoch_start<T: BeaconChainTypes>(slot: Slot) -> u64 {
        let slots_per_epoch = T::EthSpec::slots_per_epoch();
        (slot - slot.epoch(slots_per_epoch).start_slot(slots_per_epoch)).as_u64()
    }
}
