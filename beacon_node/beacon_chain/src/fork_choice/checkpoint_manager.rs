use super::Error;
use crate::{metrics, BeaconChain, BeaconChainTypes};
use proto_array_fork_choice::ProtoArrayForkChoice;
use ssz_derive::{Decode, Encode};
use types::{BeaconState, Checkpoint, Epoch, EthSpec, Hash256, Slot};

const MAX_BALANCE_CACHE_SIZE: usize = 4;

/// An item that is stored in the `BalancesCache`.
#[derive(PartialEq, Clone, Encode, Decode)]
struct CacheItem {
    /// The block root at which `self.balances` are valid.
    block_root: Hash256,
    /// The `state.balances` list.
    balances: Vec<u64>,
}

/// Provides a cache to avoid reading `BeaconState` from disk when updating the current justified
/// checkpoint.
///
/// It should store a mapping of `epoch_boundary_block_root -> state.balances`.
#[derive(PartialEq, Clone, Default, Encode, Decode)]
struct BalancesCache {
    items: Vec<CacheItem>,
}

impl BalancesCache {
    /// Inspect the given `state` and determine the root of the block at the first slot of
    /// `state.current_epoch`. If there is not already some entry for the given block root, then
    /// add `state.balances` to the cache.
    pub fn process_state<E: EthSpec>(
        &mut self,
        block_root: Hash256,
        state: &BeaconState<E>,
    ) -> Result<(), Error> {
        // We are only interested in balances from states that are at the start of an epoch,
        // because this is where the `current_justified_checkpoint.root` will point.
        if !Self::is_first_block_in_epoch(block_root, state)? {
            return Ok(());
        }

        let epoch_boundary_slot = state.current_epoch().start_slot(E::slots_per_epoch());
        let epoch_boundary_root = if epoch_boundary_slot == state.slot {
            block_root
        } else {
            // This call remains sensible as long as `state.block_roots` is larger than a single
            // epoch.
            *state.get_block_root(epoch_boundary_slot)?
        };

        if self.position(epoch_boundary_root).is_none() {
            let item = CacheItem {
                block_root: epoch_boundary_root,
                balances: get_effective_balances(state),
            };

            if self.items.len() == MAX_BALANCE_CACHE_SIZE {
                self.items.remove(0);
            }

            self.items.push(item);
        }

        Ok(())
    }

    /// Returns `true` if the given `block_root` is the first/only block to have been processed in
    /// the epoch of the given `state`.
    ///
    /// We can determine if it is the first block by looking back through `state.block_roots` to
    /// see if there is a block in the current epoch with a different root.
    fn is_first_block_in_epoch<E: EthSpec>(
        block_root: Hash256,
        state: &BeaconState<E>,
    ) -> Result<bool, Error> {
        let mut prior_block_found = false;

        for slot in state.current_epoch().slot_iter(E::slots_per_epoch()) {
            if slot < state.slot {
                if *state.get_block_root(slot)? != block_root {
                    prior_block_found = true;
                    break;
                }
            } else {
                break;
            }
        }

        Ok(!prior_block_found)
    }

    fn position(&self, block_root: Hash256) -> Option<usize> {
        self.items
            .iter()
            .position(|item| item.block_root == block_root)
    }

    /// Get the balances for the given `block_root`, if any.
    ///
    /// If some balances are found, they are removed from the cache.
    pub fn get(&mut self, block_root: Hash256) -> Option<Vec<u64>> {
        let i = self.position(block_root)?;
        Some(self.items.remove(i).balances)
    }
}

/// Returns the effective balances for every validator in the given `state`.
///
/// Any validator who is not active in the epoch of the given `state` is assigned a balance of
/// zero.
pub fn get_effective_balances<T: EthSpec>(state: &BeaconState<T>) -> Vec<u64> {
    state
        .validators
        .iter()
        .map(|validator| {
            if validator.is_active_at(state.current_epoch()) {
                validator.effective_balance
            } else {
                0
            }
        })
        .collect()
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
    /// Importantly, these are _not_ the balances of the first state that we saw that has
    /// `self.epoch` and `self.root` as `state.current_justified_checkpoint`. These are the
    /// balances of the state from the block with `state.current_justified_checkpoint.root`.
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

/// A pair of checkpoints, representing `state.current_justified_checkpoint` and
/// `state.finalized_checkpoint` for some `BeaconState`.
#[derive(PartialEq, Clone, Encode, Decode)]
pub struct FFGCheckpoints {
    pub justified: CheckpointWithBalances,
    pub finalized: Checkpoint,
}

/// A struct to manage the justified and finalized checkpoints to be used for `ForkChoice`.
///
/// This struct exists to manage the `should_update_justified_checkpoint` logic in the fork choice
/// section of the spec:
///
/// https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/fork-choice.md#should_update_justified_checkpoint
#[derive(PartialEq, Clone, Encode, Decode)]
pub struct CheckpointManager {
    /// The current FFG checkpoints that should be used for finding the head.
    pub current: FFGCheckpoints,
    /// The best-known checkpoints that should be moved to `self.current` when the time is right.
    best: FFGCheckpoints,
    /// The epoch at which `self.current` should become `self.best`, if any.
    update_at: Option<Epoch>,
    /// A cached used to try and avoid DB reads when updating `self.current` and `self.best`.
    balances_cache: BalancesCache,
}

impl CheckpointManager {
    /// Create a new checkpoint cache from `genesis_checkpoint` derived from the genesis block.
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

    /// Potentially updates `self.current`, if the conditions are correct.
    ///
    /// Should be called before running the fork choice `find_head` function to ensure
    /// `self.current` is up-to-date.
    pub fn maybe_update<T: BeaconChainTypes>(
        &mut self,
        current_slot: Slot,
        chain: &BeaconChain<T>,
    ) -> Result<(), Error> {
        if self.best.justified.epoch > self.current.justified.epoch {
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

            // Using the given `state`, determine its ancestor at the slot of our current justified
            // epoch. Later, this will be compared to the root of the current justified checkpoint
            // to determine if this state is descendant of our current justified state.
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
                .get_block(&block_root)?
                .ok_or_else(|| Error::UnknownJustifiedBlock(block_root))?;

            let state = chain
                .get_state_caching_only_with_committee_caches(&block.state_root, Some(block.slot))?
                .ok_or_else(|| Error::UnknownJustifiedState(block.state_root))?;

            Ok(get_effective_balances(&state))
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
