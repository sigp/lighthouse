use crate::ExecutionOptimistic;
use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::types::StateId as CoreStateId;
use std::fmt;
use std::str::FromStr;
use types::{BeaconState, Checkpoint, EthSpec, Fork, Hash256, Slot};

/// Wraps `eth2::types::StateId` and provides common state-access functionality. E.g., reading
/// states or parts of states from the database.
#[derive(Debug)]
pub struct StateId(pub CoreStateId);

// More clarity when returning if the state is finalized or not in the root function.
type Finalized = bool;

impl StateId {
    pub fn from_slot(slot: Slot) -> Self {
        Self(CoreStateId::Slot(slot))
    }

    /// Return the state root identified by `self`.
    pub fn root<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<(Hash256, ExecutionOptimistic, Finalized), warp::Rejection> {
        let (slot, execution_optimistic, finalized) = match &self.0 {
            CoreStateId::Head => {
                let (cached_head, execution_status) = chain
                    .canonical_head
                    .head_and_execution_status()
                    .map_err(warp_utils::reject::beacon_chain_error)?;
                return Ok((
                    cached_head.head_state_root(),
                    execution_status.is_optimistic_or_invalid(),
                    false,
                ));
            }
            CoreStateId::Genesis => return Ok((chain.genesis_state_root, false, true)),
            CoreStateId::Finalized => {
                let finalized_checkpoint =
                    chain.canonical_head.cached_head().finalized_checkpoint();
                let (slot, execution_optimistic) =
                    checkpoint_slot_and_execution_optimistic(chain, finalized_checkpoint)?;
                (slot, execution_optimistic, true)
            }
            CoreStateId::Justified => {
                let justified_checkpoint =
                    chain.canonical_head.cached_head().justified_checkpoint();
                let (slot, execution_optimistic) =
                    checkpoint_slot_and_execution_optimistic(chain, justified_checkpoint)?;
                (slot, execution_optimistic, false)
            }
            CoreStateId::Slot(slot) => (
                *slot,
                chain
                    .is_optimistic_or_invalid_head()
                    .map_err(warp_utils::reject::beacon_chain_error)?,
                *slot
                    <= chain
                        .canonical_head
                        .cached_head()
                        .finalized_checkpoint()
                        .epoch
                        .start_slot(T::EthSpec::slots_per_epoch()),
            ),
            CoreStateId::Root(root) => {
                if let Some(hot_summary) = chain
                    .store
                    .load_hot_state_summary(root)
                    .map_err(BeaconChainError::DBError)
                    .map_err(warp_utils::reject::beacon_chain_error)?
                {
                    let finalization_status = chain
                        .state_finalization_and_canonicity(root, hot_summary.slot)
                        .map_err(warp_utils::reject::beacon_chain_error)?;
                    let finalized = finalization_status.is_finalized();
                    let fork_choice = chain.canonical_head.fork_choice_read_lock();
                    let execution_optimistic = if finalization_status.slot_is_finalized
                        && !finalization_status.canonical
                    {
                        // This block is permanently orphaned and has likely been pruned from fork
                        // choice. If it isn't found in fork choice, mark it optimistic to be on the
                        // safe side.
                        fork_choice
                            .is_optimistic_or_invalid_block_no_fallback(
                                &hot_summary.latest_block_root,
                            )
                            .unwrap_or(true)
                    } else {
                        // This block is either old and finalized, or recent and unfinalized, so
                        // it's safe to fallback to the optimistic status of the finalized block.
                        chain
                            .canonical_head
                            .fork_choice_read_lock()
                            .is_optimistic_or_invalid_block(&hot_summary.latest_block_root)
                            .map_err(BeaconChainError::ForkChoiceError)
                            .map_err(warp_utils::reject::beacon_chain_error)?
                    };
                    return Ok((*root, execution_optimistic, finalized));
                } else if let Some(_cold_state_slot) = chain
                    .store
                    .load_cold_state_slot(root)
                    .map_err(BeaconChainError::DBError)
                    .map_err(warp_utils::reject::beacon_chain_error)?
                {
                    let fork_choice = chain.canonical_head.fork_choice_read_lock();
                    let finalized_root = fork_choice
                        .cached_fork_choice_view()
                        .finalized_checkpoint
                        .root;
                    let execution_optimistic = fork_choice
                        .is_optimistic_or_invalid_block_no_fallback(&finalized_root)
                        .map_err(BeaconChainError::ForkChoiceError)
                        .map_err(warp_utils::reject::beacon_chain_error)?;
                    return Ok((*root, execution_optimistic, true));
                } else {
                    return Err(warp_utils::reject::custom_not_found(format!(
                        "beacon state for state root {}",
                        root
                    )));
                }
            }
        };

        let root = chain
            .state_root_at_slot(slot)
            .map_err(warp_utils::reject::beacon_chain_error)?
            .ok_or_else(|| {
                warp_utils::reject::custom_not_found(format!("beacon state at slot {}", slot))
            })?;

        Ok((root, execution_optimistic, finalized))
    }

    /// Return the `fork` field of the state identified by `self`.
    /// Also returns the `execution_optimistic` value of the state.
    pub fn fork_and_execution_optimistic<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<(Fork, bool), warp::Rejection> {
        self.map_state_and_execution_optimistic_and_finalized(
            chain,
            |state, execution_optimistic, _finalized| Ok((state.fork(), execution_optimistic)),
        )
    }

    /// Return the `fork` field of the state identified by `self`.
    /// Also returns the `execution_optimistic` value of the state.
    /// Also returns the `finalized` value of the state.
    pub fn fork_and_execution_optimistic_and_finalized<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<(Fork, bool, bool), warp::Rejection> {
        self.map_state_and_execution_optimistic_and_finalized(
            chain,
            |state, execution_optimistic, finalized| {
                Ok((state.fork(), execution_optimistic, finalized))
            },
        )
    }

    /// Convenience function to compute `fork` when `execution_optimistic` isn't desired.
    pub fn fork<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<Fork, warp::Rejection> {
        self.fork_and_execution_optimistic(chain)
            .map(|(fork, _)| fork)
    }

    /// Return the `BeaconState` identified by `self`.
    pub fn state<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<(BeaconState<T::EthSpec>, ExecutionOptimistic, Finalized), warp::Rejection> {
        let ((state_root, execution_optimistic, finalized), slot_opt) = match &self.0 {
            CoreStateId::Head => {
                let (cached_head, execution_status) = chain
                    .canonical_head
                    .head_and_execution_status()
                    .map_err(warp_utils::reject::beacon_chain_error)?;
                return Ok((
                    cached_head
                        .snapshot
                        .beacon_state
                        .clone_with_only_committee_caches(),
                    execution_status.is_optimistic_or_invalid(),
                    false,
                ));
            }
            CoreStateId::Slot(slot) => (self.root(chain)?, Some(*slot)),
            _ => (self.root(chain)?, None),
        };

        let state = chain
            .get_state(&state_root, slot_opt)
            .map_err(warp_utils::reject::beacon_chain_error)
            .and_then(|opt| {
                opt.ok_or_else(|| {
                    warp_utils::reject::custom_not_found(format!(
                        "beacon state at root {}",
                        state_root
                    ))
                })
            })?;

        Ok((state, execution_optimistic, finalized))
    }

    /// Map a function across the `BeaconState` identified by `self`.
    ///
    /// The optimistic and finalization status of the requested state is also provided to the `func`
    /// closure.
    ///
    /// This function will avoid instantiating/copying a new state when `self` points to the head
    /// of the chain.
    pub fn map_state_and_execution_optimistic_and_finalized<T: BeaconChainTypes, F, U>(
        &self,
        chain: &BeaconChain<T>,
        func: F,
    ) -> Result<U, warp::Rejection>
    where
        F: Fn(&BeaconState<T::EthSpec>, bool, bool) -> Result<U, warp::Rejection>,
    {
        let (state, execution_optimistic, finalized) = match &self.0 {
            CoreStateId::Head => {
                let (head, execution_status) = chain
                    .canonical_head
                    .head_and_execution_status()
                    .map_err(warp_utils::reject::beacon_chain_error)?;
                return func(
                    &head.snapshot.beacon_state,
                    execution_status.is_optimistic_or_invalid(),
                    false,
                );
            }
            _ => self.state(chain)?,
        };

        func(&state, execution_optimistic, finalized)
    }
}

impl FromStr for StateId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        CoreStateId::from_str(s).map(Self)
    }
}

impl fmt::Display for StateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Returns the first slot of the checkpoint's `epoch` and the execution status of the checkpoint's
/// `root`.
pub fn checkpoint_slot_and_execution_optimistic<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    checkpoint: Checkpoint,
) -> Result<(Slot, ExecutionOptimistic), warp::reject::Rejection> {
    let slot = checkpoint.epoch.start_slot(T::EthSpec::slots_per_epoch());
    let fork_choice = chain.canonical_head.fork_choice_read_lock();
    let finalized_checkpoint = fork_choice.cached_fork_choice_view().finalized_checkpoint;

    // If the checkpoint is pre-finalization, just use the optimistic status of the finalized
    // block.
    let root = if checkpoint.epoch < finalized_checkpoint.epoch {
        &finalized_checkpoint.root
    } else {
        &checkpoint.root
    };

    let execution_optimistic = fork_choice
        .is_optimistic_or_invalid_block_no_fallback(root)
        .map_err(BeaconChainError::ForkChoiceError)
        .map_err(warp_utils::reject::beacon_chain_error)?;

    Ok((slot, execution_optimistic))
}
