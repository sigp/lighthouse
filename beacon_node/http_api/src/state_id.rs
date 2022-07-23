use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::types::StateId as CoreStateId;
use std::fmt;
use std::str::FromStr;
use types::{BeaconState, EthSpec, Fork, Hash256, Slot};

pub type ExecutionOptimistic = bool;

/// Wraps `eth2::types::StateId` and provides common state-access functionality. E.g., reading
/// states or parts of states from the database.
#[derive(Debug)]
pub struct StateId(pub CoreStateId);

impl StateId {
    pub fn from_slot(slot: Slot) -> Self {
        Self(CoreStateId::Slot(slot))
    }

    /// Return the state root identified by `self`.
    pub fn root<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<(Hash256, ExecutionOptimistic), warp::Rejection> {
        let (slot, execution_optimistic) = match &self.0 {
            CoreStateId::Head => {
                let (cached_head, execution_status) = chain
                    .canonical_head
                    .head_and_execution_status()
                    .map_err(warp_utils::reject::beacon_chain_error)?;
                return Ok((
                    cached_head.head_state_root(),
                    execution_status.is_optimistic(),
                ));
            }
            CoreStateId::Genesis => return Ok((chain.genesis_state_root, false)),
            CoreStateId::Finalized => {
                let finalized_checkpoint =
                    chain.canonical_head.cached_head().finalized_checkpoint();
                let finalized_slot = finalized_checkpoint
                    .epoch
                    .start_slot(T::EthSpec::slots_per_epoch());
                let execution_optimistic = chain
                    .canonical_head
                    .fork_choice_read_lock()
                    .is_optimistic_block(&finalized_checkpoint.root)
                    .map_err(BeaconChainError::ForkChoiceError)
                    .map_err(warp_utils::reject::beacon_chain_error)?;
                (finalized_slot, execution_optimistic)
            }
            CoreStateId::Justified => {
                let justified_checkpoint =
                    chain.canonical_head.cached_head().justified_checkpoint();
                let justified_slot = justified_checkpoint
                    .epoch
                    .start_slot(T::EthSpec::slots_per_epoch());
                let execution_optimistic = chain
                    .canonical_head
                    .fork_choice_read_lock()
                    .is_optimistic_block_no_fallback(&justified_checkpoint.root)
                    .map_err(BeaconChainError::ForkChoiceError)
                    .map_err(warp_utils::reject::beacon_chain_error)?;
                (justified_slot, execution_optimistic)
            }
            CoreStateId::Slot(slot) => (
                *slot,
                chain
                    .is_optimistic_head()
                    .map_err(warp_utils::reject::beacon_chain_error)?,
            ),
            CoreStateId::Root(root) => {
                if chain
                    .store
                    .load_hot_state_summary(root)
                    .map_err(BeaconChainError::DBError)
                    .map_err(warp_utils::reject::beacon_chain_error)?
                    .is_some()
                {
                    let execution_optimistic = chain
                        .canonical_head
                        .fork_choice_read_lock()
                        .is_optimistic_block(root)
                        .map_err(BeaconChainError::ForkChoiceError)
                        .map_err(warp_utils::reject::beacon_chain_error)?;
                    return Ok((*root, execution_optimistic));
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

        Ok((root, execution_optimistic))
    }

    /// Return the `fork` field of the state identified by `self`.
    /// Also returns the `execution_optimistic` value of the state.
    pub fn fork_and_execution_optimistic<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<(Fork, bool), warp::Rejection> {
        self.map_state_and_execution_optimistic(chain, |state, execution_optimistic| {
            Ok((state.fork(), execution_optimistic))
        })
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
    ) -> Result<(BeaconState<T::EthSpec>, ExecutionOptimistic), warp::Rejection> {
        let ((state_root, execution_optimistic), slot_opt) = match &self.0 {
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
                    execution_status.is_optimistic(),
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

        Ok((state, execution_optimistic))
    }

    /*
    /// Map a function across the `BeaconState` identified by `self`.
    ///
    /// This function will avoid instantiating/copying a new state when `self` points to the head
    /// of the chain.
    #[allow(dead_code)]
    pub fn map_state<T: BeaconChainTypes, F, U>(
        &self,
        chain: &BeaconChain<T>,
        func: F,
    ) -> Result<U, warp::Rejection>
    where
        F: Fn(&BeaconState<T::EthSpec>) -> Result<U, warp::Rejection>,
    {
        match &self.0 {
            CoreStateId::Head => chain
                .with_head(|snapshot| Ok(func(&snapshot.beacon_state)))
                .map_err(warp_utils::reject::beacon_chain_error)?,
            _ => func(&self.state(chain)?),
        }
    }
    */

    /// Functions the same as `map_state` but additionally computes the value of
    /// `execution_optimistic` of the state identified by `self`.
    ///
    /// This is to avoid re-instantiating `state` unnecessarily.
    pub fn map_state_and_execution_optimistic<T: BeaconChainTypes, F, U>(
        &self,
        chain: &BeaconChain<T>,
        func: F,
    ) -> Result<U, warp::Rejection>
    where
        F: Fn(&BeaconState<T::EthSpec>, bool) -> Result<U, warp::Rejection>,
    {
        let (state, execution_optimistic) = match &self.0 {
            CoreStateId::Head => {
                let (head, execution_status) = chain
                    .canonical_head
                    .head_and_execution_status()
                    .map_err(warp_utils::reject::beacon_chain_error)?;
                return func(
                    &head.snapshot.beacon_state,
                    execution_status.is_optimistic(),
                );
            }
            _ => self.state(chain)?,
        };

        func(&state, execution_optimistic)
    }

    /// Convenience function to compute `execution_optimistic` when `state` is not desired.
    pub fn is_execution_optimistic<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<bool, warp::Rejection> {
        self.map_state_and_execution_optimistic(chain, |_, execution_optimistic| {
            Ok(execution_optimistic)
        })
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
