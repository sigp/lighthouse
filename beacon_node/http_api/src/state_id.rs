use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::StateId as CoreStateId;
use std::str::FromStr;
use types::{BeaconState, EthSpec, Fork, Hash256, Slot};

/// Wraps `eth2::types::StateId` and provides common state-access functionality. E.g., reading
/// states or parts of states from the database.
pub struct StateId(CoreStateId);

impl StateId {
    pub fn slot(slot: Slot) -> Self {
        Self(CoreStateId::Slot(slot))
    }

    /// Return the state root identified by `self`.
    pub fn root<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<Hash256, warp::Rejection> {
        let slot = match &self.0 {
            CoreStateId::Head => {
                return chain
                    .head_info()
                    .map(|head| head.state_root)
                    .map_err(warp_utils::reject::beacon_chain_error)
            }
            CoreStateId::Genesis => return Ok(chain.genesis_state_root),
            CoreStateId::Finalized => chain.head_info().map(|head| {
                head.finalized_checkpoint
                    .epoch
                    .start_slot(T::EthSpec::slots_per_epoch())
            }),
            CoreStateId::Justified => chain.head_info().map(|head| {
                head.current_justified_checkpoint
                    .epoch
                    .start_slot(T::EthSpec::slots_per_epoch())
            }),
            CoreStateId::Slot(slot) => Ok(*slot),
            CoreStateId::Root(root) => return Ok(*root),
        }
        .map_err(warp_utils::reject::beacon_chain_error)?;

        chain
            .state_root_at_slot(slot)
            .map_err(warp_utils::reject::beacon_chain_error)?
            .ok_or_else(|| {
                warp_utils::reject::custom_not_found(format!("beacon state at slot {}", slot))
            })
    }

    /// Return the `fork` field of the state identified by `self`.
    /// Also returns the `execution_optimistic` value of the state.
    pub fn fork<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<(Fork, bool), warp::Rejection> {
        self.map_state_and_execution_optimistic(chain, |state, execution_optimistic| {
            Ok((state.fork(), execution_optimistic))
        })
    }

    /// Return the `BeaconState` identified by `self`.
    pub fn state<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<BeaconState<T::EthSpec>, warp::Rejection> {
        let (state_root, slot_opt) = match &self.0 {
            CoreStateId::Head => {
                return chain
                    .head_beacon_state()
                    .map_err(warp_utils::reject::beacon_chain_error)
            }
            CoreStateId::Slot(slot) => (self.root(chain)?, Some(*slot)),
            _ => (self.root(chain)?, None),
        };

        chain
            .get_state(&state_root, slot_opt)
            .map_err(warp_utils::reject::beacon_chain_error)
            .and_then(|opt| {
                opt.ok_or_else(|| {
                    warp_utils::reject::custom_not_found(format!(
                        "beacon state at root {}",
                        state_root
                    ))
                })
            })
    }

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
        let state = match &self.0 {
            CoreStateId::Head => {
                chain
                    .head()
                    .map_err(warp_utils::reject::beacon_chain_error)?
                    .beacon_state
            }
            _ => self.state(chain)?,
        };

        let execution_optimistic = match &self.0 {
            CoreStateId::Genesis => false,
            CoreStateId::Head
            | CoreStateId::Slot(_)
            | CoreStateId::Finalized
            | CoreStateId::Justified => chain
                .is_optimistic_head()
                .map_err(warp_utils::reject::beacon_chain_error)?,
            CoreStateId::Root(_) => {
                let state_root = self.root(chain)?;
                chain
                    .is_optimistic_block(
                        &chain
                            .get_block(&state.get_latest_block_root(state_root))
                            .map_err(warp_utils::reject::beacon_chain_error)?
                            .ok_or_else(|| {
                                warp_utils::reject::custom_not_found(format!(
                                    "latest block root not found for beacon state at root {}",
                                    state_root
                                ))
                            })?,
                    )
                    .map_err(warp_utils::reject::beacon_chain_error)?
            }
        };

        func(&state, execution_optimistic)
    }

    /// Convienience function to compute `execution_optimistic` when `state` is not desired.
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
