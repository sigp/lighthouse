use crate::upgrade::{
    upgrade_to_altair, upgrade_to_bellatrix, upgrade_to_capella, upgrade_to_deneb,
    upgrade_to_eip7732, upgrade_to_electra,
};
use crate::{per_epoch_processing::EpochProcessingSummary, *};
use safe_arith::{ArithError, SafeArith};
use types::*;

#[derive(Debug, PartialEq)]
pub enum Error {
    BeaconStateError(BeaconStateError),
    EpochProcessingError(EpochProcessingError),
    ArithError(ArithError),
    InconsistentStateFork(InconsistentFork),
}

impl From<ArithError> for Error {
    fn from(e: ArithError) -> Self {
        Self::ArithError(e)
    }
}

/// Advances a state forward by one slot, performing per-epoch processing if required.
///
/// If the root of the supplied `state` is known, then it can be passed as `state_root`. If
/// `state_root` is `None`, the root of `state` will be computed using a cached tree hash.
/// Providing the `state_root` makes this function several orders of magnitude faster.
pub fn per_slot_processing<E: EthSpec>(
    state: &mut BeaconState<E>,
    state_root: Option<Hash256>,
    spec: &ChainSpec,
) -> Result<Option<EpochProcessingSummary<E>>, Error> {
    // Verify that the `BeaconState` instantiation matches the fork at `state.slot()`.
    state
        .fork_name(spec)
        .map_err(Error::InconsistentStateFork)?;

    cache_state(state, state_root)?;

    let summary = if state.slot() > spec.genesis_slot
        && state.slot().safe_add(1)?.safe_rem(E::slots_per_epoch())? == 0
    {
        Some(per_epoch_processing(state, spec)?)
    } else {
        None
    };

    state.slot_mut().safe_add_assign(1)?;

    // Process fork upgrades here. Note that multiple upgrades can potentially run
    // in sequence if they are scheduled in the same Epoch (common in testnets)
    if state.slot().safe_rem(E::slots_per_epoch())? == 0 {
        // If the Altair fork epoch is reached, perform an irregular state upgrade.
        if spec.altair_fork_epoch == Some(state.current_epoch()) {
            upgrade_to_altair(state, spec)?;
        }
        // If the Bellatrix fork epoch is reached, perform an irregular state upgrade.
        if spec.bellatrix_fork_epoch == Some(state.current_epoch()) {
            upgrade_to_bellatrix(state, spec)?;
        }
        // Capella.
        if spec.capella_fork_epoch == Some(state.current_epoch()) {
            upgrade_to_capella(state, spec)?;
        }
        // Deneb.
        if spec.deneb_fork_epoch == Some(state.current_epoch()) {
            upgrade_to_deneb(state, spec)?;
        }
        // Electra.
        if spec.electra_fork_epoch == Some(state.current_epoch()) {
            upgrade_to_electra(state, spec)?;
        }
        // EIP-7732.
        if spec.eip7732_fork_epoch == Some(state.current_epoch()) {
            upgrade_to_eip7732(state, spec)?;
        }

        // Additionally build all caches so that all valid states that are advanced always have
        // committee caches built, and we don't have to worry about initialising them at higher
        // layers.
        state.build_caches(spec)?;
    }

    Ok(summary)
}

fn cache_state<E: EthSpec>(
    state: &mut BeaconState<E>,
    state_root: Option<Hash256>,
) -> Result<(), Error> {
    let previous_state_root = if let Some(root) = state_root {
        root
    } else {
        state.update_tree_hash_cache()?
    };

    // Note: increment the state slot here to allow use of our `state_root` and `block_root`
    // getter/setter functions.
    //
    // This is a bit hacky, however it gets the job done safely without lots of code.
    let previous_slot = state.slot();
    state.slot_mut().safe_add_assign(1)?;

    // Store the previous slot's post state transition root.
    state.set_state_root(previous_slot, previous_state_root)?;

    // Cache latest block header state root
    if state.latest_block_header().state_root == Hash256::zero() {
        state.latest_block_header_mut().state_root = previous_state_root;
    }

    // Cache block root
    let latest_block_root = state.latest_block_header().canonical_root();
    state.set_block_root(previous_slot, latest_block_root)?;

    // Set the state slot back to what it should be.
    state.slot_mut().safe_sub_assign(1)?;

    Ok(())
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}

impl From<EpochProcessingError> for Error {
    fn from(e: EpochProcessingError) -> Error {
        Error::EpochProcessingError(e)
    }
}
