use crate::beacon_chain::BeaconChainTypes;
use slog::{error, info, Logger};
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::Duration;
use store::{Error, HotColdDB};
use types::{EthSpec, Hash256, Slot};

/// The slot clock isn't usually available before the database is initialized, so we construct a
/// temporary slot clock by reading the genesis state. It should always exist if the database is
/// initialized at a prior schema version, however we still handle the lack of genesis state
/// gracefully.
fn get_slot_clock<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<Option<T::SlotClock>, Error> {
    // At schema v8 the genesis block must be a *full* block (with payload). In all likeliness it
    // actually has no payload.
    let spec = db.get_chain_spec();
    let genesis_block = if let Some(block) = db.get_full_block_prior_to_v9(&Hash256::zero())? {
        block
    } else {
        return Ok(None);
    };
    let genesis_state =
        if let Some(state) = db.get_state(&genesis_block.state_root(), Some(Slot::new(0)))? {
            state
        } else {
            return Ok(None);
        };
    Ok(Some(T::SlotClock::new(
        spec.genesis_slot,
        Duration::from_secs(genesis_state.genesis_time()),
        Duration::from_secs(spec.seconds_per_slot),
    )))
}

pub fn upgrade_to_v9<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<(), Error> {
    // This is a conditional upgrade which will only succeed if the Bellatrix fork epoch
    // has not already passed. This migration was implemented before the activation of Bellatrix
    // on all networks except Kiln, so the only users who will need to resync are Kiln users.
    let slot_clock = if let Some(slot_clock) = get_slot_clock::<T>(&db)? {
        slot_clock
    } else {
        return Ok(());
    };

    let current_epoch = if let Some(slot) = slot_clock.now() {
        slot.epoch(T::EthSpec::slots_per_epoch())
    } else {
        return Ok(());
    };

    let bellatrix_fork_epoch = if let Some(fork_epoch) = db.get_chain_spec().bellatrix_fork_epoch {
        fork_epoch
    } else {
        info!(
            log,
            "Upgrading database schema to v9";
            "info" => "To downgrade before the merge run `lighthouse db migrate`"
        );
        return Ok(());
    };

    if current_epoch >= bellatrix_fork_epoch {
        error!(
            log,
            "Re-sync required to upgrade to database schema v9";
            "current_epoch" => current_epoch,
            "bellatrix_fork_epoch" => bellatrix_fork_epoch,
            "reason" => "Lighthouse's post-merge database schema has changed, so for simplicity
                         we're requiring merged networks like Kiln to re-sync. This will NOT be \
                         necessary on mainnet or Prater",
        );
        Err(Error::ResyncRequiredForExecutionPayloadSeparation)
    } else {
        Ok(())
    }
}

pub fn downgrade_from_v9<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<(), Error> {
    let slot_clock = if let Some(slot_clock) = get_slot_clock::<T>(&db)? {
        slot_clock
    } else {
        return Ok(());
    };

    let current_epoch = if let Some(slot) = slot_clock.now() {
        slot.epoch(T::EthSpec::slots_per_epoch())
    } else {
        return Ok(());
    };

    let bellatrix_fork_epoch = if let Some(fork_epoch) = db.get_chain_spec().bellatrix_fork_epoch {
        fork_epoch
    } else {
        info!(
            log,
            "Downgrading database schema from v9";
            "info" => "You need to upgrade to v9 again before the merge"
        );
        return Ok(());
    };

    if current_epoch >= bellatrix_fork_epoch {
        error!(
            log,
            "Downgrading from schema v9 after the Bellatrix fork epoch is not supported";
            "current_epoch" => current_epoch,
            "bellatrix_fork_epoch" => bellatrix_fork_epoch,
            "reason" => "You need a v9 schema database to run on a merged version of Prater or \
                         mainnet. On Kiln, you have to re-sync",
        );
        Err(Error::ResyncRequiredForExecutionPayloadSeparation)
    } else {
        Ok(())
    }
}
