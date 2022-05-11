use crate::beacon_chain::BeaconChainTypes;
use slog::{debug, error, info, Logger};
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::Duration;
use store::{DBColumn, Error, HotColdDB, KeyValueStore};
use types::{EthSpec, Hash256, SignedBeaconBlock, Slot};

/// The slot clock isn't usually available before the database is initialized, so we construct a
/// temporary slot clock by reading the genesis state. It should always exist if the database is
/// initialized at a prior schema version, however we still handle the lack of genesis state
/// gracefully.
fn get_slot_clock<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    log: &Logger,
) -> Result<Option<T::SlotClock>, Error> {
    // At schema v8 the genesis block must be a *full* block (with payload). In all likeliness it
    // actually has no payload.
    let spec = db.get_chain_spec();
    let genesis_block = if let Some(block) = db.get_full_block_prior_to_v9(&Hash256::zero())? {
        block
    } else {
        error!(log, "Missing genesis block");
        return Ok(None);
    };
    let genesis_state =
        if let Some(state) = db.get_state(&genesis_block.state_root(), Some(Slot::new(0)))? {
            state
        } else {
            error!(log, "Missing genesis state"; "state_root" => ?genesis_block.state_root());
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
    // This upgrade is a no-op if the Bellatrix fork epoch has not already passed. This migration
    // was implemented before the activation of Bellatrix on all networks except Kiln, so the only
    // users who will need to wait for the slow copying migration are Kiln users.
    let slot_clock = if let Some(slot_clock) = get_slot_clock::<T>(&db, &log)? {
        slot_clock
    } else {
        error!(
            log,
            "Unable to complete migration because genesis state or genesis block is missing"
        );
        return Err(Error::SlotClockUnavailableForMigration);
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
            "Upgrading database schema to v9 (no-op)";
            "info" => "To downgrade before the merge run `lighthouse db migrate`"
        );
        return Ok(());
    };

    if current_epoch >= bellatrix_fork_epoch {
        info!(
            log,
            "Upgrading database schema to v9 by re-writing blocks";
            "info" => "This will take several minutes and use a *lot* of RAM. \
                       You cannot downgrade once it completes, but it is safe to exit before \
                       completion (Ctrl-C now). If your machine doesn't have enough RAM to run \
                       the migration then you will have to re-sync. This will only be necessary \
                       on Kiln and merge testnets, never Prater or mainnet."
        );

        let mut kv_batch = vec![];

        for res in db.hot_db.iter_column(DBColumn::BeaconBlock) {
            let (block_root, bytes) = res?;
            let block = SignedBeaconBlock::from_ssz_bytes(&bytes, db.get_chain_spec())?;

            if block.message().execution_payload().is_ok() {
                // Overwrite block with blinded block and store execution payload separately.
                debug!(
                    log,
                    "Rewriting Bellatrix block";
                    "block_root" => ?block_root,
                );
                db.block_as_kv_store_ops(&block_root, block, &mut kv_batch)?;
            }
        }
        info!(
            log,
            "Committing block re-write transaction";
            "num_ops" => kv_batch.len(),
            "info" => "Memory usage is about to spike, if this fails you will need to re-sync"
        );
        db.hot_db.do_atomically(kv_batch)?;
    } else {
        info!(
            log,
            "Upgrading database schema to v9 (no-op)";
            "info" => "To downgrade before the merge run `lighthouse db migrate`"
        );
    }

    Ok(())
}

// This downgrade is conditional and will only succeed if the Bellatrix fork epoch hasn't been
// reached.
pub fn downgrade_from_v9<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<(), Error> {
    let slot_clock = if let Some(slot_clock) = get_slot_clock::<T>(&db, &log)? {
        slot_clock
    } else {
        error!(
            log,
            "Unable to complete migration because genesis state or genesis block is missing"
        );
        return Err(Error::SlotClockUnavailableForMigration);
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
