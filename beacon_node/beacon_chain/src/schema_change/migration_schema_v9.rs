use crate::beacon_chain::BeaconChainTypes;
use slog::{debug, error, info, Logger};
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::Duration;
use store::{DBColumn, Error, HotColdDB, KeyValueStore};
use types::{EthSpec, Hash256, Slot};

const OPS_PER_BLOCK_WRITE: usize = 2;

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
            "Upgrading database schema to v9";
            "info" => "This will take several minutes. Each block will be read from and \
                       re-written to the database. You may safely exit now (Ctrl-C) and resume \
                       the migration later. Downgrading is no longer possible."
        );

        for res in db.hot_db.iter_column_keys(DBColumn::BeaconBlock) {
            let block_root = res?;
            let block = match db.get_full_block_prior_to_v9(&block_root) {
                // A pre-v9 block is present.
                Ok(Some(block)) => block,
                // A block is missing.
                Ok(None) => return Err(Error::BlockNotFound(block_root)),
                // There was an error reading a pre-v9 block. Try reading it as a post-v9 block.
                Err(_) => {
                    if db.try_get_full_block(&block_root)?.is_some() {
                        // The block is present as a post-v9 block, assume that it was already
                        // correctly migrated.
                        continue;
                    } else {
                        // This scenario should not be encountered since a prior check has ensured
                        // that this block exists.
                        return Err(Error::V9MigrationFailure(block_root));
                    }
                }
            };

            if block.message().execution_payload().is_ok() {
                // Overwrite block with blinded block and store execution payload separately.
                debug!(
                    log,
                    "Rewriting Bellatrix block";
                    "block_root" => ?block_root,
                );

                let mut kv_batch = Vec::with_capacity(OPS_PER_BLOCK_WRITE);
                db.block_as_kv_store_ops(&block_root, block, &mut kv_batch)?;
                db.hot_db.do_atomically(kv_batch)?;
            }
        }
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
