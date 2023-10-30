use crate::beacon_chain::BeaconChainTypes;
use slog::{error, info, warn, Logger};
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::Duration;
use store::{
    get_key_for_col, metadata::BLOB_INFO_KEY, DBColumn, Error, HotColdDB, KeyValueStoreOp,
};
use types::{Epoch, EthSpec, Hash256, Slot};

/// The slot clock isn't usually available before the database is initialized, so we construct a
/// temporary slot clock by reading the genesis state. It should always exist if the database is
/// initialized at a prior schema version, however we still handle the lack of genesis state
/// gracefully.
fn get_slot_clock<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    log: &Logger,
) -> Result<Option<T::SlotClock>, Error> {
    let spec = db.get_chain_spec();
    let Some(genesis_block) = db.get_blinded_block(&Hash256::zero())? else {
        error!(log, "Missing genesis block");
        return Ok(None);
    };
    let Some(genesis_state) = db.get_state(&genesis_block.state_root(), Some(Slot::new(0)))? else {
        error!(log, "Missing genesis state"; "state_root" => ?genesis_block.state_root());
        return Ok(None);
    };
    Ok(Some(T::SlotClock::new(
        spec.genesis_slot,
        Duration::from_secs(genesis_state.genesis_time()),
        Duration::from_secs(spec.seconds_per_slot),
    )))
}

fn get_current_epoch<T: BeaconChainTypes>(
    db: &Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: &Logger,
) -> Result<Epoch, Error> {
    get_slot_clock::<T>(db, log)?
        .and_then(|clock| clock.now())
        .map(|slot| slot.epoch(T::EthSpec::slots_per_epoch()))
        .ok_or(Error::SlotClockUnavailableForMigration)
}

pub fn upgrade_to_v18<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    db.heal_freezer_block_roots()?;
    info!(log, "Healed freezer block roots");

    // No-op, even if Deneb has already occurred. The database is probably borked in this case, but
    // *maybe* the fork recovery will revert the minority fork and succeed.
    if let Some(deneb_fork_epoch) = db.get_chain_spec().deneb_fork_epoch {
        let current_epoch = get_current_epoch::<T>(&db, &log)?;
        if current_epoch >= deneb_fork_epoch {
            warn!(
                log,
                "Attempting upgrade to v18 schema";
                "info" => "this may not work as Deneb has already been activated"
            );
        } else {
            info!(
                log,
                "Upgrading to v18 schema";
                "info" => "ready for Deneb",
                "epochs_until_deneb" => deneb_fork_epoch - current_epoch
            );
        }
    } else {
        info!(
            log,
            "Upgrading to v18 schema";
            "info" => "ready for Deneb once it is scheduled"
        );
    }
    Ok(vec![])
}

pub fn downgrade_from_v18<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    // We cannot downgrade from V18 once the Deneb fork has been activated, because there will
    // be blobs and blob metadata in the database that aren't understood by the V17 schema.
    if let Some(deneb_fork_epoch) = db.get_chain_spec().deneb_fork_epoch {
        let current_epoch = get_current_epoch::<T>(&db, &log)?;
        if current_epoch >= deneb_fork_epoch {
            error!(
                log,
                "Deneb already active: v18+ is mandatory";
                "current_epoch" => current_epoch,
                "deneb_fork_epoch" => deneb_fork_epoch,
            );
            return Err(Error::UnableToDowngrade);
        } else {
            info!(
                log,
                "Downgrading to v17 schema";
                "info" => "you will need to upgrade before Deneb",
                "epochs_until_deneb" => deneb_fork_epoch - current_epoch
            );
        }
    } else {
        info!(
            log,
            "Downgrading to v17 schema";
            "info" => "you need to upgrade before Deneb",
        );
    }

    let ops = vec![KeyValueStoreOp::DeleteKey(get_key_for_col(
        DBColumn::BeaconMeta.into(),
        BLOB_INFO_KEY.as_bytes(),
    ))];

    Ok(ops)
}
