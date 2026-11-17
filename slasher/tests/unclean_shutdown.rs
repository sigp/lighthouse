#![cfg(feature = "redb")]

use maplit::hashset;
use slasher::{
    Config, DatabaseBackend, Slasher,
    config::REDB_DATA_FILENAME,
    test_utils::{att_slashing, chain_spec, indexed_att},
};
use std::path::Path;
use tempfile::{TempDir, tempdir};
use types::Epoch;

/// Copy the database file as it currently is on disk, which is what a new process would see if
/// this one crashed now, and check that the copy opens without a full repair.
#[track_caller]
fn copy_and_open_without_repair(dir: &Path) -> TempDir {
    let copy_dir = tempdir().unwrap();
    std::fs::copy(
        dir.join(REDB_DATA_FILENAME),
        copy_dir.path().join(REDB_DATA_FILENAME),
    )
    .unwrap();

    // redb invokes the repair callback before starting a full repair (which re-reads the whole
    // file), and aborting it fails the open.
    redb::Builder::new()
        .set_repair_callback(|session| session.abort())
        .create(copy_dir.path().join(REDB_DATA_FILENAME))
        .expect("full repair should not be required");
    copy_dir
}

/// Regression test for https://github.com/sigp/lighthouse/issues/10440.
///
/// `SlasherDB` leaks its database environment, so the `redb::Database` is never dropped and every
/// shutdown is unclean. Check that the database can be reopened without a full repair, and that
/// data written before the shutdown is intact.
#[test]
fn redb_reopen_after_unclean_shutdown_without_repair() {
    let tempdir = tempdir().unwrap();
    let mut config = Config::new(tempdir.path().into());
    config.backend = DatabaseBackend::Redb;
    let spec = chain_spec();
    let current_epoch = Epoch::new(1);

    let att1 = indexed_att([0], 0, 1, 0);
    let att2 = indexed_att([0], 0, 1, 1);

    let slasher = Slasher::open(config.clone(), spec.clone()).unwrap();
    copy_and_open_without_repair(&config.database_path);

    slasher.accept_attestation(att1.clone());
    slasher.process_queued(current_epoch).unwrap();
    assert!(slasher.get_attester_slashings().is_empty());
    copy_and_open_without_repair(&config.database_path);

    slasher.prune_database(current_epoch).unwrap();
    copy_and_open_without_repair(&config.database_path);

    // Dropping the slasher does not drop the `redb::Database`, which keeps redb's exclusive file
    // lock, so reopen a copy of the file.
    drop(slasher);
    let reopen_dir = copy_and_open_without_repair(&config.database_path);

    // `att1` must have been persisted: a conflicting attestation after the restart is slashable.
    config.database_path = reopen_dir.path().into();
    let slasher = Slasher::open(config, spec).unwrap();
    slasher.accept_attestation(att2.clone());
    slasher.process_queued(current_epoch).unwrap();
    assert_eq!(
        slasher.get_attester_slashings(),
        hashset![att_slashing(&att1, &att2)]
    );
}
