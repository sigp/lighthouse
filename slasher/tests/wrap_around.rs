use slasher::{
    test_utils::{indexed_att, logger},
    Config, Error, Slasher,
};
use tempfile::tempdir;
use types::Epoch;

#[test]
fn attestation_pruning_empty_wrap_around() {
    let tempdir = tempdir().unwrap();
    let mut config = Config::new(tempdir.path().into()).for_testing();
    config.validator_chunk_size = 1;
    config.chunk_size = 16;
    config.history_length = 16;

    let slasher = Slasher::open(config.clone(), logger()).unwrap();

    let v = vec![0];
    let history_length = config.history_length as u64;

    let mut current_epoch = Epoch::new(history_length - 1);

    slasher.accept_attestation(indexed_att(v.clone(), 0, history_length - 1, 0));
    slasher.process_queued(current_epoch).unwrap();
    slasher.prune_database(current_epoch).unwrap();

    // Delete the previous attestation
    current_epoch = Epoch::new(2 * history_length + 2);
    slasher.prune_database(current_epoch).unwrap();

    // Add an attestation that would be surrounded with the modulo considered
    slasher.accept_attestation(indexed_att(
        v,
        2 * history_length - 3,
        2 * history_length - 2,
        1,
    ));
    slasher.process_queued(current_epoch).unwrap();
}

// Test that pruning can recover from a `MapFull` error
#[test]
fn pruning_with_map_full() {
    let tempdir = tempdir().unwrap();
    let mut config = Config::new(tempdir.path().into()).for_testing();
    config.validator_chunk_size = 1;
    config.chunk_size = 16;
    config.history_length = 1024;
    config.max_db_size_mbs = 1;

    let slasher = Slasher::open(config, logger()).unwrap();

    let v = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    let mut current_epoch = Epoch::new(0);

    loop {
        slasher.accept_attestation(indexed_att(
            v.clone(),
            (current_epoch - 1).as_u64(),
            current_epoch.as_u64(),
            0,
        ));
        if let Err(Error::DatabaseError(lmdb::Error::MapFull)) =
            slasher.process_queued(current_epoch)
        {
            break;
        }
        current_epoch += 1;
    }

    loop {
        slasher.prune_database(current_epoch).unwrap();

        slasher.accept_attestation(indexed_att(
            v.clone(),
            (current_epoch - 1).as_u64(),
            current_epoch.as_u64(),
            0,
        ));
        match slasher.process_queued(current_epoch) {
            Ok(_) => break,
            Err(Error::DatabaseError(lmdb::Error::MapFull)) => {
                current_epoch += 1;
            }
            Err(e) => panic!("{:?}", e),
        }
    }
}
