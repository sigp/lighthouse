#![cfg(any(feature = "mdbx", feature = "lmdb"))]

use logging::test_logger;
use slasher::{test_utils::indexed_att, Config, Slasher};
use tempfile::tempdir;
use types::Epoch;

#[test]
fn attestation_pruning_empty_wrap_around() {
    let tempdir = tempdir().unwrap();
    let mut config = Config::new(tempdir.path().into());
    config.validator_chunk_size = 1;
    config.chunk_size = 16;
    config.history_length = 16;

    let slasher = Slasher::open(config.clone(), test_logger()).unwrap();

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
