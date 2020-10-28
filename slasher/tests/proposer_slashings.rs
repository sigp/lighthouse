use slasher::{test_utils::logger, Config, Slasher};
use tempdir::TempDir;
use types::{
    BeaconBlockHeader, Epoch, EthSpec, Hash256, MainnetEthSpec, Signature, SignedBeaconBlockHeader,
    Slot,
};

type E = MainnetEthSpec;

fn test_block(slot: u64, proposer_index: u64, block_root: u64) -> SignedBeaconBlockHeader {
    SignedBeaconBlockHeader {
        message: BeaconBlockHeader {
            slot: Slot::new(slot),
            proposer_index,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body_root: Hash256::from_low_u64_be(block_root),
        },
        signature: Signature::empty(),
    }
}

#[test]
fn block_pruning() {
    let slots_per_epoch = E::slots_per_epoch();

    let tempdir = TempDir::new("slasher").unwrap();
    let mut config = Config::new(tempdir.path().into());
    config.chunk_size = 2;
    config.history_length = 2;

    let slasher = Slasher::<E>::open(config.clone(), logger()).unwrap();
    let current_epoch = Epoch::from(2 * config.history_length);

    // Pruning the empty database should be safe.
    slasher.prune_database(Epoch::new(0)).unwrap();
    slasher.prune_database(current_epoch).unwrap();

    // Add blocks in excess of the history length and prune them away.
    let proposer_index = 100_000; // high to check sorting by slot
    for slot in 1..=current_epoch.as_u64() * slots_per_epoch {
        slasher.accept_block_header(test_block(slot, proposer_index, 0));
    }
    slasher.process_queued(current_epoch).unwrap();
    slasher.prune_database(current_epoch).unwrap();

    // Add more conflicting blocks, and check that only the ones within the non-pruned
    // section are detected as slashable.
    for slot in 1..=current_epoch.as_u64() * slots_per_epoch {
        slasher.accept_block_header(test_block(slot, proposer_index, 1));
    }
    slasher.process_queued(current_epoch).unwrap();

    let proposer_slashings = slasher.get_proposer_slashings();

    // Check number of proposer slashings, accounting for single block in current epoch.
    assert_eq!(
        proposer_slashings.len(),
        (config.history_length - 1) * slots_per_epoch as usize + 1
    );
    // Check epochs of all slashings are from within range.
    assert!(proposer_slashings.iter().all(|slashing| slashing
        .signed_header_1
        .message
        .slot
        .epoch(slots_per_epoch)
        > current_epoch - config.history_length as u64));
}
