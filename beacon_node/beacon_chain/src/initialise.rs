// Initialisation functions to generate a new BeaconChain.
// Note: A new version of ClientTypes may need to be implemented for the lighthouse
// testnet. These are examples. Also. there is code duplication which can/should be cleaned up.

use crate::BeaconChain;
use db::stores::{BeaconBlockStore, BeaconStateStore};
use db::{DiskDB, MemoryDB};
use fork_choice::BitwiseLMDGhost;
use slot_clock::SystemTimeSlotClock;
use ssz::TreeHash;
use std::path::PathBuf;
use std::sync::Arc;
use types::test_utils::TestingBeaconStateBuilder;
use types::{BeaconBlock, ChainSpec, Hash256};

//TODO: Correct this for prod
//TODO: Account for historical db
pub fn initialise_beacon_chain(
    spec: &ChainSpec,
    db_name: Option<&PathBuf>,
) -> Arc<BeaconChain<DiskDB, SystemTimeSlotClock, BitwiseLMDGhost<DiskDB>>> {
    // set up the db
    let db = Arc::new(DiskDB::open(
        db_name.expect("Database directory must be included"),
        None,
    ));

    let block_store = Arc::new(BeaconBlockStore::new(db.clone()));
    let state_store = Arc::new(BeaconStateStore::new(db.clone()));

    let state_builder = TestingBeaconStateBuilder::from_deterministic_keypairs(8, &spec);
    let (genesis_state, _keypairs) = state_builder.build();

    let mut genesis_block = BeaconBlock::empty(&spec);
    genesis_block.state_root = Hash256::from_slice(&genesis_state.hash_tree_root());

    // Slot clock
    let slot_clock = SystemTimeSlotClock::new(genesis_state.genesis_time, spec.seconds_per_slot)
        .expect("Unable to load SystemTimeSlotClock");
    // Choose the fork choice
    let fork_choice = BitwiseLMDGhost::new(block_store.clone(), state_store.clone());

    // Genesis chain
    //TODO: Handle error correctly
    Arc::new(
        BeaconChain::from_genesis(
            state_store.clone(),
            block_store.clone(),
            slot_clock,
            genesis_state,
            genesis_block,
            spec.clone(),
            fork_choice,
        )
        .expect("Terminate if beacon chain generation fails"),
    )
}

/// Initialisation of a test beacon chain, uses an in memory db with fixed genesis time.
pub fn initialise_test_beacon_chain(
    spec: &ChainSpec,
    _db_name: Option<&PathBuf>,
) -> Arc<BeaconChain<MemoryDB, SystemTimeSlotClock, BitwiseLMDGhost<MemoryDB>>> {
    let db = Arc::new(MemoryDB::open());
    let block_store = Arc::new(BeaconBlockStore::new(db.clone()));
    let state_store = Arc::new(BeaconStateStore::new(db.clone()));

    let state_builder = TestingBeaconStateBuilder::from_deterministic_keypairs(8, spec);
    let (genesis_state, _keypairs) = state_builder.build();

    let mut genesis_block = BeaconBlock::empty(spec);
    genesis_block.state_root = Hash256::from_slice(&genesis_state.hash_tree_root());

    // Slot clock
    let slot_clock = SystemTimeSlotClock::new(genesis_state.genesis_time, spec.seconds_per_slot)
        .expect("Unable to load SystemTimeSlotClock");
    // Choose the fork choice
    let fork_choice = BitwiseLMDGhost::new(block_store.clone(), state_store.clone());

    // Genesis chain
    //TODO: Handle error correctly
    Arc::new(
        BeaconChain::from_genesis(
            state_store.clone(),
            block_store.clone(),
            slot_clock,
            genesis_state,
            genesis_block,
            spec.clone(),
            fork_choice,
        )
        .expect("Terminate if beacon chain generation fails"),
    )
}
