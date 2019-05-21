// Initialisation functions to generate a new BeaconChain.
// Note: A new version of ClientTypes may need to be implemented for the lighthouse
// testnet. These are examples. Also. there is code duplication which can/should be cleaned up.

use crate::BeaconChain;
use fork_choice::BitwiseLMDGhost;
use slot_clock::SystemTimeSlotClock;
use std::path::PathBuf;
use std::sync::Arc;
use store::{DiskStore, MemoryStore};
use tree_hash::TreeHash;
use types::test_utils::TestingBeaconStateBuilder;
use types::{BeaconBlock, ChainSpec, FewValidatorsEthSpec, FoundationEthSpec, Hash256};

//TODO: Correct this for prod
//TODO: Account for historical db
pub fn initialise_beacon_chain(
    spec: &ChainSpec,
    db_name: Option<&PathBuf>,
) -> Arc<
    BeaconChain<
        DiskStore,
        SystemTimeSlotClock,
        BitwiseLMDGhost<DiskStore, FoundationEthSpec>,
        FoundationEthSpec,
    >,
> {
    let path = db_name.expect("db_name cannot be None.");
    let store = DiskStore::open(path).expect("Unable to open DB.");
    let store = Arc::new(store);

    let state_builder = TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(8, &spec);
    let (genesis_state, _keypairs) = state_builder.build();

    let mut genesis_block = BeaconBlock::empty(&spec);
    genesis_block.state_root = Hash256::from_slice(&genesis_state.tree_hash_root());

    // Slot clock
    let slot_clock = SystemTimeSlotClock::new(
        spec.genesis_slot,
        genesis_state.genesis_time,
        spec.seconds_per_slot,
    )
    .expect("Unable to load SystemTimeSlotClock");
    // Choose the fork choice
    let fork_choice = BitwiseLMDGhost::new(store.clone());

    // Genesis chain
    //TODO: Handle error correctly
    Arc::new(
        BeaconChain::from_genesis(
            store,
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
pub fn initialise_test_beacon_chain_with_memory_db(
    spec: &ChainSpec,
    _db_name: Option<&PathBuf>,
) -> Arc<
    BeaconChain<
        MemoryStore,
        SystemTimeSlotClock,
        BitwiseLMDGhost<MemoryStore, FewValidatorsEthSpec>,
        FewValidatorsEthSpec,
    >,
> {
    let store = Arc::new(MemoryStore::open());

    let state_builder = TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(8, spec);
    let (genesis_state, _keypairs) = state_builder.build();

    let mut genesis_block = BeaconBlock::empty(spec);
    genesis_block.state_root = Hash256::from_slice(&genesis_state.tree_hash_root());

    // Slot clock
    let slot_clock = SystemTimeSlotClock::new(
        spec.genesis_slot,
        genesis_state.genesis_time,
        spec.seconds_per_slot,
    )
    .expect("Unable to load SystemTimeSlotClock");
    // Choose the fork choice
    let fork_choice = BitwiseLMDGhost::new(store.clone());

    // Genesis chain
    //TODO: Handle error correctly
    Arc::new(
        BeaconChain::from_genesis(
            store,
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
pub fn initialise_test_beacon_chain_with_disk_db(
    spec: &ChainSpec,
    db_name: Option<&PathBuf>,
) -> Arc<
    BeaconChain<
        DiskStore,
        SystemTimeSlotClock,
        BitwiseLMDGhost<DiskStore, FewValidatorsEthSpec>,
        FewValidatorsEthSpec,
    >,
> {
    let path = db_name.expect("db_name cannot be None.");
    let store = DiskStore::open(path).expect("Unable to open DB.");
    let store = Arc::new(store);

    let state_builder = TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(8, spec);
    let (genesis_state, _keypairs) = state_builder.build();

    let mut genesis_block = BeaconBlock::empty(spec);
    genesis_block.state_root = Hash256::from_slice(&genesis_state.tree_hash_root());

    // Slot clock
    let slot_clock = SystemTimeSlotClock::new(
        spec.genesis_slot,
        genesis_state.genesis_time,
        spec.seconds_per_slot,
    )
    .expect("Unable to load SystemTimeSlotClock");
    // Choose the fork choice
    let fork_choice = BitwiseLMDGhost::new(store.clone());

    // Genesis chain
    //TODO: Handle error correctly
    Arc::new(
        BeaconChain::from_genesis(
            store,
            slot_clock,
            genesis_state,
            genesis_block,
            spec.clone(),
            fork_choice,
        )
        .expect("Terminate if beacon chain generation fails"),
    )
}
