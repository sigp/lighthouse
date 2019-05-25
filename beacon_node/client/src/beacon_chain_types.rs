use crate::ClientConfig;
use beacon_chain::{
    fork_choice::BitwiseLMDGhost,
    slot_clock::SystemTimeSlotClock,
    store::{DiskStore, MemoryStore, Store},
    BeaconChain, BeaconChainTypes,
};
use std::sync::Arc;
use tree_hash::TreeHash;
use types::{
    test_utils::TestingBeaconStateBuilder, BeaconBlock, EthSpec, FewValidatorsEthSpec, Hash256,
};

/// Provides a new, initialized `BeaconChain`
pub trait InitialiseBeaconChain<T: BeaconChainTypes> {
    fn initialise_beacon_chain(config: &ClientConfig) -> BeaconChain<T>;
}

/// A testnet-suitable BeaconChainType, using `MemoryStore`.
#[derive(Clone)]
pub struct TestnetMemoryBeaconChainTypes;

impl BeaconChainTypes for TestnetMemoryBeaconChainTypes {
    type Store = MemoryStore;
    type SlotClock = SystemTimeSlotClock;
    type ForkChoice = BitwiseLMDGhost<Self::Store, Self::EthSpec>;
    type EthSpec = FewValidatorsEthSpec;
}

impl<T> InitialiseBeaconChain<T> for TestnetMemoryBeaconChainTypes
where
    T: BeaconChainTypes<
        Store = MemoryStore,
        SlotClock = SystemTimeSlotClock,
        ForkChoice = BitwiseLMDGhost<MemoryStore, FewValidatorsEthSpec>,
    >,
{
    fn initialise_beacon_chain(_config: &ClientConfig) -> BeaconChain<T> {
        initialize_chain(MemoryStore::open())
    }
}

/// A testnet-suitable BeaconChainType, using `DiskStore`.
#[derive(Clone)]
pub struct TestnetDiskBeaconChainTypes;

impl BeaconChainTypes for TestnetDiskBeaconChainTypes {
    type Store = DiskStore;
    type SlotClock = SystemTimeSlotClock;
    type ForkChoice = BitwiseLMDGhost<Self::Store, Self::EthSpec>;
    type EthSpec = FewValidatorsEthSpec;
}

impl<T> InitialiseBeaconChain<T> for TestnetDiskBeaconChainTypes
where
    T: BeaconChainTypes<
        Store = DiskStore,
        SlotClock = SystemTimeSlotClock,
        ForkChoice = BitwiseLMDGhost<DiskStore, FewValidatorsEthSpec>,
    >,
{
    fn initialise_beacon_chain(config: &ClientConfig) -> BeaconChain<T> {
        let store = DiskStore::open(&config.db_name).expect("Unable to open DB.");

        initialize_chain(store)
    }
}

/// Produces a `BeaconChain` given some pre-initialized `Store`.
fn initialize_chain<T, U: Store, V: EthSpec>(store: U) -> BeaconChain<T>
where
    T: BeaconChainTypes<
        Store = U,
        SlotClock = SystemTimeSlotClock,
        ForkChoice = BitwiseLMDGhost<U, V>,
    >,
{
    let spec = T::EthSpec::spec();

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
    BeaconChain::from_genesis(
        store,
        slot_clock,
        genesis_state,
        genesis_block,
        spec.clone(),
        fork_choice,
    )
    .expect("Terminate if beacon chain generation fails")
}
