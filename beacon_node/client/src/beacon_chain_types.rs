use beacon_chain::{
    fork_choice::BitwiseLMDGhost,
    slot_clock::SystemTimeSlotClock,
    store::{DiskStore, MemoryStore, Store},
    BeaconChain, BeaconChainTypes,
};
use fork_choice::ForkChoice;
use slog::{info, Logger};
use slot_clock::SlotClock;
use std::sync::Arc;
use tree_hash::TreeHash;
use types::{
    test_utils::TestingBeaconStateBuilder, BeaconBlock, EthSpec, Hash256, LighthouseTestnetEthSpec,
};

/// The number initial validators when starting the `LighthouseTestnet`.
const TESTNET_VALIDATOR_COUNT: usize = 16;

/// Provides a new, initialized `BeaconChain`
pub trait InitialiseBeaconChain<T: BeaconChainTypes> {
    fn initialise_beacon_chain(store: Arc<T::Store>, log: Logger) -> BeaconChain<T>;
}

/// A testnet-suitable BeaconChainType, using `MemoryStore`.
#[derive(Clone)]
pub struct TestnetMemoryBeaconChainTypes;

impl BeaconChainTypes for TestnetMemoryBeaconChainTypes {
    type Store = MemoryStore;
    type SlotClock = SystemTimeSlotClock;
    type ForkChoice = BitwiseLMDGhost<Self::Store, Self::EthSpec>;
    type EthSpec = LighthouseTestnetEthSpec;
}

impl<T: BeaconChainTypes> InitialiseBeaconChain<T> for TestnetMemoryBeaconChainTypes {
    fn initialise_beacon_chain(store: Arc<T::Store>, log: Logger) -> BeaconChain<T> {
        maybe_load_from_store_for_testnet::<_, T::Store, T::EthSpec>(store, log)
    }
}

/// A testnet-suitable BeaconChainType, using `DiskStore`.
#[derive(Clone)]
pub struct TestnetDiskBeaconChainTypes;

impl BeaconChainTypes for TestnetDiskBeaconChainTypes {
    type Store = DiskStore;
    type SlotClock = SystemTimeSlotClock;
    type ForkChoice = BitwiseLMDGhost<Self::Store, Self::EthSpec>;
    type EthSpec = LighthouseTestnetEthSpec;
}

impl<T: BeaconChainTypes> InitialiseBeaconChain<T> for TestnetDiskBeaconChainTypes {
    fn initialise_beacon_chain(store: Arc<T::Store>, log: Logger) -> BeaconChain<T> {
        maybe_load_from_store_for_testnet::<_, T::Store, T::EthSpec>(store, log)
    }
}

/// Loads a `BeaconChain` from `store`, if it exists. Otherwise, create a new chain from genesis.
fn maybe_load_from_store_for_testnet<T, U: Store, V: EthSpec>(
    store: Arc<U>,
    log: Logger,
) -> BeaconChain<T>
where
    T: BeaconChainTypes<Store = U>,
    T::ForkChoice: ForkChoice<U>,
{
    if let Ok(Some(beacon_chain)) = BeaconChain::from_store(store.clone()) {
        info!(
            log,
            "Loaded BeaconChain from store";
            "slot" => beacon_chain.head().beacon_state.slot,
            "best_slot" => beacon_chain.best_slot(),
        );

        beacon_chain
    } else {
        info!(log, "Initializing new BeaconChain from genesis");
        let spec = T::EthSpec::spec();

        let state_builder = TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(
            TESTNET_VALIDATOR_COUNT,
            &spec,
        );
        let (genesis_state, _keypairs) = state_builder.build();

        let mut genesis_block = BeaconBlock::empty(&spec);
        genesis_block.state_root = Hash256::from_slice(&genesis_state.tree_hash_root());

        // Slot clock
        let slot_clock = T::SlotClock::new(
            spec.genesis_slot,
            genesis_state.genesis_time,
            spec.seconds_per_slot,
        );
        // Choose the fork choice
        let fork_choice = T::ForkChoice::new(store.clone());

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
}
