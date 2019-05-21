use crate::{ArcBeaconChain, ClientConfig};
use beacon_chain::{
    fork_choice::BitwiseLMDGhost,
    initialise,
    slot_clock::{SlotClock, SystemTimeSlotClock},
    store::{DiskStore, MemoryStore, Store},
};
use fork_choice::ForkChoice;
use types::{EthSpec, FewValidatorsEthSpec, FoundationEthSpec};

pub trait ClientTypes {
    type DB: Store + 'static;
    type SlotClock: SlotClock + 'static;
    type ForkChoice: ForkChoice + 'static;
    type EthSpec: EthSpec + 'static;

    fn initialise_beacon_chain(
        config: &ClientConfig,
    ) -> ArcBeaconChain<Self::DB, Self::SlotClock, Self::ForkChoice, Self::EthSpec>;
}

pub struct StandardClientType;

impl ClientTypes for StandardClientType {
    type DB = DiskStore;
    type SlotClock = SystemTimeSlotClock;
    type ForkChoice = BitwiseLMDGhost<Self::DB, Self::EthSpec>;
    type EthSpec = FoundationEthSpec;

    fn initialise_beacon_chain(
        config: &ClientConfig,
    ) -> ArcBeaconChain<Self::DB, Self::SlotClock, Self::ForkChoice, Self::EthSpec> {
        initialise::initialise_beacon_chain(&config.spec, Some(&config.db_name))
    }
}

pub struct MemoryStoreTestingClientType;

impl ClientTypes for MemoryStoreTestingClientType {
    type DB = MemoryStore;
    type SlotClock = SystemTimeSlotClock;
    type ForkChoice = BitwiseLMDGhost<Self::DB, Self::EthSpec>;
    type EthSpec = FewValidatorsEthSpec;

    fn initialise_beacon_chain(
        config: &ClientConfig,
    ) -> ArcBeaconChain<Self::DB, Self::SlotClock, Self::ForkChoice, Self::EthSpec> {
        initialise::initialise_test_beacon_chain_with_memory_db(&config.spec, None)
    }
}

pub struct DiskStoreTestingClientType;

impl ClientTypes for DiskStoreTestingClientType {
    type DB = DiskStore;
    type SlotClock = SystemTimeSlotClock;
    type ForkChoice = BitwiseLMDGhost<Self::DB, Self::EthSpec>;
    type EthSpec = FewValidatorsEthSpec;

    fn initialise_beacon_chain(
        config: &ClientConfig,
    ) -> ArcBeaconChain<Self::DB, Self::SlotClock, Self::ForkChoice, Self::EthSpec> {
        initialise::initialise_test_beacon_chain_with_disk_db(&config.spec, Some(&config.db_name))
    }
}
