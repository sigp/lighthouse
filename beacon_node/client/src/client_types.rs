use crate::{ArcBeaconChain, ClientConfig};
use beacon_chain::{
    db::{ClientDB, DiskDB, MemoryDB},
    fork_choice::BitwiseLMDGhost,
    initialise,
    slot_clock::{SlotClock, SystemTimeSlotClock},
};
use fork_choice::ForkChoice;
use types::{EthSpec, FewValidatorsEthSpec, FoundationEthSpec};

pub trait ClientTypes {
    type DB: ClientDB + 'static;
    type SlotClock: SlotClock + 'static;
    type ForkChoice: ForkChoice + 'static;
    type EthSpec: EthSpec + 'static;

    fn initialise_beacon_chain(
        config: &ClientConfig,
    ) -> ArcBeaconChain<Self::DB, Self::SlotClock, Self::ForkChoice, Self::EthSpec>;
}

pub struct StandardClientType;

impl ClientTypes for StandardClientType {
    type DB = DiskDB;
    type SlotClock = SystemTimeSlotClock;
    type ForkChoice = BitwiseLMDGhost<DiskDB, Self::EthSpec>;
    type EthSpec = FoundationEthSpec;

    fn initialise_beacon_chain(
        config: &ClientConfig,
    ) -> ArcBeaconChain<Self::DB, Self::SlotClock, Self::ForkChoice, Self::EthSpec> {
        initialise::initialise_beacon_chain(&config.spec, Some(&config.db_name))
    }
}

pub struct MemoryDBTestingClientType;

impl ClientTypes for MemoryDBTestingClientType {
    type DB = MemoryDB;
    type SlotClock = SystemTimeSlotClock;
    type ForkChoice = BitwiseLMDGhost<MemoryDB, Self::EthSpec>;
    type EthSpec = FewValidatorsEthSpec;

    fn initialise_beacon_chain(
        config: &ClientConfig,
    ) -> ArcBeaconChain<Self::DB, Self::SlotClock, Self::ForkChoice, Self::EthSpec> {
        initialise::initialise_test_beacon_chain(&config.spec, None)
    }
}
