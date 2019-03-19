use crate::ClientConfig;
use beacon_chain::{
    db::{ClientDB, DiskDB, MemoryDB},
    fork_choice::BitwiseLMDGhost,
    initialise,
    slot_clock::{SlotClock, SystemTimeSlotClock},
    BeaconChain,
};
use fork_choice::ForkChoice;

use std::sync::Arc;

pub trait ClientTypes {
    type DB: ClientDB + 'static;
    type SlotClock: SlotClock + 'static;
    type ForkChoice: ForkChoice + 'static;

    fn initialise_beacon_chain(
        config: &ClientConfig,
    ) -> Arc<BeaconChain<Self::DB, Self::SlotClock, Self::ForkChoice>>;
}

pub struct StandardClientType;

impl ClientTypes for StandardClientType {
    type DB = DiskDB;
    type SlotClock = SystemTimeSlotClock;
    type ForkChoice = BitwiseLMDGhost<DiskDB>;

    fn initialise_beacon_chain(
        config: &ClientConfig,
    ) -> Arc<BeaconChain<Self::DB, Self::SlotClock, Self::ForkChoice>> {
        initialise::initialise_beacon_chain(&config.spec, Some(&config.db_name))
    }
}

pub struct TestingClientType;

impl ClientTypes for TestingClientType {
    type DB = MemoryDB;
    type SlotClock = SystemTimeSlotClock;
    type ForkChoice = BitwiseLMDGhost<MemoryDB>;

    fn initialise_beacon_chain(
        config: &ClientConfig,
    ) -> Arc<BeaconChain<Self::DB, Self::SlotClock, Self::ForkChoice>> {
        initialise::initialise_test_beacon_chain(&config.spec, None)
    }
}
