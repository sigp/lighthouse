use db::{ClientDB, DiskDB, MemoryDB};
use fork_choice::{BitwiseLMDGhost, ForkChoice};
use slot_clock::{SlotClock, SystemTimeSlotClock, TestingSlotClock};
use beacon_chain::initialise;
use std::sync::Arc;
use crate::ClientConfig

pub trait ClientTypes {
    type ForkChoice: ForkChoice;
    type DB: ClientDB;
    type SlotClock: SlotClock;

    pub fn initialise_beacon_chain(cchain_spec: &ClientConfig) -> Arc<BeaconChain<DB,SlotClock,ForkChoice>>);
}

pub struct StandardClientType

impl ClientTypes for StandardClientType {
    type DB = DiskDB;
    type ForkChoice = BitwiseLMDGhost<DiskDB>;
    type SlotClock = SystemTimeSlotClock;

    pub fn initialise_beacon_chain(config: &ClientConfig) -> Arc<BeaconChain<DB,SlotClock,ForkChoice>>) {
        initialise::initialise_beacon_chain(config.chain_spec, config.db_name)
    }

}

pub struct TestingClientType

impl ClientTypes for TestingClientType {
    type DB = MemoryDB;
    type SlotClock = TestingSlotClock;
    type ForkChoice = BitwiseLMDGhost<MemoryDB>;

    pub fn initialise_beacon_chain(config: &ClientConfig) -> Arc<BeaconChain<DB,SlotClock,ForkChoice>>) {
        initialise::initialise_test_beacon_chain(config.chain_spec, None)
    }
}
