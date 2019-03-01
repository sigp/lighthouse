use db::{ClientDB, DiskDB, MemoryDB};
use fork_choice::{BitwiseLMDGhost, ForkChoice};
use slot_clock::{SlotClock, SystemTimeSlotClock, TestingSlotClock};

pub trait ClientTypes {
    type ForkChoice: ForkChoice;
    type DB: ClientDB;
    type SlotClock: SlotClock;
}

pub struct StandardClientType {}

impl ClientTypes for StandardClientType {
    type DB = DiskDB;
    type ForkChoice = BitwiseLMDGhost<DiskDB>;
    type SlotClock = SystemTimeSlotClock;
}

pub struct TestingClientType {}

impl ClientTypes for TestingClientType {
    type DB = MemoryDB;
    type SlotClock = TestingSlotClock;
    type ForkChoice = BitwiseLMDGhost<MemoryDB>;
}
