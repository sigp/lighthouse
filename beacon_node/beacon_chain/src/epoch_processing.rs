use super::{BeaconChain, ClientDB, DBError, SlotClock};

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
{
    pub fn per_epoch_processing(&self) {}
}
