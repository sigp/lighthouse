use super::{BeaconChain, ClientDB, SlotClock};
use types::{AttestationData, Hash256};

#[derive(Debug, PartialEq)]
pub enum Error {
    /// The `justified_block_root` is unknown. This is an internal error.
    UnknownJustifiedRoot,
    /// The `epoch_boundary_root` is unknown. This is an internal error.
    UnknownBoundaryRoot,
}

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
{
    /// Produce an `AttestationData` that is valid for the present `slot` and given `shard`.
    pub fn produce_attestation_data(&self, shard: u64) -> Result<AttestationData, Error> {
        let justified_slot = self.justified_slot();
        let justified_block_root = self
            .state
            .read()
            .get_block_root(justified_slot, &self.spec)
            .ok_or_else(|| Error::UnknownJustifiedRoot)?
            .clone();

        let epoch_boundary_root = self
            .state
            .read()
            .get_block_root(
                self.state.read().current_epoch_start_slot(&self.spec),
                &self.spec,
            )
            .ok_or_else(|| Error::UnknownBoundaryRoot)?
            .clone();

        Ok(AttestationData {
            slot: self.state.read().slot,
            shard,
            beacon_block_root: self.head().beacon_block_root.clone(),
            epoch_boundary_root,
            shard_block_root: Hash256::zero(),
            latest_crosslink_root: Hash256::zero(),
            justified_slot,
            justified_block_root,
        })
    }
}
