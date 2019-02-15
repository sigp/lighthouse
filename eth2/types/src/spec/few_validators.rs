use crate::{ChainSpec, Slot};

impl ChainSpec {
    /// Returns a `ChainSpec` compatible with the specification suitable for 8 validators.
    ///
    /// Spec v0.2.0
    pub fn few_validators() -> Self {
        let genesis_slot = Slot::new(2_u64.pow(19));
        let epoch_length = 8;
        let genesis_epoch = genesis_slot.epoch(epoch_length);

        Self {
            shard_count: 1,
            target_committee_size: 1,
            genesis_slot,
            genesis_epoch,
            epoch_length,
            ..ChainSpec::foundation()
        }
    }
}
