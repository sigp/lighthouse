//! Identifies each shard by an integer identifier.
use crate::{BeaconState, CommitteeIndex, EthSpec, Slot};
use serde_derive::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubnetId(u64);

impl SubnetId {
    pub fn new(id: u64) -> Self {
        SubnetId(id)
    }

    /// Compute the subnet for an attestation with
    /// attestation.data.slot == slot and attestation.data.index == index
    pub fn compute_subnet_for_attestation<T: EthSpec>(
        state: &BeaconState<T>,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<SubnetId, String> {
        let slots_since_epoch_start: u64 = slot.as_u64() % T::slots_per_epoch();
        let committees_since_epoch_start = state
            .get_committee_count_at_slot(slot)
            .map_err(|e| format!("Failed to get committee count: {:?}", e))?
            * slots_since_epoch_start;
        Ok(SubnetId::new(
            (committees_since_epoch_start + committee_index)
                % T::default_spec().attestation_subnet_count,
        ))
    }
}

impl Deref for SubnetId {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SubnetId {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
