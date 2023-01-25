use super::{BeaconBlockHeader, EthSpec, Slot, SyncAggregate};
use crate::{
    light_client_update::Error, test_utils::TestRandom, BeaconState, ChainSpec, SignedBeaconBlock,
};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;

/// A LightClientOptimisticUpdate is the update we send on each slot,
/// it is based off the current unfinalized epoch is verified only against BLS signature.
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TestRandom)]
#[serde(bound = "T: EthSpec")]
pub struct LightClientOptimisticUpdate<T: EthSpec> {
    /// The last `BeaconBlockHeader` from the last attested block by the sync committee.
    pub attested_header: BeaconBlockHeader,
    /// current sync aggreggate
    pub sync_aggregate: SyncAggregate<T>,
    /// Slot of the sync aggregated singature
    pub signature_slot: Slot,
}

impl<T: EthSpec> LightClientOptimisticUpdate<T> {
    pub fn new(
        chain_spec: &ChainSpec,
        block: &SignedBeaconBlock<T>,
        attested_state: &BeaconState<T>,
    ) -> Result<Self, Error> {
        let altair_fork_epoch = chain_spec
            .altair_fork_epoch
            .ok_or(Error::AltairForkNotActive)?;
        if attested_state.slot().epoch(T::slots_per_epoch()) < altair_fork_epoch {
            return Err(Error::AltairForkNotActive);
        }

        let sync_aggregate = block.message().body().sync_aggregate()?;
        if sync_aggregate.num_set_bits() < chain_spec.min_sync_committee_participants as usize {
            return Err(Error::NotEnoughSyncCommitteeParticipants);
        }

        // Compute and validate attested header.
        let mut attested_header = attested_state.latest_block_header().clone();
        attested_header.state_root = attested_state.tree_hash_root();
        Ok(Self {
            attested_header,
            sync_aggregate: sync_aggregate.clone(),
            signature_slot: block.slot(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_tests!(LightClientOptimisticUpdate<MainnetEthSpec>);
}
