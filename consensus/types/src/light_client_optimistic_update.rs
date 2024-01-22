use super::{EthSpec, ForkName, ForkVersionDeserialize, Slot, SyncAggregate};
use crate::light_client_header::LightClientHeader;
use crate::{
    light_client_update::Error, test_utils::TestRandom, BeaconState, ChainSpec, SignedBeaconBlock,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;

/// A LightClientOptimisticUpdate is the update we send on each slot,
/// it is based off the current unfinalized epoch is verified only against BLS signature.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TestRandom,
    arbitrary::Arbitrary,
)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
pub struct LightClientOptimisticUpdate<T: EthSpec> {
    /// The last `BeaconBlockHeader` from the last attested block by the sync committee.
    pub attested_header: LightClientHeader,
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
            attested_header: attested_header.into(),
            sync_aggregate: sync_aggregate.clone(),
            signature_slot: block.slot(),
        })
    }
}

impl<T: EthSpec> ForkVersionDeserialize for LightClientOptimisticUpdate<T> {
    fn deserialize_by_fork<'de, D: Deserializer<'de>>(
        value: Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        match fork_name {
            ForkName::Altair | ForkName::Merge => Ok(serde_json::from_value::<
                LightClientOptimisticUpdate<T>,
            >(value)
            .map_err(serde::de::Error::custom))?,
            ForkName::Base | ForkName::Capella | ForkName::Deneb => {
                Err(serde::de::Error::custom(format!(
                    "LightClientOptimisticUpdate failed to deserialize: unsupported fork '{}'",
                    fork_name
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_tests!(LightClientOptimisticUpdate<MainnetEthSpec>);
}
