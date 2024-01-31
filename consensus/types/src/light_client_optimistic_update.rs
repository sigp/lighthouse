use super::{EthSpec, ForkName, ForkVersionDeserialize, Slot, SyncAggregate};
use crate::light_client_header::{
    LightClientHeaderAltair, LightClientHeaderCapella, LightClientHeaderDeneb,
};
use crate::light_client_update::Error;
use crate::{light_client_header::LightClientHeader, ChainSpec};
use crate::{BeaconState, SignedBeaconBlock};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;

/// A LightClientOptimisticUpdate is the update we send on each slot,
/// it is based off the current unfinalized epoch is verified only against BLS signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, arbitrary::Arbitrary)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
pub struct LightClientOptimisticUpdate<T: EthSpec> {
    /// The last `BeaconBlockHeader` from the last attested block by the sync committee.
    pub attested_header: LightClientHeader<T>,
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
        attested_block: SignedBeaconBlock<T>,
    ) -> Result<Self, Error> {
        let sync_aggregate = block.message().body().sync_aggregate()?;
        if sync_aggregate.num_set_bits() < chain_spec.min_sync_committee_participants as usize {
            return Err(Error::NotEnoughSyncCommitteeParticipants);
        }

        // Compute and validate attested header.
        let mut attested_header = attested_state.latest_block_header().clone();
        attested_header.state_root = attested_state.tree_hash_root();

        let attested_header: LightClientHeader<T> = match chain_spec
            .fork_name_at_epoch(attested_state.slot().epoch(T::slots_per_epoch()))
        {
            ForkName::Base => return Err(Error::AltairForkNotActive),
            ForkName::Merge => return Err(Error::AltairForkNotActive),
            ForkName::Altair => {
                LightClientHeaderAltair::block_to_light_client_header(attested_block)?.into()
            }
            ForkName::Capella => {
                LightClientHeaderCapella::block_to_light_client_header(attested_block)?.into()
            }
            ForkName::Deneb => {
                LightClientHeaderDeneb::block_to_light_client_header(attested_block)?.into()
            }
        };

        Ok(Self {
            attested_header,
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

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::MainnetEthSpec;

//     ssz_tests!(LightClientOptimisticUpdate<MainnetEthSpec>);
// }
