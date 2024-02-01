use super::{
    EthSpec, FixedVector, Hash256, SignedBeaconBlock, SignedBlindedBeaconBlock, Slot, SyncAggregate,
};
use crate::{
    light_client_update::*, test_utils::TestRandom, BeaconState, ChainSpec, ForkName,
    ForkVersionDeserialize, LightClientHeader,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;

/// A LightClientFinalityUpdate is the update light_client request or received by a gossip that
/// signal a new finalized beacon block header for the light client sync protocol.
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
pub struct LightClientFinalityUpdate<T: EthSpec> {
    /// The last `BeaconBlockHeader` from the last attested block by the sync committee.
    pub attested_header: LightClientHeader,
    /// The last `BeaconBlockHeader` from the last attested finalized block (end of epoch).
    pub finalized_header: LightClientHeader,
    /// Merkle proof attesting finalized header.
    pub finality_branch: FixedVector<Hash256, FinalizedRootProofLen>,
    /// current sync aggreggate
    pub sync_aggregate: SyncAggregate<T>,
    /// Slot of the sync aggregated singature
    pub signature_slot: Slot,
}

impl<T: EthSpec> LightClientFinalityUpdate<T> {
    pub fn new(
        chain_spec: &ChainSpec,
        beacon_state: &BeaconState<T>,
        block: &SignedBeaconBlock<T>,
        attested_state: &mut BeaconState<T>,
        finalized_block: &SignedBlindedBeaconBlock<T>,
    ) -> Result<Self, Error> {
        let altair_fork_epoch = chain_spec
            .altair_fork_epoch
            .ok_or(Error::AltairForkNotActive)?;
        if beacon_state.slot().epoch(T::slots_per_epoch()) < altair_fork_epoch {
            return Err(Error::AltairForkNotActive);
        }

        let sync_aggregate = block.message().body().sync_aggregate()?;
        if sync_aggregate.num_set_bits() < chain_spec.min_sync_committee_participants as usize {
            return Err(Error::NotEnoughSyncCommitteeParticipants);
        }

        // Compute and validate attested header.
        let mut attested_header = attested_state.latest_block_header().clone();
        attested_header.state_root = attested_state.update_tree_hash_cache()?;
        // Build finalized header from finalized block
        let finalized_header = finalized_block.message().block_header();

        if finalized_header.tree_hash_root() != beacon_state.finalized_checkpoint().root {
            return Err(Error::InvalidFinalizedBlock);
        }

        let finality_branch = attested_state.compute_merkle_proof(FINALIZED_ROOT_INDEX)?;
        Ok(Self {
            attested_header: attested_header.into(),
            finalized_header: finalized_header.into(),
            finality_branch: FixedVector::new(finality_branch)?,
            sync_aggregate: sync_aggregate.clone(),
            signature_slot: block.slot(),
        })
    }
}

impl<T: EthSpec> ForkVersionDeserialize for LightClientFinalityUpdate<T> {
    fn deserialize_by_fork<'de, D: Deserializer<'de>>(
        value: Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        match fork_name {
            ForkName::Altair | ForkName::Merge => Ok(serde_json::from_value::<
                LightClientFinalityUpdate<T>,
            >(value)
            .map_err(serde::de::Error::custom))?,
            ForkName::Base | ForkName::Capella | ForkName::Deneb => {
                Err(serde::de::Error::custom(format!(
                    "LightClientFinalityUpdate failed to deserialize: unsupported fork '{}'",
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

    ssz_tests!(LightClientFinalityUpdate<MainnetEthSpec>);
}
