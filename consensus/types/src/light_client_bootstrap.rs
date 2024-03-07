use super::{BeaconState, EthSpec, FixedVector, Hash256, SyncCommittee};
use crate::{
    light_client_update::*, test_utils::TestRandom, ChainSpec, ForkName, ForkVersionDeserialize,
    LightClientHeader, SignedBeaconBlock,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use ssz::Decode;
use ssz_derive::Encode;
use std::sync::Arc;
use test_random_derive::TestRandom;

/// A LightClientBootstrap is the initializer we send over to light_client nodes
/// that are trying to generate their basic storage when booting up.
#[derive(
    Debug, Clone, PartialEq, Serialize, Deserialize, Encode, arbitrary::Arbitrary, TestRandom,
)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
pub struct LightClientBootstrap<T: EthSpec> {
    /// The requested beacon block header.
    pub header: LightClientHeader<T>,
    /// The `SyncCommittee` used in the requested period.
    pub current_sync_committee: Arc<SyncCommittee<T>>,
    /// Merkle proof for sync committee
    pub current_sync_committee_branch: FixedVector<Hash256, CurrentSyncCommitteeProofLen>,
}

impl<T: EthSpec> LightClientBootstrap<T> {
    pub fn from_beacon_state(
        beacon_state: &mut BeaconState<T>,
        block: &SignedBeaconBlock<T>,
        chain_spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let mut header = beacon_state.latest_block_header().clone();
        header.state_root = beacon_state.update_tree_hash_cache()?;
        let current_sync_committee_branch =
            beacon_state.compute_merkle_proof(CURRENT_SYNC_COMMITTEE_INDEX)?;

        let fork_name =
            chain_spec.fork_name_at_epoch(beacon_state.slot().epoch(T::slots_per_epoch()));

        let header = LightClientHeader::<T>::block_to_light_client_header(block, fork_name)?;

        Ok(LightClientBootstrap {
            header,
            current_sync_committee: beacon_state.current_sync_committee()?.clone(),
            current_sync_committee_branch: FixedVector::new(current_sync_committee_branch)?,
        })
    }

    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        let mut builder = ssz::SszDecoderBuilder::new(bytes);
        builder.register_anonymous_variable_length_item()?;
        builder.register_type::<SyncCommittee<T>>()?;
        builder.register_type::<FixedVector<Hash256, CurrentSyncCommitteeProofLen>>()?;
        let mut decoder = builder.build()?;

        let header = decoder
            .decode_next_with(|bytes| LightClientHeader::from_ssz_bytes(bytes, fork_name))?;
        let current_sync_committee = decoder.decode_next_with(SyncCommittee::from_ssz_bytes)?;
        let current_sync_committee_branch =
            decoder.decode_next_with(FixedVector::from_ssz_bytes)?;

        Ok(Self {
            header,
            current_sync_committee: Arc::new(current_sync_committee),
            current_sync_committee_branch,
        })
    }
}

impl<T: EthSpec> ForkVersionDeserialize for LightClientBootstrap<T> {
    fn deserialize_by_fork<'de, D: Deserializer<'de>>(
        value: Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        match fork_name {
            ForkName::Altair | ForkName::Merge | ForkName::Capella | ForkName::Deneb => {
                Ok(serde_json::from_value::<LightClientBootstrap<T>>(value)
                    .map_err(serde::de::Error::custom))?
            }
            ForkName::Base => Err(serde::de::Error::custom(format!(
                "LightClientBootstrap failed to deserialize: unsupported fork '{}'",
                fork_name
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_tests_by_fork!(LightClientBootstrap<MainnetEthSpec>, ForkName::Deneb);
}
