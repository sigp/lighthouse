use super::{EthSpec, FixedVector, Hash256, Slot, SyncAggregate};
use crate::{
    light_client_update::*, test_utils::TestRandom, ForkName, ForkVersionDeserialize,
    LightClientHeader,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use ssz::Decode;
use ssz_derive::Encode;
use test_random_derive::TestRandom;

/// A LightClientFinalityUpdate is the update light_client request or received by a gossip that
/// signal a new finalized beacon block header for the light client sync protocol.
#[derive(
    Debug, Clone, PartialEq, Serialize, Deserialize, Encode, arbitrary::Arbitrary, TestRandom,
)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
pub struct LightClientFinalityUpdate<T: EthSpec> {
    /// The last `BeaconBlockHeader` from the last attested block by the sync committee.
    pub attested_header: LightClientHeader<T>,
    /// The last `BeaconBlockHeader` from the last attested finalized block (end of epoch).
    pub finalized_header: LightClientHeader<T>,
    /// Merkle proof attesting finalized header.
    pub finality_branch: FixedVector<Hash256, FinalizedRootProofLen>,
    /// current sync aggreggate
    pub sync_aggregate: SyncAggregate<T>,
    /// Slot of the sync aggregated singature
    pub signature_slot: Slot,
}

impl<E: EthSpec> LightClientFinalityUpdate<E> {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        let mut builder = ssz::SszDecoderBuilder::new(bytes);
        builder.register_anonymous_variable_length_item()?;
        builder.register_anonymous_variable_length_item()?;
        builder.register_type::<FixedVector<Hash256, FinalizedRootProofLen>>()?;
        builder.register_type::<SyncAggregate<E>>()?;
        builder.register_type::<Slot>()?;
        let mut decoder = builder.build()?;

        let attested_header = decoder
            .decode_next_with(|bytes| LightClientHeader::from_ssz_bytes(bytes, fork_name))?;
        let finalized_header = decoder
            .decode_next_with(|bytes| LightClientHeader::from_ssz_bytes(bytes, fork_name))?;
        let finality_branch = decoder.decode_next()?;
        let sync_aggregate = decoder.decode_next()?;
        let signature_slot = decoder.decode_next()?;

        Ok(Self {
            attested_header,
            finalized_header,
            finality_branch,
            sync_aggregate,
            signature_slot,
        })
    }

    pub fn from_ssz_bytes_for_fork(
        bytes: &[u8],
        fork_name: ForkName,
    ) -> Result<Self, ssz::DecodeError> {
        Self::from_ssz_bytes(bytes, fork_name)
    }
}

impl<E: EthSpec> ForkVersionDeserialize for LightClientFinalityUpdate<E> {
    fn deserialize_by_fork<'de, D: Deserializer<'de>>(
        value: Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        match fork_name {
            ForkName::Altair | ForkName::Merge | ForkName::Capella | ForkName::Deneb => Ok(
                serde_json::from_value::<LightClientFinalityUpdate<E>>(value)
                    .map_err(serde::de::Error::custom),
            )?,
            ForkName::Base => Err(serde::de::Error::custom(format!(
                "LightClientFinalityUpdate failed to deserialize: unsupported fork '{}'",
                fork_name
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_tests_by_fork!(LightClientFinalityUpdate<MainnetEthSpec>, ForkName::Deneb);
}
