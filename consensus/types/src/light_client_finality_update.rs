use super::{EthSpec, FixedVector, Hash256, Slot, SyncAggregate};
use crate::{
    light_client_update::*,
    test_utils::TestRandom,
    ForkName, ForkVersionDeserialize, LightClientHeader
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;

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
    arbitrary::Arbitrary,
    TestRandom,
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

impl<T: EthSpec> ForkVersionDeserialize for LightClientFinalityUpdate<T> {
    fn deserialize_by_fork<'de, D: Deserializer<'de>>(
        value: Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        match fork_name {
            ForkName::Altair | ForkName::Merge | ForkName::Capella | ForkName::Deneb => Ok(
                serde_json::from_value::<LightClientFinalityUpdate<T>>(value)
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

    ssz_tests!(LightClientFinalityUpdate<MainnetEthSpec>);
}
