use super::{EthSpec, FixedVector, Hash256, Slot, SyncAggregate};
use crate::{light_client_update::*, ForkName, ForkVersionDeserialize, LightClientHeader};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use ssz_derive::{Decode, Encode};

/// A LightClientFinalityUpdate is the update lightclient request or received by a gossip that
/// signal a new finalized beacon block header for the light client sync protocol.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, arbitrary::Arbitrary)]
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

impl<T: EthSpec> LightClientFinalityUpdate<T> {
    pub fn new(update: LightClientUpdate<T>) -> Result<Self, Error> {
        Ok(Self {
            attested_header: update.attested_header,
            finalized_header: update.finalized_header,
            finality_branch: update.finality_branch,
            sync_aggregate: update.sync_aggregate,
            signature_slot: update.signature_slot,
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
