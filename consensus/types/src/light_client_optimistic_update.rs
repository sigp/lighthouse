use super::{EthSpec, ForkName, ForkVersionDeserialize, Slot, SyncAggregate};
use crate::light_client_header::LightClientHeader;
use crate::light_client_update::Error;
use crate::LightClientUpdate;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use ssz_derive::{Decode, Encode};

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
    pub fn new(update: LightClientUpdate<T>) -> Result<Self, Error> {
        Ok(Self {
            attested_header: update.attested_header,
            sync_aggregate: update.sync_aggregate,
            signature_slot: update.signature_slot,
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
