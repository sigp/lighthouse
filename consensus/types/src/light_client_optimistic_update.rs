use super::{EthSpec, ForkName, ForkVersionDeserialize, Slot, SyncAggregate};
use crate::test_utils::TestRandom;
use crate::LightClientHeader;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use ssz_derive::Encode;
use test_random_derive::TestRandom;

/// A LightClientOptimisticUpdate is the update we send on each slot,
/// it is based off the current unfinalized epoch is verified only against BLS signature.
#[derive(
    Debug, Clone, PartialEq, Serialize, Deserialize, Encode, arbitrary::Arbitrary, TestRandom,
)]
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

impl<E: EthSpec> LightClientOptimisticUpdate<E> {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        let mut builder = ssz::SszDecoderBuilder::new(bytes);
        builder.register_anonymous_variable_length_item()?;
        builder.register_type::<SyncAggregate<E>>()?;
        builder.register_type::<Slot>()?;
        let mut decoder = builder.build()?;

        let attested_header = decoder
            .decode_next_with(|bytes| LightClientHeader::from_ssz_bytes(bytes, fork_name))?;
        let sync_aggregate = decoder.decode_next()?;
        let signature_slot = decoder.decode_next()?;

        Ok(Self {
            attested_header,
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

impl<T: EthSpec> ForkVersionDeserialize for LightClientOptimisticUpdate<T> {
    fn deserialize_by_fork<'de, D: Deserializer<'de>>(
        value: Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        match fork_name {
            ForkName::Altair | ForkName::Merge | ForkName::Capella | ForkName::Deneb => Ok(
                serde_json::from_value::<LightClientOptimisticUpdate<T>>(value)
                    .map_err(serde::de::Error::custom),
            )?,
            ForkName::Base => Err(serde::de::Error::custom(format!(
                "LightClientOptimisticUpdate failed to deserialize: unsupported fork '{}'",
                fork_name
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_tests_by_fork!(LightClientOptimisticUpdate<MainnetEthSpec>, ForkName::Deneb);
}
