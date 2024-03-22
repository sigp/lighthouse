use super::{EthSpec, ForkName, ForkVersionDeserialize, Slot, SyncAggregate};
use crate::test_utils::TestRandom;
use crate::{
    light_client_update::*, ChainSpec, LightClientHeaderAltair, LightClientHeaderCapella,
    LightClientHeaderDeneb, SignedBeaconBlock,
};
use derivative::Derivative;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use ssz::Decode;
use ssz_derive::Decode;
use ssz_derive::Encode;
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash::Hash256;
use tree_hash_derive::TreeHash;

/// A LightClientOptimisticUpdate is the update we send on each slot,
/// it is based off the current unfinalized epoch is verified only against BLS signature.
#[superstruct(
    variants(Altair, Capella, Deneb),
    variant_attributes(
        derive(
            Debug,
            Clone,
            PartialEq,
            Serialize,
            Deserialize,
            Derivative,
            Decode,
            Encode,
            TestRandom,
            arbitrary::Arbitrary,
            TreeHash,
        ),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec"),
    )
)]
#[derive(
    Debug, Clone, Serialize, Encode, TreeHash, Deserialize, arbitrary::Arbitrary, PartialEq,
)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
#[arbitrary(bound = "E: EthSpec")]
pub struct LightClientOptimisticUpdate<E: EthSpec> {
    /// The last `BeaconBlockHeader` from the last attested block by the sync committee.
    #[superstruct(only(Altair), partial_getter(rename = "attested_header_altair"))]
    pub attested_header: LightClientHeaderAltair<E>,
    #[superstruct(only(Capella), partial_getter(rename = "attested_header_capella"))]
    pub attested_header: LightClientHeaderCapella<E>,
    #[superstruct(only(Deneb), partial_getter(rename = "attested_header_deneb"))]
    pub attested_header: LightClientHeaderDeneb<E>,
    /// current sync aggreggate
    pub sync_aggregate: SyncAggregate<E>,
    /// Slot of the sync aggregated singature
    pub signature_slot: Slot,
}

impl<E: EthSpec> LightClientOptimisticUpdate<E> {
    pub fn new(
        attested_block: &SignedBeaconBlock<E>,
        sync_aggregate: SyncAggregate<E>,
        signature_slot: Slot,
        chain_spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let optimistic_update = match attested_block
            .fork_name(chain_spec)
            .map_err(|_| Error::InconsistentFork)?
        {
            ForkName::Altair | ForkName::Merge => {
                let optimistic_update = LightClientOptimisticUpdateAltair {
                    attested_header: LightClientHeaderAltair::block_to_light_client_header(
                        attested_block,
                    )?,
                    sync_aggregate,
                    signature_slot,
                };
                Self::Altair(optimistic_update)
            }
            ForkName::Capella => {
                let optimistic_update = LightClientOptimisticUpdateCapella {
                    attested_header: LightClientHeaderCapella::block_to_light_client_header(
                        attested_block,
                    )?,
                    sync_aggregate,
                    signature_slot,
                };
                Self::Capella(optimistic_update)
            }
            ForkName::Deneb => {
                let optimistic_update = LightClientOptimisticUpdateDeneb {
                    attested_header: LightClientHeaderDeneb::block_to_light_client_header(
                        attested_block,
                    )?,
                    sync_aggregate,
                    signature_slot,
                };
                Self::Deneb(optimistic_update)
            }
            ForkName::Base => return Err(Error::AltairForkNotActive),
        };

        Ok(optimistic_update)
    }

    pub fn get_slot<'a>(&'a self) -> Slot {
        map_light_client_optimistic_update_ref!(&'a _, self.to_ref(), |inner, cons| {
            cons(inner);
            inner.attested_header.beacon.slot
        })
    }

    pub fn get_canonical_root<'a>(&'a self) -> Hash256 {
        map_light_client_optimistic_update_ref!(&'a _, self.to_ref(), |inner, cons| {
            cons(inner);
            inner.attested_header.beacon.canonical_root()
        })
    }

    pub fn get_parent_root<'a>(&'a self) -> Hash256 {
        map_light_client_optimistic_update_ref!(&'a _, self.to_ref(), |inner, cons| {
            cons(inner);
            inner.attested_header.beacon.parent_root
        })
    }

    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        let optimistic_update = match fork_name {
            ForkName::Altair | ForkName::Merge => {
                let optimistic_update = LightClientOptimisticUpdateAltair::from_ssz_bytes(bytes)?;
                Self::Altair(optimistic_update)
            }
            ForkName::Capella => {
                let optimistic_update = LightClientOptimisticUpdateCapella::from_ssz_bytes(bytes)?;
                Self::Capella(optimistic_update)
            }
            ForkName::Deneb => {
                let optimistic_update = LightClientOptimisticUpdateDeneb::from_ssz_bytes(bytes)?;
                Self::Deneb(optimistic_update)
            }
            ForkName::Base => {
                return Err(ssz::DecodeError::BytesInvalid(format!(
                    "LightClientOptimisticUpdate decoding for {fork_name} not implemented"
                )))
            }
        };

        Ok(optimistic_update)
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

    ssz_tests!(LightClientOptimisticUpdateDeneb<MainnetEthSpec>);
}
