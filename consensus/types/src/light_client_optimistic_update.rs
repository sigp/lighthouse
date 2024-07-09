use super::{EthSpec, ForkName, ForkVersionDeserialize, LightClientHeader, Slot, SyncAggregate};
use crate::test_utils::TestRandom;
use crate::{
    light_client_update::*, ChainSpec, LightClientHeaderAltair, LightClientHeaderCapella,
    LightClientHeaderDeneb, LightClientHeaderElectra, SignedBeaconBlock,
};
use derivative::Derivative;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use ssz::{Decode, Encode};
use ssz_derive::Decode;
use ssz_derive::Encode;
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash::Hash256;
use tree_hash_derive::TreeHash;

/// A LightClientOptimisticUpdate is the update we send on each slot,
/// it is based off the current unfinalized epoch is verified only against BLS signature.
#[superstruct(
    variants(Altair, Capella, Deneb, Electra),
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
    #[superstruct(only(Electra), partial_getter(rename = "attested_header_electra"))]
    pub attested_header: LightClientHeaderElectra<E>,
    /// current sync aggregate
    pub sync_aggregate: SyncAggregate<E>,
    /// Slot of the sync aggregated signature
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
            ForkName::Altair | ForkName::Bellatrix => {
                Self::Altair(LightClientOptimisticUpdateAltair {
                    attested_header: LightClientHeaderAltair::block_to_light_client_header(
                        attested_block,
                    )?,
                    sync_aggregate,
                    signature_slot,
                })
            }
            ForkName::Capella => Self::Capella(LightClientOptimisticUpdateCapella {
                attested_header: LightClientHeaderCapella::block_to_light_client_header(
                    attested_block,
                )?,
                sync_aggregate,
                signature_slot,
            }),
            ForkName::Deneb => Self::Deneb(LightClientOptimisticUpdateDeneb {
                attested_header: LightClientHeaderDeneb::block_to_light_client_header(
                    attested_block,
                )?,
                sync_aggregate,
                signature_slot,
            }),
            ForkName::Electra => Self::Electra(LightClientOptimisticUpdateElectra {
                attested_header: LightClientHeaderElectra::block_to_light_client_header(
                    attested_block,
                )?,
                sync_aggregate,
                signature_slot,
            }),
            ForkName::Base => return Err(Error::AltairForkNotActive),
        };

        Ok(optimistic_update)
    }

    pub fn map_with_fork_name<F, R>(&self, func: F) -> R
    where
        F: Fn(ForkName) -> R,
    {
        match self {
            Self::Altair(_) => func(ForkName::Altair),
            Self::Capella(_) => func(ForkName::Capella),
            Self::Deneb(_) => func(ForkName::Deneb),
            Self::Electra(_) => func(ForkName::Electra),
        }
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
            ForkName::Altair | ForkName::Bellatrix => {
                Self::Altair(LightClientOptimisticUpdateAltair::from_ssz_bytes(bytes)?)
            }
            ForkName::Capella => {
                Self::Capella(LightClientOptimisticUpdateCapella::from_ssz_bytes(bytes)?)
            }
            ForkName::Deneb => {
                Self::Deneb(LightClientOptimisticUpdateDeneb::from_ssz_bytes(bytes)?)
            }
            ForkName::Electra => {
                Self::Electra(LightClientOptimisticUpdateElectra::from_ssz_bytes(bytes)?)
            }
            ForkName::Base => {
                return Err(ssz::DecodeError::BytesInvalid(format!(
                    "LightClientOptimisticUpdate decoding for {fork_name} not implemented"
                )))
            }
        };

        Ok(optimistic_update)
    }

    #[allow(clippy::arithmetic_side_effects)]
    pub fn ssz_max_len_for_fork(fork_name: ForkName) -> usize {
        let fixed_len = match fork_name {
            ForkName::Base => 0,
            ForkName::Altair | ForkName::Bellatrix => {
                <LightClientOptimisticUpdateAltair<E> as Encode>::ssz_fixed_len()
            }
            ForkName::Capella => <LightClientOptimisticUpdateCapella<E> as Encode>::ssz_fixed_len(),
            ForkName::Deneb => <LightClientOptimisticUpdateDeneb<E> as Encode>::ssz_fixed_len(),
            ForkName::Electra => <LightClientOptimisticUpdateElectra<E> as Encode>::ssz_fixed_len(),
        };
        fixed_len + LightClientHeader::<E>::ssz_max_var_len_for_fork(fork_name)
    }
}

impl<E: EthSpec> ForkVersionDeserialize for LightClientOptimisticUpdate<E> {
    fn deserialize_by_fork<'de, D: Deserializer<'de>>(
        value: Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        match fork_name {
            ForkName::Base => Err(serde::de::Error::custom(format!(
                "LightClientOptimisticUpdate failed to deserialize: unsupported fork '{}'",
                fork_name
            ))),
            _ => Ok(
                serde_json::from_value::<LightClientOptimisticUpdate<E>>(value)
                    .map_err(serde::de::Error::custom),
            )?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_tests!(LightClientOptimisticUpdateDeneb<MainnetEthSpec>);
}
