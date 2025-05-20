use super::{EthSpec, FixedVector, Hash256, LightClientHeader, Slot, SyncAggregate};
use crate::context_deserialize;
use crate::ChainSpec;
use crate::{
    light_client_update::*, ContextDeserialize, ForkName, ForkVersionDecode,
    SignedBlindedBeaconBlock,
};
use derivative::Derivative;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::{DecodeError, Encode};
use ssz_derive::Encode;
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

#[superstruct(
    variants(Altair, Capella, Deneb, Electra, Fulu),
    variant_attributes(
        derive(
            Debug,
            Clone,
            PartialEq,
            Serialize,
            Deserialize,
            Derivative,
            Encode,
            arbitrary::Arbitrary,
            TreeHash,
        ),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec"),
        context_deserialize(ForkName),
    )
)]
#[derive(Debug, Clone, Serialize, Encode, TreeHash, arbitrary::Arbitrary, PartialEq)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
#[arbitrary(bound = "E: EthSpec")]
pub struct LightClientFinalityUpdate<E: EthSpec> {
    /// The last `BeaconBlockHeader` from the last attested block by the sync committee.
    pub attested_header: LightClientHeader<E>,
    /// The last `BeaconBlockHeader` from the last attested finalized block (end of epoch).
    pub finalized_header: LightClientHeader<E>,
    /// Merkle proof attesting finalized header.
    #[superstruct(
        only(Altair, Capella, Deneb),
        partial_getter(rename = "finality_branch_altair")
    )]
    pub finality_branch: FixedVector<Hash256, FinalizedRootProofLen>,
    #[superstruct(
        only(Electra, Fulu),
        partial_getter(rename = "finality_branch_electra")
    )]
    pub finality_branch: FixedVector<Hash256, FinalizedRootProofLenElectra>,
    /// current sync aggregate
    pub sync_aggregate: SyncAggregate<E>,
    /// Slot of the sync aggregated signature
    pub signature_slot: Slot,
}

impl<E: EthSpec> LightClientFinalityUpdate<E> {
    pub fn new(
        attested_block: &SignedBlindedBeaconBlock<E>,
        finalized_block: &SignedBlindedBeaconBlock<E>,
        finality_branch: Vec<Hash256>,
        sync_aggregate: SyncAggregate<E>,
        signature_slot: Slot,
        chain_spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let attested_header =
            LightClientHeader::block_to_light_client_header(attested_block, chain_spec)?;
        let finalized_header =
            LightClientHeader::block_to_light_client_header(finalized_block, chain_spec)?;
        let finality_update = match attested_block
            .fork_name(chain_spec)
            .map_err(|_| Error::InconsistentFork)?
        {
            ForkName::Altair | ForkName::Bellatrix => {
                Self::Altair(LightClientFinalityUpdateAltair {
                    attested_header,
                    finalized_header,
                    finality_branch: finality_branch.into(),
                    sync_aggregate,
                    signature_slot,
                })
            }
            ForkName::Capella => Self::Capella(LightClientFinalityUpdateCapella {
                attested_header,
                finalized_header,
                finality_branch: finality_branch.into(),
                sync_aggregate,
                signature_slot,
            }),
            ForkName::Deneb => Self::Deneb(LightClientFinalityUpdateDeneb {
                attested_header,
                finalized_header,
                finality_branch: finality_branch.into(),
                sync_aggregate,
                signature_slot,
            }),
            ForkName::Electra => Self::Electra(LightClientFinalityUpdateElectra {
                attested_header,
                finalized_header,
                finality_branch: finality_branch.into(),
                sync_aggregate,
                signature_slot,
            }),
            ForkName::Fulu => Self::Fulu(LightClientFinalityUpdateFulu {
                attested_header,
                finalized_header,
                finality_branch: finality_branch.into(),
                sync_aggregate,
                signature_slot,
            }),

            ForkName::Base => return Err(Error::AltairForkNotActive),
        };

        Ok(finality_update)
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
            Self::Fulu(_) => func(ForkName::Fulu),
        }
    }

    pub fn get_attested_header_slot<'a>(&'a self) -> Slot {
        map_light_client_finality_update_ref!(&'a _, self.to_ref(), |inner, cons| {
            cons(inner);
            inner.attested_header.beacon().slot
        })
    }

    #[allow(clippy::arithmetic_side_effects)]
    pub fn ssz_max_len_for_fork(fork_name: ForkName) -> usize {
        let fixed_size = match fork_name {
            ForkName::Base => 0,
            ForkName::Altair | ForkName::Bellatrix => {
                <LightClientFinalityUpdateAltair<E> as Encode>::ssz_fixed_len()
            }
            ForkName::Capella => <LightClientFinalityUpdateCapella<E> as Encode>::ssz_fixed_len(),
            ForkName::Deneb => <LightClientFinalityUpdateDeneb<E> as Encode>::ssz_fixed_len(),
            ForkName::Electra => <LightClientFinalityUpdateElectra<E> as Encode>::ssz_fixed_len(),
            ForkName::Fulu => <LightClientFinalityUpdateFulu<E> as Encode>::ssz_fixed_len(),
        };
        // `2 *` because there are two headers in the update
        fixed_size + 2 * LightClientHeader::<E>::ssz_max_var_len_for_fork(fork_name)
    }

    // Implements spec prioritization rules:
    // > Full nodes SHOULD provide the LightClientFinalityUpdate with the highest attested_header.beacon.slot (if multiple, highest signature_slot)
    //
    // ref: https://github.com/ethereum/consensus-specs/blob/113c58f9bf9c08867f6f5f633c4d98e0364d612a/specs/altair/light-client/full-node.md#create_light_client_finality_update
    pub fn is_latest(&self, attested_slot: Slot, signature_slot: Slot) -> bool {
        let prev_slot = self.get_attested_header_slot();
        if attested_slot > prev_slot {
            true
        } else {
            attested_slot == prev_slot && signature_slot > *self.signature_slot()
        }
    }
}

impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for LightClientFinalityUpdate<E> {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let convert_err = |e| {
            serde::de::Error::custom(format!(
                "LightClientFinalityUpdate failed to deserialize: {:?}",
                e
            ))
        };
        Ok(match context {
            ForkName::Base => {
                return Err(serde::de::Error::custom(format!(
                    "LightClientFinalityUpdate failed to deserialize: unsupported fork '{}'",
                    context
                )))
            }
            ForkName::Altair | ForkName::Bellatrix => {
                Self::Altair(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Capella => {
                Self::Capella(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Deneb => {
                Self::Deneb(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Electra => {
                Self::Electra(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Fulu => {
                Self::Fulu(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
        })
    }
}

impl<E: EthSpec> ForkVersionDecode for LightClientFinalityUpdate<E> {
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, DecodeError> {
        let mut builder = ssz::SszDecoderBuilder::new(bytes);
        // attested header
        builder.register_anonymous_variable_length_item()?;
        // finalized header
        builder.register_anonymous_variable_length_item()?;
        if fork_name.electra_enabled() {
            builder.register_type::<FixedVector<Hash256, FinalizedRootProofLenElectra>>()?;
        } else {
            builder.register_type::<FixedVector<Hash256, FinalizedRootProofLen>>()?;
        }
        builder.register_type::<SyncAggregate<E>>()?;
        builder.register_type::<Slot>()?;

        let mut decoder = builder.build()?;
        let attested_header = decoder.decode_next_with(|bytes| {
            LightClientHeader::from_ssz_bytes_by_fork(bytes, fork_name)
        })?;
        let finalized_header = decoder.decode_next_with(|bytes| {
            LightClientHeader::from_ssz_bytes_by_fork(bytes, fork_name)
        })?;
        match fork_name {
            ForkName::Base => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for LightClientFinalityUpdate: {fork_name}",
            ))),
            ForkName::Altair | ForkName::Bellatrix => {
                let finality_branch = decoder.decode_next()?;
                let sync_aggregate = decoder.decode_next()?;
                let signature_slot = decoder.decode_next()?;

                Ok(Self::Altair(LightClientFinalityUpdateAltair {
                    attested_header,
                    finalized_header,
                    finality_branch,
                    sync_aggregate,
                    signature_slot,
                }))
            }
            ForkName::Capella => {
                let finality_branch = decoder.decode_next()?;
                let sync_aggregate = decoder.decode_next()?;
                let signature_slot = decoder.decode_next()?;

                Ok(Self::Capella(LightClientFinalityUpdateCapella {
                    attested_header,
                    finalized_header,
                    finality_branch,
                    sync_aggregate,
                    signature_slot,
                }))
            }
            ForkName::Deneb => {
                let finality_branch = decoder.decode_next()?;
                let sync_aggregate = decoder.decode_next()?;
                let signature_slot = decoder.decode_next()?;

                Ok(Self::Deneb(LightClientFinalityUpdateDeneb {
                    attested_header,
                    finalized_header,
                    finality_branch,
                    sync_aggregate,
                    signature_slot,
                }))
            }
            ForkName::Electra => {
                let finality_branch = decoder.decode_next()?;
                let sync_aggregate = decoder.decode_next()?;
                let signature_slot = decoder.decode_next()?;

                Ok(Self::Electra(LightClientFinalityUpdateElectra {
                    attested_header,
                    finalized_header,
                    finality_branch,
                    sync_aggregate,
                    signature_slot,
                }))
            }
            ForkName::Fulu => {
                let finality_branch = decoder.decode_next()?;
                let sync_aggregate = decoder.decode_next()?;
                let signature_slot = decoder.decode_next()?;

                Ok(Self::Fulu(LightClientFinalityUpdateFulu {
                    attested_header,
                    finalized_header,
                    finality_branch,
                    sync_aggregate,
                    signature_slot,
                }))
            }
        }
    }
}
