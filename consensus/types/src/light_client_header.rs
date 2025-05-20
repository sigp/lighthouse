use crate::context_deserialize;
use crate::ChainSpec;
use crate::{light_client_update::*, BeaconBlockBody};
use crate::{BeaconBlockHeader, ExecutionPayloadHeader};
use crate::{ContextDeserialize, ForkName, ForkVersionDecode};
use crate::{
    EthSpec, ExecutionPayloadHeaderCapella, ExecutionPayloadHeaderDeneb,
    ExecutionPayloadHeaderElectra, ExecutionPayloadHeaderFulu, FixedVector, Hash256,
    SignedBlindedBeaconBlock,
};
use derivative::Derivative;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::DecodeError;
use ssz_derive::Encode;
use std::marker::PhantomData;
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
#[derive(
    Debug, Deserialize, Clone, Serialize, TreeHash, Encode, arbitrary::Arbitrary, PartialEq,
)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
#[arbitrary(bound = "E: EthSpec")]
pub struct LightClientHeader<E: EthSpec> {
    pub beacon: BeaconBlockHeader,
    #[superstruct(only(Capella, Deneb, Electra, Fulu))]
    pub execution: ExecutionPayloadHeader<E>,
    #[superstruct(only(Capella, Deneb, Electra, Fulu))]
    pub execution_branch: FixedVector<Hash256, ExecutionPayloadProofLen>,

    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[serde(skip)]
    #[arbitrary(default)]
    pub _phantom_data: PhantomData<E>,
}

impl<E: EthSpec> LightClientHeader<E> {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock<E>,
        chain_spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let header = match block
            .fork_name(chain_spec)
            .map_err(|_| Error::InconsistentFork)?
        {
            ForkName::Base => return Err(Error::AltairForkNotActive),
            ForkName::Altair | ForkName::Bellatrix => LightClientHeader::Altair(
                LightClientHeaderAltair::block_to_light_client_header(block)?,
            ),
            ForkName::Capella => LightClientHeader::Capella(
                LightClientHeaderCapella::block_to_light_client_header(block)?,
            ),
            ForkName::Deneb => LightClientHeader::Deneb(
                LightClientHeaderDeneb::block_to_light_client_header(block)?,
            ),
            ForkName::Electra => LightClientHeader::Electra(
                LightClientHeaderElectra::block_to_light_client_header(block)?,
            ),
            ForkName::Fulu => {
                LightClientHeader::Fulu(LightClientHeaderFulu::block_to_light_client_header(block)?)
            }
        };
        Ok(header)
    }

    pub fn ssz_max_var_len_for_fork(fork_name: ForkName) -> usize {
        if fork_name.capella_enabled() {
            ExecutionPayloadHeader::<E>::ssz_max_var_len_for_fork(fork_name)
        } else {
            0
        }
    }

    pub fn from_ssz_bytes_dynamic(bytes: &[u8], spec: &ChainSpec) -> Result<Self, DecodeError> {
        let mut builder = ssz::SszDecoderBuilder::new(bytes);
        builder.register_type::<BeaconBlockHeader>()?;
        let mut decoder = builder.build()?;
        let beacon: BeaconBlockHeader = decoder.decode_next()?;
        let fork_name = spec.fork_name_at_slot::<E>(beacon.slot);
        Self::from_ssz_bytes_by_fork(bytes, fork_name)
    }
}

impl<E: EthSpec> LightClientHeaderAltair<E> {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<Self, Error> {
        Ok(LightClientHeaderAltair {
            beacon: block.message().block_header(),
            _phantom_data: PhantomData,
        })
    }
}

impl<E: EthSpec> Default for LightClientHeaderAltair<E> {
    fn default() -> Self {
        Self {
            beacon: BeaconBlockHeader::empty(),
            _phantom_data: PhantomData,
        }
    }
}

impl<E: EthSpec> LightClientHeaderCapella<E> {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<Self, Error> {
        let payload = block
            .message()
            .execution_payload()?
            .execution_payload_capella()?;

        let header = ExecutionPayloadHeaderCapella::from(payload);
        let beacon_block_body = BeaconBlockBody::from(
            block
                .message()
                .body_capella()
                .map_err(|_| Error::BeaconBlockBodyError)?
                .to_owned(),
        );

        let execution_branch = beacon_block_body
            .to_ref()
            .block_body_merkle_proof(EXECUTION_PAYLOAD_INDEX)?;

        Ok(LightClientHeaderCapella {
            beacon: block.message().block_header(),
            execution: ExecutionPayloadHeader::Capella(header),
            execution_branch: FixedVector::new(execution_branch)?,
            _phantom_data: PhantomData,
        })
    }
}

impl<E: EthSpec> Default for LightClientHeaderCapella<E> {
    fn default() -> Self {
        Self {
            beacon: BeaconBlockHeader::empty(),
            execution: ExecutionPayloadHeader::Capella(ExecutionPayloadHeaderCapella::default()),
            execution_branch: FixedVector::default(),
            _phantom_data: PhantomData,
        }
    }
}

impl<E: EthSpec> LightClientHeaderDeneb<E> {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<Self, Error> {
        let header = block
            .message()
            .execution_payload()?
            .execution_payload_deneb()?
            .clone();

        let beacon_block_body = BeaconBlockBody::from(
            block
                .message()
                .body_deneb()
                .map_err(|_| Error::BeaconBlockBodyError)?
                .to_owned(),
        );

        let execution_branch = beacon_block_body
            .to_ref()
            .block_body_merkle_proof(EXECUTION_PAYLOAD_INDEX)?;

        Ok(LightClientHeaderDeneb {
            beacon: block.message().block_header(),
            execution: ExecutionPayloadHeader::Deneb(header),
            execution_branch: FixedVector::new(execution_branch)?,
            _phantom_data: PhantomData,
        })
    }
}

impl<E: EthSpec> Default for LightClientHeaderDeneb<E> {
    fn default() -> Self {
        Self {
            beacon: BeaconBlockHeader::empty(),
            execution: ExecutionPayloadHeader::Deneb(ExecutionPayloadHeaderDeneb::default()),
            execution_branch: FixedVector::default(),
            _phantom_data: PhantomData,
        }
    }
}

impl<E: EthSpec> LightClientHeaderElectra<E> {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<Self, Error> {
        let payload = block
            .message()
            .execution_payload()?
            .execution_payload_electra()?;

        let header = ExecutionPayloadHeaderElectra::from(payload);
        let beacon_block_body = BeaconBlockBody::from(
            block
                .message()
                .body_electra()
                .map_err(|_| Error::BeaconBlockBodyError)?
                .to_owned(),
        );

        let execution_branch = beacon_block_body
            .to_ref()
            .block_body_merkle_proof(EXECUTION_PAYLOAD_INDEX)?;

        Ok(LightClientHeaderElectra {
            beacon: block.message().block_header(),
            execution: ExecutionPayloadHeader::Electra(header),
            execution_branch: FixedVector::new(execution_branch)?,
            _phantom_data: PhantomData,
        })
    }
}

impl<E: EthSpec> Default for LightClientHeaderElectra<E> {
    fn default() -> Self {
        Self {
            beacon: BeaconBlockHeader::empty(),
            execution: ExecutionPayloadHeader::Electra(ExecutionPayloadHeaderElectra::default()),
            execution_branch: FixedVector::default(),
            _phantom_data: PhantomData,
        }
    }
}

impl<E: EthSpec> LightClientHeaderFulu<E> {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<Self, Error> {
        let payload = block
            .message()
            .execution_payload()?
            .execution_payload_fulu()?;

        let header = ExecutionPayloadHeaderFulu::from(payload);
        let beacon_block_body = BeaconBlockBody::from(
            block
                .message()
                .body_fulu()
                .map_err(|_| Error::BeaconBlockBodyError)?
                .to_owned(),
        );

        let execution_branch = beacon_block_body
            .to_ref()
            .block_body_merkle_proof(EXECUTION_PAYLOAD_INDEX)?;

        Ok(LightClientHeaderFulu {
            beacon: block.message().block_header(),
            execution: ExecutionPayloadHeader::Fulu(header),
            execution_branch: FixedVector::new(execution_branch)?,
            _phantom_data: PhantomData,
        })
    }
}

impl<E: EthSpec> Default for LightClientHeaderFulu<E> {
    fn default() -> Self {
        Self {
            beacon: BeaconBlockHeader::empty(),
            execution: ExecutionPayloadHeader::Fulu(ExecutionPayloadHeaderFulu::default()),
            execution_branch: FixedVector::default(),
            _phantom_data: PhantomData,
        }
    }
}

impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for LightClientHeader<E> {
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

impl<E: EthSpec> ForkVersionDecode for LightClientHeader<E> {
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, DecodeError> {
        let mut builder = ssz::SszDecoderBuilder::new(bytes);
        builder.register_type::<BeaconBlockHeader>()?;

        match fork_name {
            ForkName::Base => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for LightClientHeader: {fork_name}",
            ))),
            ForkName::Altair | ForkName::Bellatrix => {
                let mut decoder = builder.build()?;
                let beacon = decoder.decode_next()?;
                Ok(Self::Altair(LightClientHeaderAltair {
                    beacon,
                    _phantom_data: PhantomData,
                }))
            }
            ForkName::Capella => {
                builder.register_type::<ExecutionPayloadHeaderCapella<E>>()?;
                builder.register_type::<FixedVector<Hash256, ExecutionPayloadProofLen>>()?;
                let mut decoder = builder.build()?;
                let beacon = decoder.decode_next()?;
                let execution = ExecutionPayloadHeader::Capella(decoder.decode_next()?);
                let execution_branch = decoder.decode_next()?;
                Ok(Self::Capella(LightClientHeaderCapella {
                    beacon,
                    execution,
                    execution_branch,
                    _phantom_data: PhantomData,
                }))
            }
            ForkName::Deneb => {
                builder.register_type::<ExecutionPayloadHeaderDeneb<E>>()?;
                builder.register_type::<FixedVector<Hash256, ExecutionPayloadProofLen>>()?;
                let mut decoder = builder.build()?;
                let beacon = decoder.decode_next()?;
                let execution = ExecutionPayloadHeader::Deneb(decoder.decode_next()?);
                let execution_branch = decoder.decode_next()?;
                Ok(Self::Deneb(LightClientHeaderDeneb {
                    beacon,
                    execution,
                    execution_branch,
                    _phantom_data: PhantomData,
                }))
            }
            ForkName::Electra => {
                builder.register_type::<ExecutionPayloadHeaderElectra<E>>()?;
                builder.register_type::<FixedVector<Hash256, ExecutionPayloadProofLen>>()?;
                let mut decoder = builder.build()?;
                let beacon = decoder.decode_next()?;
                let execution = ExecutionPayloadHeader::Electra(decoder.decode_next()?);
                let execution_branch = decoder.decode_next()?;
                Ok(Self::Electra(LightClientHeaderElectra {
                    beacon,
                    execution,
                    execution_branch,
                    _phantom_data: PhantomData,
                }))
            }
            ForkName::Fulu => {
                builder.register_type::<ExecutionPayloadHeaderFulu<E>>()?;
                builder.register_type::<FixedVector<Hash256, ExecutionPayloadProofLen>>()?;
                let mut decoder = builder.build()?;
                let beacon = decoder.decode_next()?;
                let execution = ExecutionPayloadHeader::Fulu(decoder.decode_next()?);
                let execution_branch = decoder.decode_next()?;
                Ok(Self::Fulu(LightClientHeaderFulu {
                    beacon,
                    execution,
                    execution_branch,
                    _phantom_data: PhantomData,
                }))
            }
        }
    }
}
