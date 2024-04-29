use crate::ChainSpec;
use crate::ForkName;
use crate::ForkVersionDeserialize;
use crate::{light_client_update::*, BeaconBlockBody};
use crate::{
    test_utils::TestRandom, EthSpec, ExecutionPayloadHeaderCapella, ExecutionPayloadHeaderDeneb,
    FixedVector, Hash256, SignedBeaconBlock,
};
use crate::{BeaconBlockHeader, ExecutionPayloadHeader};
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use std::marker::PhantomData;
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

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
    Debug, Clone, Serialize, TreeHash, Encode, Deserialize, arbitrary::Arbitrary, PartialEq,
)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
#[arbitrary(bound = "E: EthSpec")]
pub struct LightClientHeader<E: EthSpec> {
    pub beacon: BeaconBlockHeader,

    #[superstruct(
        only(Capella),
        partial_getter(rename = "execution_payload_header_capella")
    )]
    pub execution: ExecutionPayloadHeaderCapella<E>,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_header_deneb"))]
    pub execution: ExecutionPayloadHeaderDeneb<E>,

    #[superstruct(only(Capella, Deneb))]
    pub execution_branch: FixedVector<Hash256, ExecutionPayloadProofLen>,

    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[serde(skip)]
    #[arbitrary(default)]
    pub _phantom_data: PhantomData<E>,
}

impl<E: EthSpec> LightClientHeader<E> {
    pub fn block_to_light_client_header(
        block: &SignedBeaconBlock<E>,
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
            ForkName::Deneb | ForkName::Electra => LightClientHeader::Deneb(
                LightClientHeaderDeneb::block_to_light_client_header(block)?,
            ),
        };
        Ok(header)
    }

    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        let header = match fork_name {
            ForkName::Altair | ForkName::Bellatrix => {
                LightClientHeader::Altair(LightClientHeaderAltair::from_ssz_bytes(bytes)?)
            }
            ForkName::Capella => {
                LightClientHeader::Capella(LightClientHeaderCapella::from_ssz_bytes(bytes)?)
            }
            ForkName::Deneb | ForkName::Electra => {
                LightClientHeader::Deneb(LightClientHeaderDeneb::from_ssz_bytes(bytes)?)
            }
            ForkName::Base => {
                return Err(ssz::DecodeError::BytesInvalid(format!(
                    "LightClientHeader decoding for {fork_name} not implemented"
                )))
            }
        };

        Ok(header)
    }

    /// Custom SSZ decoder that takes a `ForkName` as context.
    pub fn from_ssz_bytes_for_fork(
        bytes: &[u8],
        fork_name: ForkName,
    ) -> Result<Self, ssz::DecodeError> {
        Self::from_ssz_bytes(bytes, fork_name)
    }

    pub fn ssz_max_var_len_for_fork(fork_name: ForkName) -> usize {
        match fork_name {
            ForkName::Base | ForkName::Altair | ForkName::Bellatrix => 0,
            ForkName::Capella | ForkName::Deneb | ForkName::Electra => {
                ExecutionPayloadHeader::<E>::ssz_max_var_len_for_fork(fork_name)
            }
        }
    }
}

impl<E: EthSpec> LightClientHeaderAltair<E> {
    pub fn block_to_light_client_header(block: &SignedBeaconBlock<E>) -> Result<Self, Error> {
        Ok(LightClientHeaderAltair {
            beacon: block.message().block_header(),
            _phantom_data: PhantomData,
        })
    }
}

impl<E: EthSpec> LightClientHeaderCapella<E> {
    pub fn block_to_light_client_header(block: &SignedBeaconBlock<E>) -> Result<Self, Error> {
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

        let execution_branch =
            beacon_block_body.block_body_merkle_proof(EXECUTION_PAYLOAD_INDEX)?;

        return Ok(LightClientHeaderCapella {
            beacon: block.message().block_header(),
            execution: header,
            execution_branch: FixedVector::new(execution_branch)?,
            _phantom_data: PhantomData,
        });
    }
}

impl<E: EthSpec> LightClientHeaderDeneb<E> {
    pub fn block_to_light_client_header(block: &SignedBeaconBlock<E>) -> Result<Self, Error> {
        let payload = block
            .message()
            .execution_payload()?
            .execution_payload_deneb()?;

        let header = ExecutionPayloadHeaderDeneb::from(payload);
        let beacon_block_body = BeaconBlockBody::from(
            block
                .message()
                .body_deneb()
                .map_err(|_| Error::BeaconBlockBodyError)?
                .to_owned(),
        );

        let execution_branch =
            beacon_block_body.block_body_merkle_proof(EXECUTION_PAYLOAD_INDEX)?;

        Ok(LightClientHeaderDeneb {
            beacon: block.message().block_header(),
            execution: header,
            execution_branch: FixedVector::new(execution_branch)?,
            _phantom_data: PhantomData,
        })
    }
}

impl<E: EthSpec> ForkVersionDeserialize for LightClientHeader<E> {
    fn deserialize_by_fork<'de, D: serde::Deserializer<'de>>(
        value: serde_json::value::Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        match fork_name {
            ForkName::Altair | ForkName::Bellatrix => serde_json::from_value(value)
                .map(|light_client_header| Self::Altair(light_client_header))
                .map_err(serde::de::Error::custom),
            ForkName::Capella => serde_json::from_value(value)
                .map(|light_client_header| Self::Capella(light_client_header))
                .map_err(serde::de::Error::custom),
            ForkName::Deneb | ForkName::Electra => serde_json::from_value(value)
                .map(|light_client_header| Self::Deneb(light_client_header))
                .map_err(serde::de::Error::custom),
            ForkName::Base => Err(serde::de::Error::custom(format!(
                "LightClientHeader deserialization for {fork_name} not implemented"
            ))),
        }
    }
}
