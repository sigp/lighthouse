use crate::BeaconBlockHeader;
use crate::ForkName;
use crate::ForkVersionDeserialize;
use crate::{light_client_update::*, BeaconBlockBody};
use crate::{
    test_utils::TestRandom, EthSpec, ExecutionPayloadHeaderCapella, ExecutionPayloadHeaderDeneb,
    FixedVector, Hash256, SignedBeaconBlock,
};
use serde::{Deserialize, Serialize};
use serde_json;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::marker::PhantomData;
use superstruct::superstruct;
use test_random_derive::TestRandom;

#[superstruct(
    variants(Altair, Capella, Deneb),
    variant_attributes(
        derive(
            Debug,
            Clone,
            PartialEq,
            Serialize,
            Deserialize,
            Decode,
            Encode,
            TestRandom,
            arbitrary::Arbitrary,
        ),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec"),
    )
)]
#[derive(Debug, Clone, Serialize, Deserialize, arbitrary::Arbitrary, PartialEq)]
#[serde(untagged)]
// #[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
#[arbitrary(bound = "E: EthSpec")]
pub struct LightClientHeader<E: EthSpec> {
    pub beacon: BeaconBlockHeader,
    #[superstruct(only(Capella, Deneb))]
    pub execution_branch: FixedVector<Hash256, ExecutionPayloadProofLen>,
    #[superstruct(
        only(Capella),
        partial_getter(rename = "execution_payload_header_capella")
    )]
    pub execution: ExecutionPayloadHeaderCapella<E>,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_header_deneb"))]
    pub execution: ExecutionPayloadHeaderDeneb<E>,

    #[serde(skip)]
    #[ssz(skip_serializing, skip_deserializing)]
    pub phantom_data: PhantomData<E>,
}

impl<E: EthSpec> LightClientHeader<E> {
    pub fn block_to_light_client_header(
        block: &SignedBeaconBlock<E>,
        fork_name: ForkName,
    ) -> Result<Self, Error> {
        let header = match fork_name {
            ForkName::Base => return Err(Error::AltairForkNotActive),
            ForkName::Altair | ForkName::Merge => LightClientHeader::Altair(
                LightClientHeaderAltair::block_to_light_client_header(block)?,
            ),
            ForkName::Capella => LightClientHeader::Capella(
                LightClientHeaderCapella::block_to_light_client_header(block)?,
            ),
            ForkName::Deneb => LightClientHeader::Deneb(
                LightClientHeaderDeneb::block_to_light_client_header(block)?,
            ),
        };
        Ok(header)
    }

    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        let header = match fork_name {
            ForkName::Altair | ForkName::Merge => {
                let header = LightClientHeaderAltair::from_ssz_bytes(bytes)?;
                LightClientHeader::Altair(header)
            }
            ForkName::Capella => {
                let header = LightClientHeaderCapella::from_ssz_bytes(bytes)?;
                LightClientHeader::Capella(header)
            }
            ForkName::Deneb => {
                let header = LightClientHeaderDeneb::from_ssz_bytes(bytes)?;
                LightClientHeader::Deneb(header)
            }
            ForkName::Base => {
                return Err(ssz::DecodeError::BytesInvalid(format!(
                    "LightClientHeader decoding for {fork_name} not implemented"
                )))
            }
        };

        Ok(header)
    }
}

impl<E: EthSpec> Encode for LightClientHeader<E> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        match self {
            LightClientHeader::Altair(header) => header.ssz_bytes_len(),
            LightClientHeader::Capella(header) => header.ssz_bytes_len(),
            LightClientHeader::Deneb(header) => header.ssz_bytes_len(),
        }
    }

    fn ssz_fixed_len() -> usize {
        ssz::BYTES_PER_LENGTH_OFFSET
    }

    fn as_ssz_bytes(&self) -> Vec<u8> {
        match self {
            LightClientHeader::Altair(header) => header.as_ssz_bytes(),
            LightClientHeader::Capella(header) => header.as_ssz_bytes(),
            LightClientHeader::Deneb(header) => header.as_ssz_bytes(),
        }
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match self {
            LightClientHeader::Altair(header) => header.ssz_append(buf),
            LightClientHeader::Capella(header) => header.ssz_append(buf),
            LightClientHeader::Deneb(header) => header.ssz_append(buf),
        }
    }
}

impl<E: EthSpec> LightClientHeaderAltair<E> {
    pub fn block_to_light_client_header(block: &SignedBeaconBlock<E>) -> Result<Self, Error> {
        Ok(LightClientHeaderAltair {
            beacon: block.message().block_header(),
            phantom_data: PhantomData,
        })
    }
}

impl<E: EthSpec> LightClientHeaderCapella<E> {
    pub fn block_to_light_client_header(block: &SignedBeaconBlock<E>) -> Result<Self, Error> {
        let payload = block
            .message()
            .execution_payload()?
            .execution_payload_capella()?
            .to_owned();

        let header = ExecutionPayloadHeaderCapella::from(&payload);
        let mut beacon_block_body = BeaconBlockBody::from(
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
            phantom_data: PhantomData,
        });
    }
}

impl<E: EthSpec> LightClientHeaderDeneb<E> {
    pub fn block_to_light_client_header(block: &SignedBeaconBlock<E>) -> Result<Self, Error> {
        let payload = block
            .message()
            .execution_payload()?
            .execution_payload_deneb()?
            .to_owned();

        let header = ExecutionPayloadHeaderDeneb::from(&payload);
        let mut beacon_block_body = BeaconBlockBody::from(
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
            phantom_data: PhantomData,
        })
    }
}

impl<T: EthSpec> ForkVersionDeserialize for LightClientHeader<T> {
    fn deserialize_by_fork<'de, D: serde::Deserializer<'de>>(
        value: serde_json::value::Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        match fork_name {
            ForkName::Altair | ForkName::Merge => serde_json::from_value(value)
                .map(|light_client_header| Self::Altair(light_client_header))
                .map_err(serde::de::Error::custom),
            ForkName::Capella => serde_json::from_value(value)
                .map(|light_client_header| Self::Capella(light_client_header))
                .map_err(serde::de::Error::custom),
            ForkName::Deneb => serde_json::from_value(value)
                .map(|light_client_header| Self::Deneb(light_client_header))
                .map_err(serde::de::Error::custom),
            ForkName::Base => Err(serde::de::Error::custom(format!(
                "LightClientHeader deserialization for {fork_name} not implemented"
            ))),
        }
    }
}
