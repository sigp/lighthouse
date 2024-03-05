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
use ssz_derive::{Decode, Encode};
use std::marker::PhantomData;
use superstruct::superstruct;
use test_random_derive::TestRandom;

#[superstruct(
    variants(Altair, Capella, Deneb),
    variant_attributes(
        derive(
            Default,
            Debug,
            Clone,
            PartialEq,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TestRandom,
            arbitrary::Arbitrary,
        ),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec"),
    )
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, arbitrary::Arbitrary, PartialEq)]
#[serde(untagged)]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
#[ssz(enum_behaviour = "union")]
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

    #[ssz(skip_serializing, skip_deserializing)]
    pub phantom_data: PhantomData<E>,
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
            ForkName::Base  => Err(serde::de::Error::custom(format!(
                "LightClientHeader deserialization for {fork_name} not implemented"
            ))),
        }
    }
}
