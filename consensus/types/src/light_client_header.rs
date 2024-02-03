use crate::beacon_block_body::NUM_BEACON_BLOCK_BODY_HASH_TREE_ROOT_LEAVES;
use crate::BeaconBlockHeader;
use crate::{light_client_update::*, BeaconBlockBody};
use crate::{
    test_utils::TestRandom, EthSpec, ExecutionPayloadHeaderCapella, ExecutionPayloadHeaderDeneb,
    FixedVector, Hash256, SignedBeaconBlock,
};
use merkle_proof::verify_merkle_proof;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::marker::PhantomData;
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;

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

    #[allow(dead_code)]
    fn get_lc_execution_root(&self) -> Option<Hash256> {
        None
    }

    #[allow(dead_code)]
    fn is_valid_light_client_header(&self) -> Result<bool, Error> {
        Ok(true)
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

    #[allow(dead_code)]
    fn get_lc_execution_root(&self) -> Option<Hash256> {
        Some(self.execution.tree_hash_root())
    }

    #[allow(dead_code)]
    fn is_valid_light_client_header(&self) -> Result<bool, Error> {
        let Some(execution_root) = self.get_lc_execution_root() else {
            return Ok(false);
        };

        let Some(field_index) =
            EXECUTION_PAYLOAD_INDEX.checked_sub(NUM_BEACON_BLOCK_BODY_HASH_TREE_ROOT_LEAVES)
        else {
            return Ok(false);
        };

        Ok(verify_merkle_proof(
            execution_root,
            &self.execution_branch,
            EXECUTION_PAYLOAD_PROOF_LEN,
            field_index,
            self.beacon.body_root,
        ))
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

    #[allow(dead_code)]
    fn get_lc_execution_root(&self) -> Option<Hash256> {
        Some(self.execution.tree_hash_root())
    }

    #[allow(dead_code)]
    fn is_valid_light_client_header(&self) -> Result<bool, Error> {
        let Some(execution_root) = self.get_lc_execution_root() else {
            return Ok(false);
        };

        let Some(field_index) =
            EXECUTION_PAYLOAD_INDEX.checked_sub(NUM_BEACON_BLOCK_BODY_HASH_TREE_ROOT_LEAVES)
        else {
            return Ok(false);
        };

        Ok(verify_merkle_proof(
            execution_root,
            &self.execution_branch,
            EXECUTION_PAYLOAD_PROOF_LEN,
            field_index,
            self.beacon.body_root,
        ))
    }
}
