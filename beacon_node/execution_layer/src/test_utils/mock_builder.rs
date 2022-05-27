use crate::test_utils::MockExecutionLayer;
use crate::{ExecutionLayer, PayloadAttributes, PublicKeyBytes};
use async_trait::async_trait;
use eth2::types::{BlockId, StateId, ValidatorId};
use eth2::BeaconNodeHttpClient;
use ethereum_consensus::builder::ValidatorRegistration;
use ethereum_consensus::primitives::BlsPublicKey;
use ethereum_consensus::state_transition::Context;
use ethers_core::k256::elliptic_curve::consts::U256;
use futures::AsyncReadExt;
use mev_build_rs::{
    verify_signed_builder_message, ApiServer, BidRequest, BuilderBid, Error,
    ExecutionPayload as ServerPayload, ExecutionPayloadHeader as ServerPayloadHeader,
    SignedBlindedBeaconBlock, SignedBuilderBid, SignedValidatorRegistration,
};
use parking_lot::RwLock;
use slot_clock::SlotClock;
use ssz::{Decode, Encode};
use ssz_rs::SimpleSerialize;
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tree_hash::TreeHash;
use types::{
    Address, BlindedPayload, ChainSpec, EthSpec, ExecPayload, ExecutionBlockHash, ExecutionPayload,
    Hash256, Slot, ValidatorRegistrationData,
};

pub type MockBuilderPool<E> = ApiServer<MockBuilder<E>>;

pub struct MockBuilder<E: EthSpec> {
    el: ExecutionLayer<E>,
    beacon_client: BeaconNodeHttpClient,
    spec: ChainSpec,
    context: Context,
    val_registration_cache: Arc<RwLock<HashMap<BlsPublicKey, SignedValidatorRegistration>>>,
}

impl<E: EthSpec> MockBuilder<E> {
    pub fn new(
        el: ExecutionLayer<E>,
        beacon_client: BeaconNodeHttpClient,
        spec: ChainSpec,
        context: Context,
    ) -> Self {
        Self {
            el,
            beacon_client,
            // Should keep spec and context consistent somehow
            spec,
            context,
            val_registration_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl<E: EthSpec> mev_build_rs::Builder for MockBuilder<E> {
    async fn register_validator(
        &self,
        registration: &mut SignedValidatorRegistration,
    ) -> Result<(), Error> {
        let pubkey = registration.message.public_key.clone();
        let message = &mut registration.message;
        verify_signed_builder_message(message, &registration.signature, &pubkey, &self.context)?;
        self.val_registration_cache.write().insert(
            registration.message.public_key.clone(),
            registration.clone(),
        );
        Ok(())
    }

    async fn fetch_best_bid(
        &self,
        bid_request: &mut BidRequest,
    ) -> Result<SignedBuilderBid, Error> {
        let slot = Slot::new(bid_request.slot);
        let signed_cached_data = self
            .val_registration_cache
            .read()
            .get(&bid_request.public_key)
            .ok_or(convert_err("missing registration"))?
            .clone();
        let cached_data = signed_cached_data.message;

        let head = self
            .beacon_client
            .get_beacon_blocks::<E>(BlockId::Head)
            .await
            .map_err(convert_err)?
            .ok_or(convert_err("missing head block"))?;

        let block = head.data.message_merge().map_err(convert_err)?;
        let head_block_root = block.tree_hash_root();
        let head_execution_hash = block.body.execution_payload.execution_payload.block_hash;
        if head_execution_hash != from_ssz_rs(&bid_request.parent_hash)? {
            return Err(Error::Custom("head mismatch".to_string()));
        }

        let prev_randao = block.body.execution_payload.execution_payload.prev_randao;
        let finalized_execution_hash = self
            .beacon_client
            .get_beacon_blocks::<E>(BlockId::Finalized)
            .await
            .map_err(convert_err)?
            .ok_or(convert_err("missing finalized block"))?
            .data
            .message_merge()
            .map_err(convert_err)?
            .body
            .execution_payload
            .execution_payload
            .block_hash;

        let val_index = self
            .beacon_client
            .get_beacon_states_validator_id(
                StateId::Head,
                &ValidatorId::PublicKey(from_ssz_rs(&cached_data.public_key)?),
            )
            .await
            .map_err(convert_err)?
            .ok_or(convert_err("missing validator from state"))?
            .data
            .index;
        let fee_recipient = from_ssz_rs(&cached_data.fee_recipient)?;
        let slots_since_genesis = slot.as_u64() - self.spec.genesis_slot.as_u64();

        let genesis_time = self
            .beacon_client
            .get_beacon_genesis()
            .await
            .map_err(convert_err)?
            .data
            .genesis_time;
        let timestamp = (slots_since_genesis * self.spec.seconds_per_slot) + genesis_time;
        let payload_attributes = PayloadAttributes {
            timestamp,
            prev_randao,
            suggested_fee_recipient: fee_recipient,
        };

        self.el
            .insert_proposer(slot, head_block_root, val_index, payload_attributes)
            .await;

        let payload = self
            .el
            .get_full_payload_caching::<BlindedPayload<E>>(
                head_execution_hash,
                timestamp,
                prev_randao,
                finalized_execution_hash,
                fee_recipient,
            )
            .await
            .map_err(convert_err)?
            .to_execution_payload_header();

        let mut header: ServerPayloadHeader = to_ssz_rs(&payload)?;
        header.gas_limit = cached_data.gas_limit;

        let signed_bid = SignedBuilderBid {
            message: BuilderBid {
                header,
                value: ssz_rs::U256::default(),
                public_key: cached_data.public_key,
            },
            // Garbage value, not verified by the CL
            signature: signed_cached_data.signature,
        };
        Ok(signed_bid)
    }

    async fn open_bid(
        &self,
        signed_block: &mut SignedBlindedBeaconBlock,
    ) -> Result<ServerPayload, Error> {
        let payload = self
            .el
            .get_payload_by_tx_root(&from_ssz_rs(
                &signed_block
                    .message
                    .body
                    .execution_payload_header
                    .transactions_root,
            )?)
            .ok_or(convert_err("missing payload for tx root"))?;

        to_ssz_rs(&payload)
    }
}

pub fn from_ssz_rs<T: SimpleSerialize, U: Decode>(ssz_rs_data: &T) -> Result<U, Error> {
    U::from_ssz_bytes(
        ssz_rs::serialize(ssz_rs_data)
            .map_err(convert_err)?
            .as_ref(),
    )
    .map_err(convert_err)
}

pub fn to_ssz_rs<T: Encode, U: SimpleSerialize>(ssz_data: &T) -> Result<U, Error> {
    ssz_rs::deserialize::<U>(&ssz_data.as_ssz_bytes()).map_err(convert_err)
}

fn convert_err<E: Debug>(e: E) -> Error {
    Error::Custom(format!("{e:?}"))
}
