use crate::test_utils::DEFAULT_JWT_SECRET;
use crate::{Config, ExecutionLayer, PayloadAttributes, PayloadAttributesV1};
use async_trait::async_trait;
use eth2::types::{BlockId, StateId, ValidatorId};
use eth2::{BeaconNodeHttpClient, Timeouts};
use ethereum_consensus::crypto::{SecretKey, Signature};
use ethereum_consensus::primitives::BlsPublicKey;
pub use ethereum_consensus::state_transition::Context;
use fork_choice::ForkchoiceUpdateParameters;
use mev_build_rs::{
    sign_builder_message, verify_signed_builder_message, BidRequest, BlindedBlockProviderError,
    BlindedBlockProviderServer, BuilderBid, ExecutionPayload as ServerPayload,
    ExecutionPayloadHeader as ServerPayloadHeader, SignedBlindedBeaconBlock, SignedBuilderBid,
    SignedValidatorRegistration,
};
use parking_lot::RwLock;
use sensitive_url::SensitiveUrl;
use ssz::{Decode, Encode};
use ssz_rs::{Merkleized, SimpleSerialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use task_executor::TaskExecutor;
use tempfile::NamedTempFile;
use tree_hash::TreeHash;
use types::{
    Address, BeaconState, BlindedPayload, ChainSpec, EthSpec, ExecPayload, ForkName, Hash256, Slot,
    Uint256,
};

#[derive(Clone)]
pub enum Operation {
    FeeRecipient(Address),
    GasLimit(usize),
    Value(Uint256),
    ParentHash(Hash256),
    PrevRandao(Hash256),
    BlockNumber(usize),
    Timestamp(usize),
}

impl Operation {
    fn apply(self, bid: &mut BuilderBid) -> Result<(), BlindedBlockProviderError> {
        match self {
            Operation::FeeRecipient(fee_recipient) => {
                bid.header.fee_recipient = to_ssz_rs(&fee_recipient)?
            }
            Operation::GasLimit(gas_limit) => bid.header.gas_limit = gas_limit as u64,
            Operation::Value(value) => bid.value = to_ssz_rs(&value)?,
            Operation::ParentHash(parent_hash) => bid.header.parent_hash = to_ssz_rs(&parent_hash)?,
            Operation::PrevRandao(prev_randao) => bid.header.prev_randao = to_ssz_rs(&prev_randao)?,
            Operation::BlockNumber(block_number) => bid.header.block_number = block_number as u64,
            Operation::Timestamp(timestamp) => bid.header.timestamp = timestamp as u64,
        }
        Ok(())
    }
}

pub struct TestingBuilder<E: EthSpec> {
    server: BlindedBlockProviderServer<MockBuilder<E>>,
    pub builder: MockBuilder<E>,
}

impl<E: EthSpec> TestingBuilder<E> {
    pub fn new(
        mock_el_url: SensitiveUrl,
        builder_url: SensitiveUrl,
        beacon_url: SensitiveUrl,
        spec: ChainSpec,
        executor: TaskExecutor,
    ) -> Self {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().into();
        std::fs::write(&path, hex::encode(DEFAULT_JWT_SECRET)).unwrap();

        // This EL should not talk to a builder
        let config = Config {
            execution_endpoints: vec![mock_el_url],
            secret_files: vec![path],
            suggested_fee_recipient: None,
            ..Default::default()
        };

        let el =
            ExecutionLayer::from_config(config, executor.clone(), executor.log().clone()).unwrap();

        // This should probably be done for all fields, we only update ones we are testing with so far.
        let mut context = Context::for_mainnet();
        context.terminal_total_difficulty = to_ssz_rs(&spec.terminal_total_difficulty).unwrap();
        context.terminal_block_hash = to_ssz_rs(&spec.terminal_block_hash).unwrap();
        context.terminal_block_hash_activation_epoch =
            to_ssz_rs(&spec.terminal_block_hash_activation_epoch).unwrap();

        let builder = MockBuilder::new(
            el,
            BeaconNodeHttpClient::new(beacon_url, Timeouts::set_all(Duration::from_secs(1))),
            spec,
            context,
        );
        let port = builder_url.full.port().unwrap();
        let host: Ipv4Addr = builder_url
            .full
            .host_str()
            .unwrap()
            .to_string()
            .parse()
            .unwrap();
        let server = BlindedBlockProviderServer::new(host, port, builder.clone());
        Self { server, builder }
    }

    pub async fn run(&self) {
        self.server.run().await
    }
}

#[derive(Clone)]
pub struct MockBuilder<E: EthSpec> {
    el: ExecutionLayer<E>,
    beacon_client: BeaconNodeHttpClient,
    spec: ChainSpec,
    context: Arc<Context>,
    val_registration_cache: Arc<RwLock<HashMap<BlsPublicKey, SignedValidatorRegistration>>>,
    builder_sk: SecretKey,
    operations: Arc<RwLock<Vec<Operation>>>,
    invalidate_signatures: Arc<RwLock<bool>>,
}

impl<E: EthSpec> MockBuilder<E> {
    pub fn new(
        el: ExecutionLayer<E>,
        beacon_client: BeaconNodeHttpClient,
        spec: ChainSpec,
        context: Context,
    ) -> Self {
        let sk = SecretKey::random(&mut rand::thread_rng()).unwrap();
        Self {
            el,
            beacon_client,
            // Should keep spec and context consistent somehow
            spec,
            context: Arc::new(context),
            val_registration_cache: Arc::new(RwLock::new(HashMap::new())),
            builder_sk: sk,
            operations: Arc::new(RwLock::new(vec![])),
            invalidate_signatures: Arc::new(RwLock::new(false)),
        }
    }

    pub fn add_operation(&self, op: Operation) {
        // Insert operations at the front of the vec to make sure `apply_operations` applies them
        // in the order they are added.
        self.operations.write().insert(0, op);
    }

    pub fn invalid_signatures(&self) {
        *self.invalidate_signatures.write() = true;
    }

    pub fn valid_signatures(&mut self) {
        *self.invalidate_signatures.write() = false;
    }

    fn apply_operations(&self, bid: &mut BuilderBid) -> Result<(), BlindedBlockProviderError> {
        let mut guard = self.operations.write();
        while let Some(op) = guard.pop() {
            op.apply(bid)?;
        }
        Ok(())
    }
}

#[async_trait]
impl<E: EthSpec> mev_build_rs::BlindedBlockProvider for MockBuilder<E> {
    async fn register_validators(
        &self,
        registrations: &mut [SignedValidatorRegistration],
    ) -> Result<(), BlindedBlockProviderError> {
        for registration in registrations {
            let pubkey = registration.message.public_key.clone();
            let message = &mut registration.message;
            verify_signed_builder_message(
                message,
                &registration.signature,
                &pubkey,
                &self.context,
            )?;
            self.val_registration_cache.write().insert(
                registration.message.public_key.clone(),
                registration.clone(),
            );
        }

        Ok(())
    }

    async fn fetch_best_bid(
        &self,
        bid_request: &BidRequest,
    ) -> Result<SignedBuilderBid, BlindedBlockProviderError> {
        let slot = Slot::new(bid_request.slot);
        let signed_cached_data = self
            .val_registration_cache
            .read()
            .get(&bid_request.public_key)
            .ok_or_else(|| convert_err("missing registration"))?
            .clone();
        let cached_data = signed_cached_data.message;

        let head = self
            .beacon_client
            .get_beacon_blocks::<E>(BlockId::Head)
            .await
            .map_err(convert_err)?
            .ok_or_else(|| convert_err("missing head block"))?;

        let block = head.data.message_merge().map_err(convert_err)?;
        let head_block_root = block.tree_hash_root();
        let head_execution_hash = block.body.execution_payload.execution_payload.block_hash;
        if head_execution_hash != from_ssz_rs(&bid_request.parent_hash)? {
            return Err(BlindedBlockProviderError::Custom(format!(
                "head mismatch: {} {}",
                head_execution_hash, bid_request.parent_hash
            )));
        }

        let finalized_execution_hash = self
            .beacon_client
            .get_beacon_blocks::<E>(BlockId::Finalized)
            .await
            .map_err(convert_err)?
            .ok_or_else(|| convert_err("missing finalized block"))?
            .data
            .message_merge()
            .map_err(convert_err)?
            .body
            .execution_payload
            .execution_payload
            .block_hash;

        let justified_execution_hash = self
            .beacon_client
            .get_beacon_blocks::<E>(BlockId::Justified)
            .await
            .map_err(convert_err)?
            .ok_or_else(|| convert_err("missing finalized block"))?
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
            .ok_or_else(|| convert_err("missing validator from state"))?
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

        let head_state: BeaconState<E> = self
            .beacon_client
            .get_debug_beacon_states(StateId::Head)
            .await
            .map_err(convert_err)?
            .ok_or_else(|| BlindedBlockProviderError::Custom("missing head state".to_string()))?
            .data;
        let prev_randao = head_state
            .get_randao_mix(head_state.current_epoch())
            .map_err(convert_err)?;

        // FIXME: think about proper fork here
        let payload_attributes = PayloadAttributes::V1(PayloadAttributesV1 {
            timestamp,
            prev_randao: *prev_randao,
            suggested_fee_recipient: fee_recipient,
        });

        self.el
            .insert_proposer(slot, head_block_root, val_index, payload_attributes)
            .await;

        let forkchoice_update_params = ForkchoiceUpdateParameters {
            head_root: Hash256::zero(),
            head_hash: None,
            justified_hash: Some(justified_execution_hash),
            finalized_hash: Some(finalized_execution_hash),
        };

        let payload = self
            .el
            .get_full_payload_caching::<BlindedPayload<E>>(
                head_execution_hash,
                timestamp,
                *prev_randao,
                fee_recipient,
                forkchoice_update_params,
                // TODO: do we need to write a test for this if this is Capella fork?
                ForkName::Merge,
                #[cfg(feature = "withdrawals")]
                None,
            )
            .await
            .map_err(convert_err)?
            .to_payload()
            .to_execution_payload_header();

        let json_payload = serde_json::to_string(&payload).map_err(convert_err)?;
        let mut header: ServerPayloadHeader =
            serde_json::from_str(json_payload.as_str()).map_err(convert_err)?;

        header.gas_limit = cached_data.gas_limit;

        let mut message = BuilderBid {
            header,
            value: ssz_rs::U256::default(),
            public_key: self.builder_sk.public_key(),
        };

        self.apply_operations(&mut message)?;

        let mut signature =
            sign_builder_message(&mut message, &self.builder_sk, self.context.as_ref())?;

        if *self.invalidate_signatures.read() {
            signature = Signature::default();
        }

        let signed_bid = SignedBuilderBid { message, signature };
        Ok(signed_bid)
    }

    async fn open_bid(
        &self,
        signed_block: &mut SignedBlindedBeaconBlock,
    ) -> Result<ServerPayload, BlindedBlockProviderError> {
        let payload = self
            .el
            .get_payload_by_root(&from_ssz_rs(
                &signed_block
                    .message
                    .body
                    .execution_payload_header
                    .hash_tree_root()
                    .map_err(convert_err)?,
            )?)
            .ok_or_else(|| convert_err("missing payload for tx root"))?;

        let json_payload = serde_json::to_string(&payload).map_err(convert_err)?;
        serde_json::from_str(json_payload.as_str()).map_err(convert_err)
    }
}

pub fn from_ssz_rs<T: SimpleSerialize, U: Decode>(
    ssz_rs_data: &T,
) -> Result<U, BlindedBlockProviderError> {
    U::from_ssz_bytes(
        ssz_rs::serialize(ssz_rs_data)
            .map_err(convert_err)?
            .as_ref(),
    )
    .map_err(convert_err)
}

pub fn to_ssz_rs<T: Encode, U: SimpleSerialize>(
    ssz_data: &T,
) -> Result<U, BlindedBlockProviderError> {
    ssz_rs::deserialize::<U>(&ssz_data.as_ssz_bytes()).map_err(convert_err)
}

fn convert_err<E: Debug>(e: E) -> BlindedBlockProviderError {
    BlindedBlockProviderError::Custom(format!("{e:?}"))
}
