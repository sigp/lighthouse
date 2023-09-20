use crate::test_utils::{DEFAULT_BUILDER_PAYLOAD_VALUE_WEI, DEFAULT_JWT_SECRET};
use crate::{Config, ExecutionLayer, PayloadAttributes};
use async_trait::async_trait;
use eth2::types::{BlockId, StateId, ValidatorId};
use eth2::{BeaconNodeHttpClient, Timeouts};
pub use ethereum_consensus::state_transition::Context;
use ethereum_consensus::{
    crypto::{SecretKey, Signature},
    primitives::{BlsPublicKey, BlsSignature, ExecutionAddress, Hash32, Root, U256},
    state_transition::Error,
};
use fork_choice::ForkchoiceUpdateParameters;
use mev_rs::{
    blinded_block_provider::Server as BlindedBlockProviderServer,
    signing::{sign_builder_message, verify_signed_builder_message},
    types::{
        bellatrix::{
            BuilderBid as BuilderBidBellatrix, SignedBuilderBid as SignedBuilderBidBellatrix,
        },
        capella::{BuilderBid as BuilderBidCapella, SignedBuilderBid as SignedBuilderBidCapella},
        BidRequest, BuilderBid, ExecutionPayload as ServerPayload, SignedBlindedBeaconBlock,
        SignedBuilderBid, SignedValidatorRegistration,
    },
    Error as MevError,
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

pub type MockBuilderServer = axum::Server<
    hyper::server::conn::AddrIncoming,
    axum::routing::IntoMakeService<axum::routing::Router>,
>;

#[derive(Clone)]
pub enum Operation {
    FeeRecipient(Address),
    GasLimit(usize),
    Value(Uint256),
    ParentHash(Hash256),
    PrevRandao(Hash256),
    BlockNumber(usize),
    Timestamp(usize),
    WithdrawalsRoot(Hash256),
}

impl Operation {
    fn apply<B: BidStuff>(self, bid: &mut B) -> Result<(), MevError> {
        match self {
            Operation::FeeRecipient(fee_recipient) => {
                *bid.fee_recipient_mut() = to_ssz_rs(&fee_recipient)?
            }
            Operation::GasLimit(gas_limit) => *bid.gas_limit_mut() = gas_limit as u64,
            Operation::Value(value) => *bid.value_mut() = to_ssz_rs(&value)?,
            Operation::ParentHash(parent_hash) => *bid.parent_hash_mut() = to_ssz_rs(&parent_hash)?,
            Operation::PrevRandao(prev_randao) => *bid.prev_randao_mut() = to_ssz_rs(&prev_randao)?,
            Operation::BlockNumber(block_number) => *bid.block_number_mut() = block_number as u64,
            Operation::Timestamp(timestamp) => *bid.timestamp_mut() = timestamp as u64,
            Operation::WithdrawalsRoot(root) => *bid.withdrawals_root_mut()? = to_ssz_rs(&root)?,
        }
        Ok(())
    }
}

// contains functions we need for BuilderBids.. not sure what to call this
pub trait BidStuff {
    fn fee_recipient_mut(&mut self) -> &mut ExecutionAddress;
    fn gas_limit_mut(&mut self) -> &mut u64;
    fn value_mut(&mut self) -> &mut U256;
    fn parent_hash_mut(&mut self) -> &mut Hash32;
    fn prev_randao_mut(&mut self) -> &mut Hash32;
    fn block_number_mut(&mut self) -> &mut u64;
    fn timestamp_mut(&mut self) -> &mut u64;
    fn withdrawals_root_mut(&mut self) -> Result<&mut Root, MevError>;

    fn sign_builder_message(
        &mut self,
        signing_key: &SecretKey,
        context: &Context,
    ) -> Result<BlsSignature, Error>;

    fn to_signed_bid(self, signature: BlsSignature) -> SignedBuilderBid;
}

impl BidStuff for BuilderBid {
    fn fee_recipient_mut(&mut self) -> &mut ExecutionAddress {
        match self {
            Self::Bellatrix(bid) => &mut bid.header.fee_recipient,
            Self::Capella(bid) => &mut bid.header.fee_recipient,
        }
    }

    fn gas_limit_mut(&mut self) -> &mut u64 {
        match self {
            Self::Bellatrix(bid) => &mut bid.header.gas_limit,
            Self::Capella(bid) => &mut bid.header.gas_limit,
        }
    }

    fn value_mut(&mut self) -> &mut U256 {
        match self {
            Self::Bellatrix(bid) => &mut bid.value,
            Self::Capella(bid) => &mut bid.value,
        }
    }

    fn parent_hash_mut(&mut self) -> &mut Hash32 {
        match self {
            Self::Bellatrix(bid) => &mut bid.header.parent_hash,
            Self::Capella(bid) => &mut bid.header.parent_hash,
        }
    }

    fn prev_randao_mut(&mut self) -> &mut Hash32 {
        match self {
            Self::Bellatrix(bid) => &mut bid.header.prev_randao,
            Self::Capella(bid) => &mut bid.header.prev_randao,
        }
    }

    fn block_number_mut(&mut self) -> &mut u64 {
        match self {
            Self::Bellatrix(bid) => &mut bid.header.block_number,
            Self::Capella(bid) => &mut bid.header.block_number,
        }
    }

    fn timestamp_mut(&mut self) -> &mut u64 {
        match self {
            Self::Bellatrix(bid) => &mut bid.header.timestamp,
            Self::Capella(bid) => &mut bid.header.timestamp,
        }
    }

    fn withdrawals_root_mut(&mut self) -> Result<&mut Root, MevError> {
        match self {
            Self::Bellatrix(_) => Err(MevError::InvalidFork),
            Self::Capella(bid) => Ok(&mut bid.header.withdrawals_root),
        }
    }

    fn sign_builder_message(
        &mut self,
        signing_key: &SecretKey,
        context: &Context,
    ) -> Result<Signature, Error> {
        match self {
            Self::Bellatrix(message) => sign_builder_message(message, signing_key, context),
            Self::Capella(message) => sign_builder_message(message, signing_key, context),
        }
    }

    fn to_signed_bid(self, signature: Signature) -> SignedBuilderBid {
        match self {
            Self::Bellatrix(message) => {
                SignedBuilderBid::Bellatrix(SignedBuilderBidBellatrix { message, signature })
            }
            Self::Capella(message) => {
                SignedBuilderBid::Capella(SignedBuilderBidCapella { message, signature })
            }
        }
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
    pub fn new_for_testing(
        mock_el_url: SensitiveUrl,
        beacon_url: SensitiveUrl,
        spec: ChainSpec,
        executor: TaskExecutor,
    ) -> (Self, MockBuilderServer) {
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
        let host: Ipv4Addr = Ipv4Addr::LOCALHOST;
        let port = 0;
        let provider = BlindedBlockProviderServer::new(host, port, builder.clone());
        let server = provider.serve();
        (builder, server)
    }

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

    fn apply_operations<B: BidStuff>(&self, bid: &mut B) -> Result<(), MevError> {
        let mut guard = self.operations.write();
        while let Some(op) = guard.pop() {
            op.apply(bid)?;
        }
        Ok(())
    }
}

#[async_trait]
impl<E: EthSpec> mev_rs::BlindedBlockProvider for MockBuilder<E> {
    async fn register_validators(
        &self,
        registrations: &mut [SignedValidatorRegistration],
    ) -> Result<(), MevError> {
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

    async fn fetch_best_bid(&self, bid_request: &BidRequest) -> Result<SignedBuilderBid, MevError> {
        let slot = Slot::new(bid_request.slot);
        let fork = self.spec.fork_name_at_slot::<E>(slot);
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

        let block = head.data.message();
        let head_block_root = block.tree_hash_root();
        let head_execution_hash = block
            .body()
            .execution_payload()
            .map_err(convert_err)?
            .block_hash();
        if head_execution_hash != from_ssz_rs(&bid_request.parent_hash)? {
            return Err(custom_err(format!(
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
            .message()
            .body()
            .execution_payload()
            .map_err(convert_err)?
            .block_hash();

        let justified_execution_hash = self
            .beacon_client
            .get_beacon_blocks::<E>(BlockId::Justified)
            .await
            .map_err(convert_err)?
            .ok_or_else(|| convert_err("missing finalized block"))?
            .data
            .message()
            .body()
            .execution_payload()
            .map_err(convert_err)?
            .block_hash();

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
            .ok_or_else(|| custom_err("missing head state".to_string()))?
            .data;
        let prev_randao = head_state
            .get_randao_mix(head_state.current_epoch())
            .map_err(convert_err)?;

        let payload_attributes = match fork {
            ForkName::Merge => PayloadAttributes::new(timestamp, *prev_randao, fee_recipient, None),
            // the withdrawals root is filled in by operations
            ForkName::Capella => {
                PayloadAttributes::new(timestamp, *prev_randao, fee_recipient, Some(vec![]))
            }
            ForkName::Base | ForkName::Altair => {
                return Err(MevError::InvalidFork);
            }
        };

        self.el
            .insert_proposer(slot, head_block_root, val_index, payload_attributes.clone())
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
                &payload_attributes,
                forkchoice_update_params,
                fork,
            )
            .await
            .map_err(convert_err)?
            .to_payload()
            .to_execution_payload_header();

        let json_payload = serde_json::to_string(&payload).map_err(convert_err)?;
        let mut message = match fork {
            ForkName::Capella => BuilderBid::Capella(BuilderBidCapella {
                header: serde_json::from_str(json_payload.as_str()).map_err(convert_err)?,
                value: to_ssz_rs(&Uint256::from(DEFAULT_BUILDER_PAYLOAD_VALUE_WEI))?,
                public_key: self.builder_sk.public_key(),
            }),
            ForkName::Merge => BuilderBid::Bellatrix(BuilderBidBellatrix {
                header: serde_json::from_str(json_payload.as_str()).map_err(convert_err)?,
                value: to_ssz_rs(&Uint256::from(DEFAULT_BUILDER_PAYLOAD_VALUE_WEI))?,
                public_key: self.builder_sk.public_key(),
            }),
            ForkName::Base | ForkName::Altair => return Err(MevError::InvalidFork),
        };
        *message.gas_limit_mut() = cached_data.gas_limit;

        self.apply_operations(&mut message)?;
        let mut signature =
            message.sign_builder_message(&self.builder_sk, self.context.as_ref())?;

        if *self.invalidate_signatures.read() {
            signature = Signature::default();
        }

        Ok(message.to_signed_bid(signature))
    }

    async fn open_bid(
        &self,
        signed_block: &mut SignedBlindedBeaconBlock,
    ) -> Result<ServerPayload, MevError> {
        let node = match signed_block {
            SignedBlindedBeaconBlock::Bellatrix(block) => {
                block.message.body.execution_payload_header.hash_tree_root()
            }
            SignedBlindedBeaconBlock::Capella(block) => {
                block.message.body.execution_payload_header.hash_tree_root()
            }
        }
        .map_err(convert_err)?;

        let payload = self
            .el
            .get_payload_by_root(&from_ssz_rs(&node)?)
            .ok_or_else(|| convert_err("missing payload for tx root"))?;

        let json_payload = serde_json::to_string(&payload).map_err(convert_err)?;
        serde_json::from_str(json_payload.as_str()).map_err(convert_err)
    }
}

pub fn from_ssz_rs<T: SimpleSerialize, U: Decode>(ssz_rs_data: &T) -> Result<U, MevError> {
    U::from_ssz_bytes(
        ssz_rs::serialize(ssz_rs_data)
            .map_err(convert_err)?
            .as_ref(),
    )
    .map_err(convert_err)
}

pub fn to_ssz_rs<T: Encode, U: SimpleSerialize>(ssz_data: &T) -> Result<U, MevError> {
    ssz_rs::deserialize::<U>(&ssz_data.as_ssz_bytes()).map_err(convert_err)
}

fn convert_err<E: Debug>(e: E) -> MevError {
    custom_err(format!("{e:?}"))
}

// This is a bit of a hack since the `Custom` variant was removed from `mev_rs::Error`.
fn custom_err(s: String) -> MevError {
    MevError::Consensus(ethereum_consensus::state_transition::Error::Io(
        std::io::Error::new(std::io::ErrorKind::Other, s),
    ))
}
