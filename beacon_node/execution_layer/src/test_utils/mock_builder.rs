use crate::test_utils::{DEFAULT_BUILDER_PAYLOAD_VALUE_WEI, DEFAULT_JWT_SECRET};
use crate::{Config, ExecutionLayer, PayloadAttributes};
use eth2::types::{BlobsBundle, BlockId, StateId, ValidatorId};
use eth2::{BeaconNodeHttpClient, Timeouts, CONSENSUS_VERSION_HEADER};
use fork_choice::ForkchoiceUpdateParameters;
use parking_lot::RwLock;
use sensitive_url::SensitiveUrl;
use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use task_executor::TaskExecutor;
use tempfile::NamedTempFile;
use tree_hash::TreeHash;
use types::builder_bid::{
    BuilderBid, BuilderBidBellatrix, BuilderBidCapella, BuilderBidDeneb, BuilderBidElectra,
    SignedBuilderBid,
};
use types::{
    Address, BeaconState, ChainSpec, EthSpec, ExecPayload, ExecutionPayload,
    ExecutionPayloadHeaderRefMut, ExecutionRequests, FixedBytesExtended, ForkName,
    ForkVersionedResponse, Hash256, PublicKeyBytes, Signature, SignedBlindedBeaconBlock,
    SignedRoot, SignedValidatorRegistrationData, Slot, Uint256,
};
use types::{ExecutionBlockHash, SecretKey};
use warp::{Filter, Rejection};

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
    fn apply<E: EthSpec, B: BidStuff<E>>(self, bid: &mut B) {
        match self {
            Operation::FeeRecipient(fee_recipient) => bid.set_fee_recipient(fee_recipient),
            Operation::GasLimit(gas_limit) => bid.set_gas_limit(gas_limit as u64),
            Operation::Value(value) => bid.set_value(value),
            Operation::ParentHash(parent_hash) => bid.set_parent_hash(parent_hash),
            Operation::PrevRandao(prev_randao) => bid.set_prev_randao(prev_randao),
            Operation::BlockNumber(block_number) => bid.set_block_number(block_number as u64),
            Operation::Timestamp(timestamp) => bid.set_timestamp(timestamp as u64),
            Operation::WithdrawalsRoot(root) => bid.set_withdrawals_root(root),
        }
    }
}

#[derive(Debug)]
// We don't use the string value directly, but it's used in the Debug impl which is required by `warp::reject::Reject`.
struct Custom(#[allow(dead_code)] String);

impl warp::reject::Reject for Custom {}

// contains functions we need for BuilderBids.. not sure what to call this
pub trait BidStuff<E: EthSpec> {
    fn set_fee_recipient(&mut self, fee_recipient_address: Address);
    fn set_gas_limit(&mut self, gas_limit: u64);
    fn set_value(&mut self, value: Uint256);
    fn set_parent_hash(&mut self, parent_hash: Hash256);
    fn set_prev_randao(&mut self, randao: Hash256);
    fn set_block_number(&mut self, block_number: u64);
    fn set_timestamp(&mut self, timestamp: u64);
    fn set_withdrawals_root(&mut self, withdrawals_root: Hash256);

    fn sign_builder_message(&mut self, sk: &SecretKey, spec: &ChainSpec) -> Signature;
}

impl<E: EthSpec> BidStuff<E> for BuilderBid<E> {
    fn set_fee_recipient(&mut self, fee_recipient: Address) {
        match self.to_mut().header_mut() {
            ExecutionPayloadHeaderRefMut::Bellatrix(header) => {
                header.fee_recipient = fee_recipient;
            }
            ExecutionPayloadHeaderRefMut::Capella(header) => {
                header.fee_recipient = fee_recipient;
            }
            ExecutionPayloadHeaderRefMut::Deneb(header) => {
                header.fee_recipient = fee_recipient;
            }
            ExecutionPayloadHeaderRefMut::Electra(header) => {
                header.fee_recipient = fee_recipient;
            }
        }
    }

    fn set_gas_limit(&mut self, gas_limit: u64) {
        match self.to_mut().header_mut() {
            ExecutionPayloadHeaderRefMut::Bellatrix(header) => {
                header.gas_limit = gas_limit;
            }
            ExecutionPayloadHeaderRefMut::Capella(header) => {
                header.gas_limit = gas_limit;
            }
            ExecutionPayloadHeaderRefMut::Deneb(header) => {
                header.gas_limit = gas_limit;
            }
            ExecutionPayloadHeaderRefMut::Electra(header) => {
                header.gas_limit = gas_limit;
            }
        }
    }

    fn set_value(&mut self, value: Uint256) {
        *self.value_mut() = value;
    }

    fn set_parent_hash(&mut self, parent_hash: Hash256) {
        match self.to_mut().header_mut() {
            ExecutionPayloadHeaderRefMut::Bellatrix(header) => {
                header.parent_hash = ExecutionBlockHash::from_root(parent_hash);
            }
            ExecutionPayloadHeaderRefMut::Capella(header) => {
                header.parent_hash = ExecutionBlockHash::from_root(parent_hash);
            }
            ExecutionPayloadHeaderRefMut::Deneb(header) => {
                header.parent_hash = ExecutionBlockHash::from_root(parent_hash);
            }
            ExecutionPayloadHeaderRefMut::Electra(header) => {
                header.parent_hash = ExecutionBlockHash::from_root(parent_hash);
            }
        }
    }

    fn set_prev_randao(&mut self, prev_randao: Hash256) {
        match self.to_mut().header_mut() {
            ExecutionPayloadHeaderRefMut::Bellatrix(header) => {
                header.prev_randao = prev_randao;
            }
            ExecutionPayloadHeaderRefMut::Capella(header) => {
                header.prev_randao = prev_randao;
            }
            ExecutionPayloadHeaderRefMut::Deneb(header) => {
                header.prev_randao = prev_randao;
            }
            ExecutionPayloadHeaderRefMut::Electra(header) => {
                header.prev_randao = prev_randao;
            }
        }
    }

    fn set_block_number(&mut self, block_number: u64) {
        match self.to_mut().header_mut() {
            ExecutionPayloadHeaderRefMut::Bellatrix(header) => {
                header.block_number = block_number;
            }
            ExecutionPayloadHeaderRefMut::Capella(header) => {
                header.block_number = block_number;
            }
            ExecutionPayloadHeaderRefMut::Deneb(header) => {
                header.block_number = block_number;
            }
            ExecutionPayloadHeaderRefMut::Electra(header) => {
                header.block_number = block_number;
            }
        }
    }

    fn set_timestamp(&mut self, timestamp: u64) {
        match self.to_mut().header_mut() {
            ExecutionPayloadHeaderRefMut::Bellatrix(header) => {
                header.timestamp = timestamp;
            }
            ExecutionPayloadHeaderRefMut::Capella(header) => {
                header.timestamp = timestamp;
            }
            ExecutionPayloadHeaderRefMut::Deneb(header) => {
                header.timestamp = timestamp;
            }
            ExecutionPayloadHeaderRefMut::Electra(header) => {
                header.timestamp = timestamp;
            }
        }
    }

    fn set_withdrawals_root(&mut self, withdrawals_root: Hash256) {
        match self.to_mut().header_mut() {
            ExecutionPayloadHeaderRefMut::Bellatrix(_) => {
                panic!("no withdrawals before capella")
            }
            ExecutionPayloadHeaderRefMut::Capella(header) => {
                header.withdrawals_root = withdrawals_root;
            }
            ExecutionPayloadHeaderRefMut::Deneb(header) => {
                header.withdrawals_root = withdrawals_root;
            }
            ExecutionPayloadHeaderRefMut::Electra(header) => {
                header.withdrawals_root = withdrawals_root;
            }
        }
    }

    fn sign_builder_message(&mut self, sk: &SecretKey, spec: &ChainSpec) -> Signature {
        let domain = spec.get_builder_domain();
        let message = self.signing_root(domain);
        sk.sign(message)
    }
}

#[derive(Clone)]
pub struct MockBuilder<E: EthSpec> {
    el: ExecutionLayer<E>,
    beacon_client: BeaconNodeHttpClient,
    spec: Arc<ChainSpec>,
    val_registration_cache: Arc<RwLock<HashMap<PublicKeyBytes, SignedValidatorRegistrationData>>>,
    builder_sk: SecretKey,
    operations: Arc<RwLock<Vec<Operation>>>,
    invalidate_signatures: Arc<RwLock<bool>>,
}

impl<E: EthSpec> MockBuilder<E> {
    pub fn new_for_testing(
        mock_el_url: SensitiveUrl,
        beacon_url: SensitiveUrl,
        spec: Arc<ChainSpec>,
        executor: TaskExecutor,
    ) -> (Self, (SocketAddr, impl Future<Output = ()>)) {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().into();
        std::fs::write(&path, hex::encode(DEFAULT_JWT_SECRET)).unwrap();

        // This EL should not talk to a builder
        let config = Config {
            execution_endpoint: Some(mock_el_url),
            secret_file: Some(path),
            suggested_fee_recipient: None,
            ..Default::default()
        };

        let el =
            ExecutionLayer::from_config(config, executor.clone(), executor.log().clone()).unwrap();

        let builder = MockBuilder::new(
            el,
            BeaconNodeHttpClient::new(beacon_url, Timeouts::set_all(Duration::from_secs(1))),
            spec,
        );
        let host: Ipv4Addr = Ipv4Addr::LOCALHOST;
        let port = 0;
        let server = serve(host, port, builder.clone()).expect("mock builder server should start");
        (builder, server)
    }

    pub fn new(
        el: ExecutionLayer<E>,
        beacon_client: BeaconNodeHttpClient,
        spec: Arc<ChainSpec>,
    ) -> Self {
        let sk = SecretKey::random();
        Self {
            el,
            beacon_client,
            // Should keep spec and context consistent somehow
            spec,
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

    fn apply_operations<B: BidStuff<E>>(&self, bid: &mut B) {
        let mut guard = self.operations.write();
        while let Some(op) = guard.pop() {
            op.apply(bid);
        }
    }
}

pub fn serve<E: EthSpec>(
    listen_addr: Ipv4Addr,
    listen_port: u16,
    builder: MockBuilder<E>,
) -> Result<(SocketAddr, impl Future<Output = ()>), crate::test_utils::Error> {
    let inner_ctx = builder.clone();
    let ctx_filter = warp::any().map(move || inner_ctx.clone());

    let prefix = warp::path("eth")
        .and(warp::path("v1"))
        .and(warp::path("builder"));

    let validators = prefix
        .and(warp::path("validators"))
        .and(warp::body::json())
        .and(warp::path::end())
        .and(ctx_filter.clone())
        .and_then(
            |registrations: Vec<SignedValidatorRegistrationData>, builder: MockBuilder<E>| async move {
                for registration in registrations {
                    if !registration.verify_signature(&builder.spec) {
                        return Err(reject("invalid signature"));
                    }
                    builder
                        .val_registration_cache
                        .write()
                        .insert(registration.message.pubkey, registration);
                }
                Ok(warp::reply())
            },
        );

    let blinded_block =
        prefix
            .and(warp::path("blinded_blocks"))
            .and(warp::body::json())
            .and(warp::header::header::<ForkName>(CONSENSUS_VERSION_HEADER))
            .and(warp::path::end())
            .and(ctx_filter.clone())
            .and_then(
                |block: SignedBlindedBeaconBlock<E>,
                 fork_name: ForkName,
                 builder: MockBuilder<E>| async move {
                    let root = match block {
                        SignedBlindedBeaconBlock::Base(_) | types::SignedBeaconBlock::Altair(_) => {
                            return Err(reject("invalid fork"));
                        }
                        SignedBlindedBeaconBlock::Bellatrix(block) => {
                            block.message.body.execution_payload.tree_hash_root()
                        }
                        SignedBlindedBeaconBlock::Capella(block) => {
                            block.message.body.execution_payload.tree_hash_root()
                        }
                        SignedBlindedBeaconBlock::Deneb(block) => {
                            block.message.body.execution_payload.tree_hash_root()
                        }
                        SignedBlindedBeaconBlock::Electra(block) => {
                            block.message.body.execution_payload.tree_hash_root()
                        }
                        SignedBlindedBeaconBlock::EIP7732(_) => {
                            return Err(reject("invalid fork EIP7732"));
                        }
                    };
                    let payload = builder
                        .el
                        .get_payload_by_root(&root)
                        .ok_or_else(|| reject("missing payload for tx root"))?;
                    let resp: ForkVersionedResponse<_> = ForkVersionedResponse {
                        version: Some(fork_name),
                        metadata: Default::default(),
                        data: payload,
                    };

                    let json_payload = serde_json::to_string(&resp)
                        .map_err(|_| reject("coudn't serialize response"))?;
                    Ok::<_, warp::reject::Rejection>(
                        warp::http::Response::builder()
                            .status(200)
                            .body(
                                serde_json::to_string(&json_payload)
                                    .map_err(|_| reject("invalid JSON"))?,
                            )
                            .unwrap(),
                    )
                },
            );

    let status = prefix
        .and(warp::path("status"))
        .then(|| async { warp::reply() });

    let header = prefix
        .and(warp::path("header"))
        .and(warp::path::param::<Slot>().or_else(|_| async { Err(reject("Invalid slot")) }))
        .and(
            warp::path::param::<ExecutionBlockHash>()
                .or_else(|_| async { Err(reject("Invalid parent hash")) }),
        )
        .and(
            warp::path::param::<PublicKeyBytes>()
                .or_else(|_| async { Err(reject("Invalid pubkey")) }),
        )
        .and(warp::path::end())
        .and(ctx_filter.clone())
        .and_then(
            |slot: Slot,
             parent_hash: ExecutionBlockHash,
             pubkey: PublicKeyBytes,
             builder: MockBuilder<E>| async move {
                let fork = builder.spec.fork_name_at_slot::<E>(slot);
                let signed_cached_data = builder
                    .val_registration_cache
                    .read()
                    .get(&pubkey)
                    .ok_or_else(|| reject("missing registration"))?
                    .clone();
                let cached_data = signed_cached_data.message;

                let head = builder
                    .beacon_client
                    .get_beacon_blocks::<E>(BlockId::Head)
                    .await
                    .map_err(|_| reject("couldn't get head"))?
                    .ok_or_else(|| reject("missing head block"))?;

                let block = head.data.message();
                let head_block_root = block.tree_hash_root();
                let head_execution_hash = block
                    .body()
                    .execution_payload()
                    .map_err(|_| reject("pre-merge block"))?
                    .block_hash();
                if head_execution_hash != parent_hash {
                    return Err(reject("head mismatch"));
                }

                let finalized_execution_hash = builder
                    .beacon_client
                    .get_beacon_blocks::<E>(BlockId::Finalized)
                    .await
                    .map_err(|_| reject("couldn't get finalized block"))?
                    .ok_or_else(|| reject("missing finalized block"))?
                    .data
                    .message()
                    .body()
                    .execution_payload()
                    .map_err(|_| reject("pre-merge block"))?
                    .block_hash();

                let justified_execution_hash = builder
                    .beacon_client
                    .get_beacon_blocks::<E>(BlockId::Justified)
                    .await
                    .map_err(|_| reject("couldn't get justified block"))?
                    .ok_or_else(|| reject("missing justified block"))?
                    .data
                    .message()
                    .body()
                    .execution_payload()
                    .map_err(|_| reject("pre-merge block"))?
                    .block_hash();

                let val_index = builder
                    .beacon_client
                    .get_beacon_states_validator_id(StateId::Head, &ValidatorId::PublicKey(pubkey))
                    .await
                    .map_err(|_| reject("couldn't get validator"))?
                    .ok_or_else(|| reject("missing validator"))?
                    .data
                    .index;
                let fee_recipient = cached_data.fee_recipient;
                let slots_since_genesis = slot.as_u64() - builder.spec.genesis_slot.as_u64();

                let genesis_data = builder
                    .beacon_client
                    .get_beacon_genesis()
                    .await
                    .map_err(|_| reject("couldn't get beacon genesis"))?
                    .data;
                let genesis_time = genesis_data.genesis_time;
                let timestamp =
                    (slots_since_genesis * builder.spec.seconds_per_slot) + genesis_time;

                let head_state: BeaconState<E> = builder
                    .beacon_client
                    .get_debug_beacon_states(StateId::Head)
                    .await
                    .map_err(|_| reject("couldn't get state"))?
                    .ok_or_else(|| reject("missing state"))?
                    .data;
                let prev_randao = head_state
                    .get_randao_mix(head_state.current_epoch())
                    .map_err(|_| reject("couldn't get prev randao"))?;

                let expected_withdrawals = if fork.capella_enabled() {
                    Some(
                        builder
                            .beacon_client
                            .get_expected_withdrawals(&StateId::Head)
                            .await
                            .unwrap()
                            .data,
                    )
                } else {
                    None
                };

                let payload_attributes = match fork {
                    // the withdrawals root is filled in by operations, but we supply the valid withdrawals
                    // first to avoid polluting the execution block generator with invalid payload attributes
                    // NOTE: this was part of an effort to add payload attribute uniqueness checks,
                    // which was abandoned because it broke too many tests in subtle ways.
                    ForkName::EIP7732 => {
                        return Err(reject("invalid fork"));
                    }
                    ForkName::Bellatrix | ForkName::Capella => PayloadAttributes::new(
                        timestamp,
                        *prev_randao,
                        fee_recipient,
                        expected_withdrawals,
                        None,
                    ),
                    ForkName::Deneb | ForkName::Electra => PayloadAttributes::new(
                        timestamp,
                        *prev_randao,
                        fee_recipient,
                        expected_withdrawals,
                        Some(head_block_root),
                    ),
                    ForkName::Base | ForkName::Altair => {
                        return Err(reject("invalid fork"));
                    }
                };

                builder
                    .el
                    .insert_proposer(slot, head_block_root, val_index, payload_attributes.clone())
                    .await;

                let forkchoice_update_params = ForkchoiceUpdateParameters {
                    head_root: Hash256::zero(),
                    head_hash: None,
                    justified_hash: Some(justified_execution_hash),
                    finalized_hash: Some(finalized_execution_hash),
                };

                let payload_response_type = builder
                    .el
                    .get_full_payload_caching(
                        head_execution_hash,
                        &payload_attributes,
                        forkchoice_update_params,
                        fork,
                    )
                    .await
                    .map_err(|_| reject("couldn't get payload"))?;

                let mut message = match payload_response_type {
                    crate::GetPayloadResponseType::Full(payload_response) => {
                        #[allow(clippy::type_complexity)]
                        let (payload, _block_value, maybe_blobs_bundle, _maybe_requests): (
                            ExecutionPayload<E>,
                            Uint256,
                            Option<BlobsBundle<E>>,
                            Option<ExecutionRequests<E>>,
                        ) = payload_response.into();

                        match fork {
                            ForkName::EIP7732 => {
                                return Err(reject("invalid fork"));
                            }
                            ForkName::Electra => BuilderBid::Electra(BuilderBidElectra {
                                header: payload
                                    .as_electra()
                                    .map_err(|_| reject("incorrect payload variant"))?
                                    .into(),
                                blob_kzg_commitments: maybe_blobs_bundle
                                    .map(|b| b.commitments)
                                    .unwrap_or_default(),
                                value: Uint256::from(DEFAULT_BUILDER_PAYLOAD_VALUE_WEI),
                                pubkey: builder.builder_sk.public_key().compress(),
                            }),
                            ForkName::Deneb => BuilderBid::Deneb(BuilderBidDeneb {
                                header: payload
                                    .as_deneb()
                                    .map_err(|_| reject("incorrect payload variant"))?
                                    .into(),
                                blob_kzg_commitments: maybe_blobs_bundle
                                    .map(|b| b.commitments)
                                    .unwrap_or_default(),
                                value: Uint256::from(DEFAULT_BUILDER_PAYLOAD_VALUE_WEI),
                                pubkey: builder.builder_sk.public_key().compress(),
                            }),
                            ForkName::Capella => BuilderBid::Capella(BuilderBidCapella {
                                header: payload
                                    .as_capella()
                                    .map_err(|_| reject("incorrect payload variant"))?
                                    .into(),
                                value: Uint256::from(DEFAULT_BUILDER_PAYLOAD_VALUE_WEI),
                                pubkey: builder.builder_sk.public_key().compress(),
                            }),
                            ForkName::Bellatrix => BuilderBid::Bellatrix(BuilderBidBellatrix {
                                header: payload
                                    .as_bellatrix()
                                    .map_err(|_| reject("incorrect payload variant"))?
                                    .into(),
                                value: Uint256::from(DEFAULT_BUILDER_PAYLOAD_VALUE_WEI),
                                pubkey: builder.builder_sk.public_key().compress(),
                            }),
                            ForkName::Base | ForkName::Altair => {
                                return Err(reject("invalid fork"))
                            }
                        }
                    }
                    crate::GetPayloadResponseType::Blinded(payload_response) => {
                        #[allow(clippy::type_complexity)]
                        let (payload, _block_value, maybe_blobs_bundle, _maybe_requests): (
                            ExecutionPayload<E>,
                            Uint256,
                            Option<BlobsBundle<E>>,
                            Option<ExecutionRequests<E>>,
                        ) = payload_response.into();
                        match fork {
                            ForkName::EIP7732 => {
                                return Err(reject("invalid fork"));
                            }
                            ForkName::Electra => BuilderBid::Electra(BuilderBidElectra {
                                header: payload
                                    .as_electra()
                                    .map_err(|_| reject("incorrect payload variant"))?
                                    .into(),
                                blob_kzg_commitments: maybe_blobs_bundle
                                    .map(|b| b.commitments)
                                    .unwrap_or_default(),
                                value: Uint256::from(DEFAULT_BUILDER_PAYLOAD_VALUE_WEI),
                                pubkey: builder.builder_sk.public_key().compress(),
                            }),
                            ForkName::Deneb => BuilderBid::Deneb(BuilderBidDeneb {
                                header: payload
                                    .as_deneb()
                                    .map_err(|_| reject("incorrect payload variant"))?
                                    .into(),
                                blob_kzg_commitments: maybe_blobs_bundle
                                    .map(|b| b.commitments)
                                    .unwrap_or_default(),
                                value: Uint256::from(DEFAULT_BUILDER_PAYLOAD_VALUE_WEI),
                                pubkey: builder.builder_sk.public_key().compress(),
                            }),
                            ForkName::Capella => BuilderBid::Capella(BuilderBidCapella {
                                header: payload
                                    .as_capella()
                                    .map_err(|_| reject("incorrect payload variant"))?
                                    .into(),
                                value: Uint256::from(DEFAULT_BUILDER_PAYLOAD_VALUE_WEI),
                                pubkey: builder.builder_sk.public_key().compress(),
                            }),
                            ForkName::Bellatrix => BuilderBid::Bellatrix(BuilderBidBellatrix {
                                header: payload
                                    .as_bellatrix()
                                    .map_err(|_| reject("incorrect payload variant"))?
                                    .into(),
                                value: Uint256::from(DEFAULT_BUILDER_PAYLOAD_VALUE_WEI),
                                pubkey: builder.builder_sk.public_key().compress(),
                            }),
                            ForkName::Base | ForkName::Altair => {
                                return Err(reject("invalid fork"))
                            }
                        }
                    }
                };

                message.set_gas_limit(cached_data.gas_limit);

                builder.apply_operations(&mut message);

                let mut signature =
                    message.sign_builder_message(&builder.builder_sk, &builder.spec);

                if *builder.invalidate_signatures.read() {
                    signature = Signature::empty();
                }

                let fork_name = builder
                    .spec
                    .fork_name_at_epoch(slot.epoch(E::slots_per_epoch()));
                let signed_bid = SignedBuilderBid { message, signature };
                let resp: ForkVersionedResponse<_> = ForkVersionedResponse {
                    version: Some(fork_name),
                    metadata: Default::default(),
                    data: signed_bid,
                };
                let json_bid = serde_json::to_string(&resp)
                    .map_err(|_| reject("coudn't serialize signed bid"))?;
                Ok::<_, Rejection>(
                    warp::http::Response::builder()
                        .status(200)
                        .body(json_bid)
                        .unwrap(),
                )
            },
        );

    let routes = warp::post()
        .and(validators.or(blinded_block))
        .or(warp::get().and(status).or(header))
        .map(|reply| warp::reply::with_header(reply, "Server", "lighthouse-mock-builder-server"));

    let (listening_socket, server) = warp::serve(routes)
        .try_bind_ephemeral(SocketAddrV4::new(listen_addr, listen_port))
        .expect("mock builder server should start");
    Ok((listening_socket, server))
}

fn reject(msg: &'static str) -> Rejection {
    warp::reject::custom(Custom(msg.to_string()))
}
