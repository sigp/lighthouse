use std::sync::Arc;
use std::time::Duration;

use bls::{PublicKeyBytes, Signature};
use ethereum_hashing::hash;
use fork_choice::ForkChoice;
use genesis::{generate_deterministic_keypairs, interop_genesis_state};
use proto_array::{Block as ProtoBlock, ExecutionStatus, PayloadStatus};
use ssz::Encode;
use state_processing::genesis::genesis_block;
use store::{HotColdDB, KeyValueStore, StoreConfig};
use types::{
    AttestationShufflingId, ChainSpec, Checkpoint, Epoch, ExecutionBlockHash,
    ExecutionPayloadEnvelope, ExecutionPayloadGloas, ExecutionRequestsGloas, Hash256,
    MinimalEthSpec, SignedBeaconBlock, SignedExecutionPayloadEnvelope, Slot,
    consts::gloas::PAYLOAD_BUILDER_VERSION,
};

use crate::{
    BeaconChainError, BeaconStore, ServerSentEventHandler,
    beacon_fork_choice_store::BeaconForkChoiceStore,
    beacon_proposer_cache::BeaconProposerCache,
    beacon_snapshot::BeaconSnapshot,
    canonical_head::CanonicalHead,
    chain_config::FastConfirmationMode,
    observed_invalid_block_roots::ObservedInvalidBlockRoots,
    payload_envelope_verification::{
        EnvelopeError,
        gossip_verified_envelope::{GossipVerificationContext, GossipVerifiedEnvelope},
    },
    test_utils::{EphemeralHarnessType, fork_name_from_env, test_spec},
    validator_pubkey_cache::ValidatorPubkeyCache,
};
use parking_lot::{Mutex, RwLock};

type E = MinimalEthSpec;
type T = EphemeralHarnessType<E>;

const NUM_VALIDATORS: usize = 64;
/// Balance given to the registered builder (min_deposit_amount + extra).
const BUILDER_BALANCE: u64 = 2_000_000_000;

fn gloas_fork_enabled() -> bool {
    fork_name_from_env().is_some_and(|f| f.gloas_enabled())
}

fn builder_withdrawal_credentials(pubkey: &bls::PublicKey, spec: &ChainSpec) -> Hash256 {
    let fake_execution_address = &hash(&pubkey.as_ssz_bytes())[0..20];
    let mut credentials = [0u8; 32];
    credentials[0] = spec.builder_withdrawal_prefix_byte;
    credentials[12..].copy_from_slice(fake_execution_address);
    Hash256::from_slice(&credentials)
}

struct TestContext {
    canonical_head: CanonicalHead<T>,
    store: BeaconStore<T>,
    spec: ChainSpec,
    beacon_proposer_cache: Mutex<BeaconProposerCache>,
    validator_pubkey_cache: RwLock<ValidatorPubkeyCache<T>>,
    genesis_validators_root: Hash256,
    event_handler: Option<ServerSentEventHandler<E>>,
    observed_invalid_block_roots: ObservedInvalidBlockRoots,
    genesis_block_root: Hash256,
}

impl TestContext {
    fn new() -> Self {
        let spec = test_spec::<E>();
        let store = Arc::new(
            HotColdDB::open_ephemeral(StoreConfig::default(), Arc::new(spec.clone()))
                .expect("should open ephemeral store"),
        );

        let keypairs = generate_deterministic_keypairs(NUM_VALIDATORS);
        let mut state =
            interop_genesis_state::<E>(&keypairs, 0, Hash256::repeat_byte(0x42), None, &spec)
                .expect("should build genesis state");

        // Register a builder at index 0, matching the genesis bid's builder index, so envelope
        // signature verification can look up its pubkey.
        if state.fork_name_unchecked().gloas_enabled() {
            let keypair = &keypairs[0];
            let creds = builder_withdrawal_credentials(&keypair.pk, &spec);
            state
                .add_builder_to_registry(
                    PublicKeyBytes::from(keypair.pk.clone()),
                    PAYLOAD_BUILDER_VERSION,
                    creds,
                    BUILDER_BALANCE,
                    Slot::new(0),
                    &spec,
                )
                .expect("should register builder");
        }

        let mut block = genesis_block(&state, &spec).expect("should build genesis block");
        let state_root = state
            .update_tree_hash_cache()
            .expect("should hash genesis state");
        *block.state_root_mut() = state_root;
        let signed_block = SignedBeaconBlock::from_block(block, Signature::empty());
        let block_root = signed_block.canonical_root();

        // Initialize the store's anchor so the anchor block and state can be written (envelope
        // verification loads them from the store).
        let anchor_op = store
            .init_anchor_info(
                signed_block.message().parent_root(),
                Slot::new(0),
                Slot::new(0),
                true,
            )
            .expect("should init anchor info");
        store
            .hot_db
            .do_atomically(vec![anchor_op])
            .expect("should commit anchor info");
        store
            .put_block(&block_root, signed_block.clone())
            .expect("should store anchor block");
        store
            .put_state(&state_root, &state)
            .expect("should store anchor state");

        let snapshot = BeaconSnapshot::new(
            Arc::new(signed_block.clone()),
            None,
            block_root,
            state.clone(),
        );

        let fc_store = BeaconForkChoiceStore::get_forkchoice_store(store.clone(), snapshot.clone())
            .expect("should create fork choice store");
        let fork_choice =
            ForkChoice::from_anchor(fc_store, block_root, &signed_block, &state, None, &spec)
                .expect("should create fork choice");

        let canonical_head = CanonicalHead::new(
            fork_choice,
            Arc::new(snapshot),
            PayloadStatus::Pending,
            FastConfirmationMode::Disabled,
            &store,
            &spec,
        )
        .unwrap();

        let validator_pubkey_cache =
            ValidatorPubkeyCache::new(&state, store.clone()).expect("should build pubkey cache");

        Self {
            canonical_head,
            store,
            genesis_validators_root: state.genesis_validators_root(),
            spec,
            beacon_proposer_cache: <_>::default(),
            validator_pubkey_cache: RwLock::new(validator_pubkey_cache),
            event_handler: None,
            observed_invalid_block_roots: <_>::default(),
            genesis_block_root: block_root,
        }
    }

    fn gossip_ctx(&self) -> GossipVerificationContext<'_, T> {
        GossipVerificationContext {
            canonical_head: &self.canonical_head,
            store: &self.store,
            spec: &self.spec,
            beacon_proposer_cache: &self.beacon_proposer_cache,
            validator_pubkey_cache: &self.validator_pubkey_cache,
            genesis_validators_root: self.genesis_validators_root,
            event_handler: &self.event_handler,
            observed_invalid_block_roots: &self.observed_invalid_block_roots,
        }
    }

    /// Insert a proto block into fork choice whose block is (deliberately) not in the store.
    fn insert_block_without_store_entry(&self) -> Hash256 {
        let shuffling_id = AttestationShufflingId {
            shuffling_epoch: Epoch::new(0),
            shuffling_decision_block: self.genesis_block_root,
        };
        let fork_block_root = Hash256::repeat_byte(0xab);
        let mut fc = self.canonical_head.fork_choice_write_lock();
        fc.proto_array_mut()
            .process_block::<E>(
                ProtoBlock {
                    slot: Slot::new(1),
                    root: fork_block_root,
                    parent_root: Some(self.genesis_block_root),
                    target_root: fork_block_root,
                    current_epoch_shuffling_id: shuffling_id.clone(),
                    next_epoch_shuffling_id: shuffling_id,
                    state_root: Hash256::ZERO,
                    justified_checkpoint: Checkpoint {
                        epoch: Epoch::new(0),
                        root: self.genesis_block_root,
                    },
                    finalized_checkpoint: Checkpoint {
                        epoch: Epoch::new(0),
                        root: self.genesis_block_root,
                    },
                    execution_status: ExecutionStatus::irrelevant(),
                    unrealized_justified_checkpoint: None,
                    unrealized_finalized_checkpoint: None,
                    execution_payload_parent_hash: Some(ExecutionBlockHash::zero()),
                    execution_payload_block_hash: Some(ExecutionBlockHash::repeat_byte(0xab)),
                    proposer_index: Some(0),
                    payload_received: false,
                },
                Slot::new(1),
                &self.spec,
                Duration::from_secs(0),
            )
            .expect("should insert fork block");
        fork_block_root
    }
}

fn make_signed_envelope(
    slot: Slot,
    builder_index: u64,
    block_hash: ExecutionBlockHash,
    beacon_block_root: Hash256,
) -> Arc<SignedExecutionPayloadEnvelope<E>> {
    Arc::new(SignedExecutionPayloadEnvelope {
        message: ExecutionPayloadEnvelope {
            payload: ExecutionPayloadGloas {
                block_hash,
                slot_number: slot,
                ..ExecutionPayloadGloas::default()
            },
            execution_requests: ExecutionRequestsGloas::default(),
            builder_index,
            beacon_block_root,
            parent_beacon_block_root: Hash256::ZERO,
        },
        signature: Signature::empty(),
    })
}

fn unwrap_err<T2>(result: Result<T2, EnvelopeError>) -> EnvelopeError {
    match result {
        Ok(_) => panic!("expected verification to fail"),
        Err(e) => e,
    }
}

#[test]
fn block_root_unknown_is_ignored() {
    let ctx = TestContext::new();
    let unknown_root = Hash256::repeat_byte(0xcd);
    let envelope = make_signed_envelope(Slot::new(0), 0, ExecutionBlockHash::zero(), unknown_root);

    let err = unwrap_err(GossipVerifiedEnvelope::new(envelope, &ctx.gossip_ctx()));
    assert!(
        matches!(err, EnvelopeError::BlockRootUnknown { block_root } if block_root == unknown_root),
        "expected BlockRootUnknown, got: {err:?}"
    );
}

#[test]
fn block_observed_invalid_is_rejected() {
    let ctx = TestContext::new();
    let invalid_root = Hash256::repeat_byte(0xcd);
    let envelope = make_signed_envelope(Slot::new(0), 0, ExecutionBlockHash::zero(), invalid_root);

    ctx.observed_invalid_block_roots.insert(invalid_root);
    let err = unwrap_err(GossipVerifiedEnvelope::new(envelope, &ctx.gossip_ctx()));
    assert!(
        matches!(
            err,
            EnvelopeError::BlockFailedValidation { block_root } if block_root == invalid_root
        ),
        "expected BlockFailedValidation, got: {err:?}"
    );
}

#[test]
fn block_in_fork_choice_but_missing_from_store() {
    let ctx = TestContext::new();
    let fork_block_root = ctx.insert_block_without_store_entry();
    let envelope =
        make_signed_envelope(Slot::new(1), 0, ExecutionBlockHash::zero(), fork_block_root);

    let err = unwrap_err(GossipVerifiedEnvelope::new(envelope, &ctx.gossip_ctx()));
    assert!(
        matches!(
            &err,
            EnvelopeError::BeaconChainError(e)
                if matches!(**e, BeaconChainError::MissingBeaconBlock(root) if root == fork_block_root)
        ),
        "expected MissingBeaconBlock, got: {err:?}"
    );
}

#[test]
fn slot_mismatch_is_rejected() {
    if !gloas_fork_enabled() {
        return;
    }
    let ctx = TestContext::new();
    // The anchor block is at slot 0; the envelope claims slot 1.
    let envelope = make_signed_envelope(
        Slot::new(1),
        0,
        ExecutionBlockHash::zero(),
        ctx.genesis_block_root,
    );

    let err = unwrap_err(GossipVerifiedEnvelope::new(envelope, &ctx.gossip_ctx()));
    assert!(
        matches!(err, EnvelopeError::SlotMismatch { block, envelope }
            if block == Slot::new(0) && envelope == Slot::new(1)),
        "expected SlotMismatch, got: {err:?}"
    );
}

#[test]
fn builder_index_mismatch_is_rejected() {
    if !gloas_fork_enabled() {
        return;
    }
    let ctx = TestContext::new();
    // The anchor block's bid commits to builder index 0; the envelope claims builder 5.
    let envelope = make_signed_envelope(
        Slot::new(0),
        5,
        ExecutionBlockHash::zero(),
        ctx.genesis_block_root,
    );

    let err = unwrap_err(GossipVerifiedEnvelope::new(envelope, &ctx.gossip_ctx()));
    assert!(
        matches!(
            err,
            EnvelopeError::BuilderIndexMismatch {
                committed_bid: 0,
                envelope: 5
            }
        ),
        "expected BuilderIndexMismatch, got: {err:?}"
    );
}

#[test]
fn block_hash_mismatch_is_rejected() {
    if !gloas_fork_enabled() {
        return;
    }
    let ctx = TestContext::new();
    // The anchor block's bid commits to a zero block hash; the envelope reveals a different one.
    let envelope = make_signed_envelope(
        Slot::new(0),
        0,
        ExecutionBlockHash::repeat_byte(0xee),
        ctx.genesis_block_root,
    );

    let err = unwrap_err(GossipVerifiedEnvelope::new(envelope, &ctx.gossip_ctx()));
    assert!(
        matches!(err, EnvelopeError::BlockHashMismatch { .. }),
        "expected BlockHashMismatch, got: {err:?}"
    );
}

#[test]
fn bad_signature_is_rejected() {
    if !gloas_fork_enabled() {
        return;
    }
    let ctx = TestContext::new();
    // Consistent with the anchor bid (builder 0, zero block hash, slot 0) so verification
    // reaches the external-builder signature check, which fails on the empty signature.
    let envelope = make_signed_envelope(
        Slot::new(0),
        0,
        ExecutionBlockHash::zero(),
        ctx.genesis_block_root,
    );

    let err = unwrap_err(GossipVerifiedEnvelope::new(envelope, &ctx.gossip_ctx()));
    assert!(
        matches!(err, EnvelopeError::BadSignature),
        "expected BadSignature, got: {err:?}"
    );
}
