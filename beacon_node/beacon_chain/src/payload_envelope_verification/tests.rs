use std::sync::Arc;
use std::time::Duration;

use bls::{FixedBytesExtended, Keypair, Signature};
use fork_choice::ForkChoice;
use parking_lot::{Mutex, RwLock};
use ssz_types::VariableList;
use store::{HotColdDB, KeyValueStore, MemoryStore, StoreConfig};
use types::consts::gloas::BUILDER_INDEX_SELF_BUILD;
use types::test_utils::generate_deterministic_keypairs;
use types::*;

use crate::BeaconStore;
use crate::beacon_fork_choice_store::BeaconForkChoiceStore;
use crate::beacon_proposer_cache::BeaconProposerCache;
use crate::builder::Witness;
use crate::canonical_head::CanonicalHead;
use crate::payload_envelope_verification::EnvelopeError;
use crate::payload_envelope_verification::gossip_verified_envelope::{
    GossipVerificationContext, GossipVerifiedEnvelope,
};
use crate::validator_pubkey_cache::ValidatorPubkeyCache;

type TestEthSpec = MinimalEthSpec;
type TestTypes = Witness<
    slot_clock::TestingSlotClock,
    TestEthSpec,
    MemoryStore<TestEthSpec>,
    MemoryStore<TestEthSpec>,
>;

/// Test context that holds the minimal state needed for gossip verification.
struct TestContext {
    store: BeaconStore<TestTypes>,
    canonical_head: CanonicalHead<TestTypes>,
    beacon_proposer_cache: Mutex<BeaconProposerCache>,
    validator_pubkey_cache: RwLock<ValidatorPubkeyCache<TestTypes>>,
    spec: Arc<ChainSpec>,
    keypairs: Vec<Keypair>,
    genesis_state: BeaconState<TestEthSpec>,
    genesis_block_root: Hash256,
    genesis_validators_root: Hash256,
}

impl TestContext {
    fn new(validator_count: usize) -> Self {
        let spec = Arc::new(ForkName::Gloas.make_genesis_spec(ChainSpec::minimal()));
        let keypairs = generate_deterministic_keypairs(validator_count);

        let mut genesis_state = genesis::interop_genesis_state::<TestEthSpec>(
            &keypairs,
            0, // genesis_time
            Hash256::from_slice(&[0x42; 32]),
            None, // no execution payload header
            &spec,
        )
        .expect("should create genesis state");

        let genesis_validators_root = genesis_state.genesis_validators_root();

        let store: BeaconStore<TestTypes> = Arc::new(
            HotColdDB::open_ephemeral(StoreConfig::default(), spec.clone())
                .expect("should create ephemeral store"),
        );

        // Initialize store metadata.
        let genesis_block = BeaconBlock::<TestEthSpec>::empty(&spec);
        let genesis_block_root = genesis_block.canonical_root();
        let signed_genesis_block = SignedBeaconBlock::from_block(genesis_block, Signature::empty());

        // Build caches and compute state root before storing.
        genesis_state
            .build_caches(&spec)
            .expect("should build caches");

        // Initialize store metadata ops (must be done before put_state).
        let ops = vec![
            store
                .init_anchor_info(
                    signed_genesis_block.parent_root(),
                    signed_genesis_block.slot(),
                    Slot::new(0),
                    false,
                )
                .expect("should init anchor info"),
            store
                .init_blob_info(signed_genesis_block.slot())
                .expect("should init blob info"),
            store
                .init_data_column_info(signed_genesis_block.slot())
                .expect("should init data column info"),
        ];
        store
            .hot_db
            .do_atomically(ops)
            .expect("should store metadata");

        // Store the genesis block and state.
        store
            .put_block(&genesis_block_root, signed_genesis_block.clone())
            .expect("should store genesis block");
        let state_root = genesis_state
            .update_tree_hash_cache()
            .expect("should compute state root");
        store
            .put_state(&state_root, &genesis_state)
            .expect("should store genesis state");

        // Create BeaconSnapshot and fork choice.
        let snapshot = crate::BeaconSnapshot {
            beacon_block: Arc::new(signed_genesis_block),
            beacon_block_root: genesis_block_root,
            beacon_state: genesis_state.clone(),
        };

        let fc_store = BeaconForkChoiceStore::get_forkchoice_store(store.clone(), snapshot.clone())
            .expect("should create fork choice store");

        let fork_choice = ForkChoice::from_anchor(
            fc_store,
            genesis_block_root,
            &snapshot.beacon_block,
            &snapshot.beacon_state,
            None,
            &spec,
        )
        .expect("should create fork choice from anchor");

        let canonical_head = CanonicalHead::new(fork_choice, Arc::new(snapshot));

        let validator_pubkey_cache = ValidatorPubkeyCache::new(&genesis_state, store.clone())
            .expect("should create validator pubkey cache");

        TestContext {
            store,
            canonical_head,
            beacon_proposer_cache: Mutex::new(BeaconProposerCache::default()),
            validator_pubkey_cache: RwLock::new(validator_pubkey_cache),
            spec,
            keypairs,
            genesis_state,
            genesis_block_root,
            genesis_validators_root,
        }
    }

    fn gossip_verification_context(&self) -> GossipVerificationContext<'_, TestTypes> {
        GossipVerificationContext {
            canonical_head: &self.canonical_head,
            store: &self.store,
            spec: &self.spec,
            beacon_proposer_cache: &self.beacon_proposer_cache,
            validator_pubkey_cache: &self.validator_pubkey_cache,
            genesis_validators_root: self.genesis_validators_root,
        }
    }

    /// Build a gloas block at `slot` with the given proposer, store it, add it to fork choice,
    /// and return the signed block, block root, and post-state.
    fn build_and_import_block(
        &self,
        slot: Slot,
        proposer_index: usize,
        execution_bid: ExecutionPayloadBid<TestEthSpec>,
    ) -> (
        Arc<SignedBeaconBlock<TestEthSpec>>,
        Hash256,
        BeaconState<TestEthSpec>,
    ) {
        let mut state = self.genesis_state.clone();

        // Advance the state to the target slot.
        if slot > state.slot() {
            state_processing::state_advance::complete_state_advance(
                &mut state, None, slot, &self.spec,
            )
            .expect("should advance state");
        }

        state.build_caches(&self.spec).expect("should build caches");

        // Compute the state root so we can embed it in the block.
        let state_root = state
            .update_tree_hash_cache()
            .expect("should compute state root");

        let signed_bid = SignedExecutionPayloadBid {
            message: execution_bid,
            signature: Signature::infinity().expect("should create infinity signature"),
        };

        // Create the block body with the actual state root.
        let block = BeaconBlock::Gloas(BeaconBlockGloas {
            slot,
            proposer_index: proposer_index as u64,
            parent_root: self.genesis_block_root,
            state_root,
            body: BeaconBlockBodyGloas {
                randao_reveal: Signature::empty(),
                eth1_data: state.eth1_data().clone(),
                graffiti: Graffiti::default(),
                proposer_slashings: VariableList::empty(),
                attester_slashings: VariableList::empty(),
                attestations: VariableList::empty(),
                deposits: VariableList::empty(),
                voluntary_exits: VariableList::empty(),
                sync_aggregate: SyncAggregate::empty(),
                bls_to_execution_changes: VariableList::empty(),
                signed_execution_payload_bid: signed_bid,
                payload_attestations: VariableList::empty(),
                _phantom: std::marker::PhantomData,
            },
        });

        let block_root = block.canonical_root();
        let proposer_sk = &self.keypairs[proposer_index].sk;
        let fork = self
            .spec
            .fork_at_epoch(slot.epoch(TestEthSpec::slots_per_epoch()));
        let signed_block = block.sign(proposer_sk, &fork, self.genesis_validators_root, &self.spec);

        // Store block and state.
        self.store
            .put_block(&block_root, signed_block.clone())
            .expect("should store block");
        self.store
            .put_state(&state_root, &state)
            .expect("should store state");

        // Add block to fork choice.
        let mut fork_choice = self.canonical_head.fork_choice_write_lock();
        fork_choice
            .on_block(
                slot,
                signed_block.message(),
                block_root,
                Duration::from_secs(0),
                &state,
                crate::PayloadVerificationStatus::Verified,
                &self.spec,
            )
            .expect("should add block to fork choice");
        drop(fork_choice);

        (Arc::new(signed_block), block_root, state)
    }

    /// Build a signed execution payload envelope for the given block.
    fn build_signed_envelope(
        &self,
        block_root: Hash256,
        slot: Slot,
        builder_index: u64,
        block_hash: ExecutionBlockHash,
        signing_key: &bls::SecretKey,
    ) -> Arc<SignedExecutionPayloadEnvelope<TestEthSpec>> {
        let mut payload = ExecutionPayloadGloas::default();
        payload.block_hash = block_hash;

        let envelope = ExecutionPayloadEnvelope {
            payload,
            execution_requests: ExecutionRequests::default(),
            builder_index,
            beacon_block_root: block_root,
            slot,
            state_root: Hash256::zero(),
        };

        let fork = self
            .spec
            .fork_at_epoch(slot.epoch(TestEthSpec::slots_per_epoch()));
        let domain = self.spec.get_domain(
            slot.epoch(TestEthSpec::slots_per_epoch()),
            Domain::BeaconBuilder,
            &fork,
            self.genesis_validators_root,
        );
        let message = envelope.signing_root(domain);
        let signature = signing_key.sign(message);

        Arc::new(SignedExecutionPayloadEnvelope {
            message: envelope,
            signature,
        })
    }

    /// Helper: build a block and matching self-build envelope.
    fn build_block_and_envelope(
        &self,
    ) -> (
        Arc<SignedBeaconBlock<TestEthSpec>>,
        Hash256,
        Arc<SignedExecutionPayloadEnvelope<TestEthSpec>>,
    ) {
        let slot = Slot::new(1);
        let block_hash = ExecutionBlockHash::from_root(Hash256::from_slice(&[0xaa; 32]));

        // Get proposer for slot 1.
        let mut state = self.genesis_state.clone();
        state_processing::state_advance::complete_state_advance(&mut state, None, slot, &self.spec)
            .expect("should advance state");
        state.build_caches(&self.spec).expect("should build caches");
        let proposer_index = state
            .get_beacon_proposer_index(slot, &self.spec)
            .expect("should get proposer index");

        let bid = ExecutionPayloadBid {
            builder_index: BUILDER_INDEX_SELF_BUILD,
            block_hash,
            slot,
            ..Default::default()
        };

        let (signed_block, block_root, _post_state) =
            self.build_and_import_block(slot, proposer_index, bid);

        let proposer_sk = &self.keypairs[proposer_index].sk;
        let envelope = self.build_signed_envelope(
            block_root,
            slot,
            BUILDER_INDEX_SELF_BUILD,
            block_hash,
            proposer_sk,
        );

        (signed_block, block_root, envelope)
    }
}

#[test]
fn test_valid_self_build_envelope() {
    let ctx = TestContext::new(32);
    let (_block, _block_root, envelope) = ctx.build_block_and_envelope();
    let gossip_ctx = ctx.gossip_verification_context();

    let result = GossipVerifiedEnvelope::new(envelope, &gossip_ctx);
    assert!(
        result.is_ok(),
        "valid self-build envelope should pass verification, got: {:?}",
        result.err()
    );
}

#[test]
fn test_unknown_block_root() {
    let ctx = TestContext::new(32);
    let gossip_ctx = ctx.gossip_verification_context();

    // Build an envelope referencing a block root not in fork choice.
    let unknown_root = Hash256::from_slice(&[0xff; 32]);
    let envelope = ctx.build_signed_envelope(
        unknown_root,
        Slot::new(1),
        BUILDER_INDEX_SELF_BUILD,
        ExecutionBlockHash::from_root(Hash256::zero()),
        &ctx.keypairs[0].sk,
    );

    let result = GossipVerifiedEnvelope::new(envelope, &gossip_ctx);
    assert!(
        matches!(result, Err(EnvelopeError::BlockRootUnknown { .. })),
        "should reject envelope with unknown block root, got: {:?}",
        result
    );
}

#[test]
fn test_slot_mismatch() {
    let ctx = TestContext::new(32);
    let (_block, block_root, _good_envelope) = ctx.build_block_and_envelope();
    let gossip_ctx = ctx.gossip_verification_context();

    // Build an envelope with a different slot than the block.
    let wrong_slot = Slot::new(2);
    let envelope = ctx.build_signed_envelope(
        block_root,
        wrong_slot,
        BUILDER_INDEX_SELF_BUILD,
        ExecutionBlockHash::from_root(Hash256::from_slice(&[0xaa; 32])),
        &ctx.keypairs[0].sk,
    );

    let result = GossipVerifiedEnvelope::new(envelope, &gossip_ctx);
    assert!(
        matches!(result, Err(EnvelopeError::SlotMismatch { .. })),
        "should reject envelope with slot mismatch, got: {:?}",
        result
    );
}

#[test]
fn test_builder_index_mismatch() {
    let ctx = TestContext::new(32);
    let gossip_ctx = ctx.gossip_verification_context();

    let slot = Slot::new(1);
    let block_hash = ExecutionBlockHash::from_root(Hash256::from_slice(&[0xaa; 32]));

    // Get proposer for slot 1.
    let mut state = ctx.genesis_state.clone();
    state_processing::state_advance::complete_state_advance(&mut state, None, slot, &ctx.spec)
        .expect("should advance state");
    state.build_caches(&ctx.spec).expect("should build caches");
    let proposer_index = state
        .get_beacon_proposer_index(slot, &ctx.spec)
        .expect("should get proposer index");

    // Block has builder_index = BUILDER_INDEX_SELF_BUILD
    let bid = ExecutionPayloadBid {
        builder_index: BUILDER_INDEX_SELF_BUILD,
        block_hash,
        slot,
        ..Default::default()
    };
    let (_block, block_root, _post_state) = ctx.build_and_import_block(slot, proposer_index, bid);

    // Envelope has a different builder_index.
    let wrong_builder_index = 999;
    let envelope = ctx.build_signed_envelope(
        block_root,
        slot,
        wrong_builder_index,
        block_hash,
        &ctx.keypairs[proposer_index].sk,
    );

    let result = GossipVerifiedEnvelope::new(envelope, &gossip_ctx);
    assert!(
        matches!(result, Err(EnvelopeError::BuilderIndexMismatch { .. })),
        "should reject envelope with builder index mismatch, got: {:?}",
        result
    );
}

#[test]
fn test_block_hash_mismatch() {
    let ctx = TestContext::new(32);
    let gossip_ctx = ctx.gossip_verification_context();

    let slot = Slot::new(1);
    let block_hash = ExecutionBlockHash::from_root(Hash256::from_slice(&[0xaa; 32]));
    let wrong_block_hash = ExecutionBlockHash::from_root(Hash256::from_slice(&[0xbb; 32]));

    // Get proposer for slot 1.
    let mut state = ctx.genesis_state.clone();
    state_processing::state_advance::complete_state_advance(&mut state, None, slot, &ctx.spec)
        .expect("should advance state");
    state.build_caches(&ctx.spec).expect("should build caches");
    let proposer_index = state
        .get_beacon_proposer_index(slot, &ctx.spec)
        .expect("should get proposer index");

    // Block has block_hash = 0xaa
    let bid = ExecutionPayloadBid {
        builder_index: BUILDER_INDEX_SELF_BUILD,
        block_hash,
        slot,
        ..Default::default()
    };
    let (_block, block_root, _post_state) = ctx.build_and_import_block(slot, proposer_index, bid);

    // Envelope has a different block_hash.
    let envelope = ctx.build_signed_envelope(
        block_root,
        slot,
        BUILDER_INDEX_SELF_BUILD,
        wrong_block_hash,
        &ctx.keypairs[proposer_index].sk,
    );

    let result = GossipVerifiedEnvelope::new(envelope, &gossip_ctx);
    assert!(
        matches!(result, Err(EnvelopeError::BlockHashMismatch { .. })),
        "should reject envelope with block hash mismatch, got: {:?}",
        result
    );
}

#[test]
fn test_bad_signature() {
    let ctx = TestContext::new(32);
    let gossip_ctx = ctx.gossip_verification_context();

    let slot = Slot::new(1);
    let block_hash = ExecutionBlockHash::from_root(Hash256::from_slice(&[0xaa; 32]));

    // Get proposer for slot 1.
    let mut state = ctx.genesis_state.clone();
    state_processing::state_advance::complete_state_advance(&mut state, None, slot, &ctx.spec)
        .expect("should advance state");
    state.build_caches(&ctx.spec).expect("should build caches");
    let proposer_index = state
        .get_beacon_proposer_index(slot, &ctx.spec)
        .expect("should get proposer index");

    let bid = ExecutionPayloadBid {
        builder_index: BUILDER_INDEX_SELF_BUILD,
        block_hash,
        slot,
        ..Default::default()
    };
    let (_block, block_root, _post_state) = ctx.build_and_import_block(slot, proposer_index, bid);

    // Sign the envelope with the wrong key (some other validator's key).
    let wrong_key_index = if proposer_index == 0 { 1 } else { 0 };
    let envelope = ctx.build_signed_envelope(
        block_root,
        slot,
        BUILDER_INDEX_SELF_BUILD,
        block_hash,
        &ctx.keypairs[wrong_key_index].sk,
    );

    let result = GossipVerifiedEnvelope::new(envelope, &gossip_ctx);
    assert!(
        matches!(result, Err(EnvelopeError::BadSignature)),
        "should reject envelope with bad signature, got: {:?}",
        result
    );
}

// NOTE: `test_prior_to_finalization` is omitted here because advancing finalization requires
// attestation-based justification which needs the full `BeaconChainHarness`. The
// `PriorToFinalization` code path is tested in the integration tests.
