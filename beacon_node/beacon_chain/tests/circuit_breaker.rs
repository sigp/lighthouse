//! Tests for the post-Gloas builder circuit breaker: the missed-payload skip rules that gate
//! external bids during block production, and the bans recorded for builders that fail to reveal.

use beacon_chain::circuit_breaker::BanEntry;
use beacon_chain::payload_envelope_verification::gossip_verified_envelope::GossipVerifiedEnvelope;
use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
    PayloadAttestationVote, fork_name_from_env, test_spec,
};
use beacon_chain::{
    AvailabilityProcessingStatus, BlockError, BlockProductionError, ChainConfig,
    NotifyExecutionLayer,
};
use bls::PublicKeyBytes;
use execution_layer::{PayloadStatusV1, PayloadStatusV1Status};
use fork_choice::PayloadVerificationStatus;
use proto_array::PayloadStatus;
use state_processing::state_advance::complete_state_advance;
use std::sync::Arc;
use types::consts::gloas::BUILDER_INDEX_SELF_BUILD;
use types::{
    BeaconState, BlockImportSource, BuilderIndex, EthSpec, ExecutionBlockHash, Hash256,
    MinimalEthSpec, SignedBeaconBlock, Slot,
};

type E = MinimalEthSpec;
type Harness = BeaconChainHarness<EphemeralHarnessType<E>>;

const VALIDATOR_COUNT: usize = 64;
/// Validators whose keypairs double as payload builders 0 and 1.
const BUILDER_VALIDATORS: [usize; 2] = [0, 1];
const BUILDER_BALANCE: u64 = 32_000_000_000;
/// 0.1 ETH in gwei: comfortably above the mock EL's 0.01 ETH local block value, so an external bid
/// wins whenever it is allowed to compete.
const BID_VALUE: u64 = 100_000_000;
const BUILDER_A: BuilderIndex = 0;
const BUILDER_B: BuilderIndex = 1;

fn gloas_harness(chain_config: ChainConfig) -> Option<Harness> {
    if !fork_name_from_env().is_some_and(|fork| fork.gloas_enabled()) {
        return None;
    }
    let harness = BeaconChainHarness::builder(E::default())
        .spec(Arc::new(test_spec::<E>()))
        .chain_config(chain_config)
        .deterministic_keypairs(VALIDATOR_COUNT)
        .genesis_builders(BUILDER_VALIDATORS.to_vec(), BUILDER_BALANCE)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();
    Some(harness)
}

/// Extend the chain with fully-attested self-built blocks until it has finalized, which activates
/// the genesis builders. A self-built chain never records a ban.
async fn finalize(harness: &Harness) {
    Box::pin(harness.extend_to_slot(Slot::new(E::slots_per_epoch() * 4))).await;
    let finalized_epoch = harness
        .chain
        .canonical_head
        .cached_head()
        .finalized_checkpoint()
        .epoch;
    assert!(finalized_epoch > 0, "chain should have finalized");
    assert_eq!(
        harness.chain.circuit_breaker.num_ban_entries(),
        0,
        "a self-built chain never bans anyone"
    );
}

fn builder_pubkey(state: &BeaconState<E>, builder_index: BuilderIndex) -> PublicKeyBytes {
    state.get_builder(builder_index).unwrap().pubkey
}

fn block_builder_index(block: &SignedBeaconBlock<E>) -> BuilderIndex {
    block
        .message()
        .body()
        .signed_execution_payload_bid()
        .unwrap()
        .message
        .builder_index
}

fn always_canonical(_: &BanEntry) -> bool {
    true
}

/// Make the mock EL refuse to build on `parent_block_hash`: forkchoice updates with that head
/// return SYNCING without a payload id, so the local payload build fails.
fn fail_local_builds_on(harness: &Harness, parent_block_hash: ExecutionBlockHash) {
    harness
        .mock_execution_layer
        .as_ref()
        .expect("harness should have a mock EL")
        .server
        .set_fcu_payload_status(
            parent_block_hash,
            PayloadStatusV1 {
                status: PayloadStatusV1Status::Syncing,
                latest_valid_hash: None,
                validation_error: None,
                inclusion_list_satisfied: None,
            },
        );
}

/// Recompute the head at the current slot, as the per-slot task would before a proposal, so the
/// previous slot's attestations are reflected in fork choice's block weights. Unlike the per-slot
/// task this never records a ban, which keeps the skip rules under test on their own.
async fn recompute_head(harness: &Harness) {
    harness.chain.recompute_head_at_current_slot().await;
}

/// Assert the circuit breaker's skip rules have tripped for a proposal at `slot` extending
/// `state` on an EMPTY parent, as block production would evaluate them.
async fn assert_breaker_tripped(harness: &Harness, state: &BeaconState<E>, slot: Slot) {
    recompute_head(harness).await;
    let mut production_state = state.clone();
    complete_state_advance(&mut production_state, None, slot, None, &harness.spec)
        .expect("should advance state to the proposal slot");
    let parent_root = *production_state
        .get_block_root(slot - 1)
        .expect("should have a block root for the previous slot");
    let previous_slot_reached_quorum = harness
        .chain
        .fork_choice_weight_reaches_builder_payment_quorum(&parent_root);
    assert!(
        harness
            .chain
            .circuit_breaker
            .evaluate_skips_for_state(
                &production_state,
                slot,
                previous_slot_reached_quorum,
                &harness.spec
            )
            .expect("should evaluate skip rules")
            .is_some(),
        "circuit breaker should have tripped"
    );
}

/// The execution block hash a block extending `state` on an EMPTY parent builds on.
fn empty_parent_block_hash(state: &BeaconState<E>) -> ExecutionBlockHash {
    state
        .latest_execution_payload_bid()
        .expect("Gloas state should have a bid")
        .parent_block_hash
}

/// What `import_builder_block` produced: the block at `slot`, the state after it, and the head
/// state it was built on (useful for building a competing fork).
struct BuilderBlock {
    root: Hash256,
    slot: Slot,
    block: Arc<SignedBeaconBlock<E>>,
    post_state: BeaconState<E>,
    pre_state: BeaconState<E>,
}

/// Import a block carrying builder A's bid at the next slot, extending the head on its current
/// payload status. With `attest`, every validator in that slot's committees attests to it, which
/// is well above the builder payment quorum. The attestations reach fork choice at once and the
/// chain via the next block.
async fn import_builder_block(harness: &Harness, attest: bool) -> BuilderBlock {
    harness.advance_slot();
    recompute_head(harness).await;
    let slot = harness.get_current_slot();
    let pre_state = harness.get_current_state();
    let parent_payload_status = harness
        .chain
        .canonical_head
        .cached_head()
        .head_payload_status();
    let (block_contents, post_state) = Box::pin(harness.make_block_with_gossip_bid(
        pre_state.clone(),
        slot,
        parent_payload_status,
        BUILDER_A,
        BID_VALUE,
    ))
    .await;
    let root = block_contents.0.canonical_root();
    let state_root = block_contents.0.state_root();
    let block = block_contents.0.clone();
    harness
        .process_block(slot, root, block_contents)
        .await
        .expect("block with builder bid should import");
    if attest {
        let attestations = harness.make_attestations(
            &harness.get_all_validators(),
            &post_state,
            state_root,
            root.into(),
            slot,
        );
        harness.process_attestations(attestations, &post_state);
    }
    BuilderBlock {
        root,
        slot,
        block,
        post_state,
        pre_state,
    }
}

/// Build the builder's signed envelope answering `block`'s bid and run it through the full
/// envelope pipeline: consensus verification, then the mock EL's `newPayload` verdict.
async fn process_builder_envelope(
    harness: &Harness,
    block: &BuilderBlock,
) -> Result<AvailabilityProcessingStatus, BlockError> {
    let envelope = harness.make_builder_envelope_for_block(&block.block, &block.post_state);
    harness
        .chain
        .process_execution_payload_envelope(
            block.root,
            GossipVerifiedEnvelope {
                signed_envelope: Arc::new(envelope),
                block: block.block.clone(),
                snapshot: None,
            },
            NotifyExecutionLayer::Yes,
            BlockImportSource::Gossip,
            || Ok(()),
        )
        .await
}

/// Build `count` fully-attested blocks carrying builder A's bid in consecutive slots and never
/// process their envelopes, so each one's payload goes missing with the builder charged for it.
/// Returns the state after the last block.
async fn withhold_payloads(harness: &Harness, count: usize) -> BeaconState<E> {
    let mut state = harness.get_current_state();
    for _ in 0..count {
        state = Box::pin(import_builder_block(harness, true))
            .await
            .post_state;
    }
    state
}

/// Build `count` self-built blocks in consecutive slots and never process their envelopes. Each
/// payload goes missing, but no builder is charged for it.
async fn withhold_self_built_payloads(harness: &Harness, count: usize) -> BeaconState<E> {
    let mut state = harness.get_current_state();
    let mut parent_payload_status = harness
        .chain
        .canonical_head
        .cached_head()
        .head_payload_status();
    for _ in 0..count {
        harness.advance_slot();
        let slot = harness.get_current_slot();
        let (block_contents, envelope, post_state) =
            Box::pin(harness.make_block_with_envelope_on(state, slot, parent_payload_status)).await;
        assert!(
            envelope.is_some(),
            "self-built block should have an envelope"
        );
        harness
            .process_block(slot, block_contents.0.canonical_root(), block_contents)
            .await
            .expect("self-built block should import");
        state = post_state;
        parent_payload_status = PayloadStatus::Empty;
    }
    state
}

/// Build `count` fully-attested self-built blocks whose payloads are revealed.
async fn reveal_payloads(harness: &Harness, count: usize) {
    for _ in 0..count {
        harness.advance_slot();
        Box::pin(harness.extend_chain(
            1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        ))
        .await;
    }
}

/// Put a signed gossip bid from `builder_index` for the current slot into the chain's bid cache.
fn observe_gossip_bid(
    harness: &Harness,
    state: &BeaconState<E>,
    parent_payload_status: PayloadStatus,
    builder_index: BuilderIndex,
    value: u64,
) {
    let slot = harness.get_current_slot();
    let signed_bid =
        harness.make_signed_gossip_bid(state, slot, parent_payload_status, builder_index, value);
    assert!(harness.chain.gossip_verified_payload_bid_cache.observe_bid(
        beacon_chain::payload_bid_verification::gossip_verified_bid::GossipVerifiedPayloadBid {
            signed_bid: Arc::new(signed_bid),
        }
    ));
}

/// Produce a block at the current slot on `state` with a gossip bid from `builder_index` in the
/// cache, and return the builder index that won. The head is recomputed first, as it would be
/// before a real proposal.
async fn produce_with_gossip_bid(
    harness: &Harness,
    state: BeaconState<E>,
    parent_payload_status: PayloadStatus,
    builder_index: BuilderIndex,
    value: u64,
) -> BuilderIndex {
    recompute_head(harness).await;
    let slot = harness.get_current_slot();
    observe_gossip_bid(harness, &state, parent_payload_status, builder_index, value);
    let (block_contents, _envelope, _post_state) =
        Box::pin(harness.make_block_with_envelope_on(state, slot, parent_payload_status)).await;
    block_builder_index(&block_contents.0)
}

#[tokio::test]
async fn missed_reveal_with_quorum_bans_builder() {
    let Some(harness) = gloas_harness(ChainConfig::default()) else {
        return;
    };
    Box::pin(finalize(&harness)).await;
    let block = Box::pin(import_builder_block(&harness, true)).await;
    let pubkey = builder_pubkey(&block.post_state, BUILDER_A);

    // No envelope ever arrives. The miss is detected at the start of the next slot.
    harness.advance_slot();
    harness.chain.per_slot_task().await;

    let breaker = &harness.chain.circuit_breaker;
    let detected_at = block.slot + 1;
    let ban_slots = breaker.config().ban_slots;
    assert_eq!(breaker.num_ban_entries(), 1);
    assert!(breaker.is_banned_with(&pubkey, detected_at, always_canonical));
    assert!(breaker.is_banned_with(&pubkey, detected_at + ban_slots - 1, always_canonical));
    assert!(!breaker.is_banned_with(&pubkey, detected_at + ban_slots, always_canonical));
    assert!(!breaker.is_banned_with(
        &builder_pubkey(&block.post_state, BUILDER_B),
        detected_at,
        always_canonical
    ));

    // Re-running the per-slot task for the same slot does not record a second entry.
    harness.chain.per_slot_task().await;
    assert_eq!(breaker.num_ban_entries(), 1);
}

#[tokio::test]
async fn revealed_payload_is_not_banned() {
    let Some(harness) = gloas_harness(ChainConfig::default()) else {
        return;
    };
    Box::pin(finalize(&harness)).await;
    let block = Box::pin(import_builder_block(&harness, true)).await;

    // Stand in for envelope import: fork choice learns the payload was received.
    harness
        .chain
        .canonical_head
        .fork_choice_write_lock()
        .on_payload_envelope_received(
            block.root,
            PayloadVerificationStatus::Verified,
            block
                .post_state
                .latest_execution_payload_bid()
                .unwrap()
                .block_hash,
        )
        .unwrap();

    harness.advance_slot();
    harness.chain.per_slot_task().await;
    assert_eq!(harness.chain.circuit_breaker.num_ban_entries(), 0);
}

#[tokio::test]
async fn missed_reveal_without_quorum_is_not_banned() {
    let Some(harness) = gloas_harness(ChainConfig::default()) else {
        return;
    };
    Box::pin(finalize(&harness)).await;
    let _block = Box::pin(import_builder_block(&harness, false)).await;

    harness.advance_slot();
    harness.chain.per_slot_task().await;
    assert_eq!(harness.chain.circuit_breaker.num_ban_entries(), 0);
}

#[tokio::test]
async fn ptc_timely_vote_prevents_ban() {
    let Some(harness) = gloas_harness(ChainConfig::default()) else {
        return;
    };
    Box::pin(finalize(&harness)).await;
    let block = Box::pin(import_builder_block(&harness, true)).await;

    // A PTC majority saw the payload even though this node never received it.
    let (messages, _) = harness.make_payload_attestation_messages(
        &block.post_state,
        block.root,
        block.slot,
        vec![PayloadAttestationVote {
            validator_count: E::payload_timely_threshold() + 1,
            payload_present: true,
            blob_data_available: true,
        }],
    );
    harness
        .import_payload_attestation_messages(messages)
        .expect("PTC messages should import");

    harness.advance_slot();
    harness.chain.per_slot_task().await;
    assert_eq!(harness.chain.circuit_breaker.num_ban_entries(), 0);
}

#[tokio::test]
async fn ptc_timely_vote_with_unavailable_data_still_bans() {
    let Some(harness) = gloas_harness(ChainConfig::default()) else {
        return;
    };
    Box::pin(finalize(&harness)).await;
    let block = Box::pin(import_builder_block(&harness, true)).await;
    let pubkey = builder_pubkey(&block.post_state, BUILDER_A);

    // The PTC saw a timely reveal but voted the blob data unavailable: the slot still goes
    // empty and the builder is still charged, so the timely reveal is no excuse.
    let (messages, _) = harness.make_payload_attestation_messages(
        &block.post_state,
        block.root,
        block.slot,
        vec![PayloadAttestationVote {
            validator_count: E::payload_timely_threshold() + 1,
            payload_present: true,
            blob_data_available: false,
        }],
    );
    harness
        .import_payload_attestation_messages(messages)
        .expect("PTC messages should import");

    harness.advance_slot();
    harness.chain.per_slot_task().await;
    let breaker = &harness.chain.circuit_breaker;
    assert_eq!(breaker.num_ban_entries(), 1);
    assert!(breaker.is_banned_with(&pubkey, block.slot + 1, always_canonical));
}

#[tokio::test]
async fn missed_reveal_with_checks_disabled_is_not_banned() {
    let Some(harness) = gloas_harness(ChainConfig {
        builder_fallback_disable_checks: true,
        ..ChainConfig::default()
    }) else {
        return;
    };
    Box::pin(finalize(&harness)).await;
    let _block = Box::pin(import_builder_block(&harness, true)).await;

    harness.advance_slot();
    harness.chain.per_slot_task().await;
    assert_eq!(harness.chain.circuit_breaker.num_ban_entries(), 0);
}

#[tokio::test]
async fn el_invalid_payload_bans_builder() {
    let Some(harness) = gloas_harness(ChainConfig::default()) else {
        return;
    };
    Box::pin(finalize(&harness)).await;
    // No attestations: unlike a missed reveal, an invalid payload needs no payment quorum.
    let block = Box::pin(import_builder_block(&harness, false)).await;
    let pubkey = builder_pubkey(&block.post_state, BUILDER_A);

    // The EL rejects the revealed payload as INVALID. The latest valid hash is the payload's
    // parent, so the invalidation pass has nothing to invalidate.
    let parent_hash = *block.post_state.latest_block_hash().unwrap();
    harness
        .mock_execution_layer
        .as_ref()
        .expect("harness should have a mock EL")
        .server
        .all_payloads_invalid_on_new_payload(parent_hash);

    let result = Box::pin(process_builder_envelope(&harness, &block)).await;
    assert!(result.is_err(), "invalid envelope should be rejected");

    let breaker = &harness.chain.circuit_breaker;
    assert_eq!(breaker.num_ban_entries(), 1);
    assert!(breaker.is_banned_with(&pubkey, block.slot, always_canonical));
    assert!(!breaker.is_banned_with(
        &builder_pubkey(&block.post_state, BUILDER_B),
        block.slot,
        always_canonical
    ));

    // Re-processing the same envelope does not record a second entry.
    let result = Box::pin(process_builder_envelope(&harness, &block)).await;
    assert!(result.is_err());
    assert_eq!(breaker.num_ban_entries(), 1);
}

#[tokio::test]
async fn el_invalid_block_hash_bans_builder() {
    let Some(harness) = gloas_harness(ChainConfig::default()) else {
        return;
    };
    Box::pin(finalize(&harness)).await;
    let block = Box::pin(import_builder_block(&harness, false)).await;
    let pubkey = builder_pubkey(&block.post_state, BUILDER_A);

    harness
        .mock_execution_layer
        .as_ref()
        .expect("harness should have a mock EL")
        .server
        .all_payloads_invalid_block_hash_on_new_payload();

    let result = Box::pin(process_builder_envelope(&harness, &block)).await;
    assert!(result.is_err(), "invalid envelope should be rejected");

    let breaker = &harness.chain.circuit_breaker;
    assert_eq!(breaker.num_ban_entries(), 1);
    assert!(breaker.is_banned_with(&pubkey, block.slot, always_canonical));
}

#[tokio::test]
async fn el_invalid_payload_with_checks_disabled_is_not_banned() {
    let Some(harness) = gloas_harness(ChainConfig {
        builder_fallback_disable_checks: true,
        ..ChainConfig::default()
    }) else {
        return;
    };
    Box::pin(finalize(&harness)).await;
    let block = Box::pin(import_builder_block(&harness, false)).await;

    harness
        .mock_execution_layer
        .as_ref()
        .expect("harness should have a mock EL")
        .server
        .all_payloads_invalid_block_hash_on_new_payload();

    let result = Box::pin(process_builder_envelope(&harness, &block)).await;
    assert!(result.is_err(), "invalid envelope should be rejected");
    assert_eq!(harness.chain.circuit_breaker.num_ban_entries(), 0);
}

#[tokio::test]
async fn banned_builder_bid_is_filtered_from_production() {
    let Some(harness) = gloas_harness(ChainConfig::default()) else {
        return;
    };
    Box::pin(finalize(&harness)).await;
    let block = Box::pin(import_builder_block(&harness, true)).await;
    harness.advance_slot();
    harness.chain.per_slot_task().await;
    assert_eq!(harness.chain.circuit_breaker.num_ban_entries(), 1);

    // Builder A's bid loses to the local build even though it is worth more.
    let winner = produce_with_gossip_bid(
        &harness,
        block.post_state.clone(),
        PayloadStatus::Empty,
        BUILDER_A,
        BID_VALUE,
    )
    .await;
    assert_eq!(winner, BUILDER_INDEX_SELF_BUILD);

    // An unbanned builder's bid still wins.
    let winner = produce_with_gossip_bid(
        &harness,
        block.post_state,
        PayloadStatus::Empty,
        BUILDER_B,
        BID_VALUE + 1,
    )
    .await;
    assert_eq!(winner, BUILDER_B);
}

#[tokio::test]
async fn reorg_away_from_offending_block_lifts_ban() {
    let Some(harness) = gloas_harness(ChainConfig::default()) else {
        return;
    };
    Box::pin(finalize(&harness)).await;
    let block = Box::pin(import_builder_block(&harness, true)).await;
    harness.advance_slot();
    harness.chain.per_slot_task().await;
    let pubkey = builder_pubkey(&block.post_state, BUILDER_A);
    assert_eq!(harness.chain.circuit_breaker.num_ban_entries(), 1);

    // A competing block at the next slot that skips the offending block: it extends the
    // offending block's parent.
    let competing_slot = block.slot + 1;
    let (competing_contents, _envelope, competing_post_state) = Box::pin(
        harness.make_block_with_envelope_on(block.pre_state, competing_slot, PayloadStatus::Full),
    )
    .await;
    let competing_root = competing_contents.0.canonical_root();
    assert_eq!(
        competing_contents.0.parent_root(),
        block
            .post_state
            .get_block_root(block.slot - 1)
            .copied()
            .unwrap()
    );
    harness
        .process_block(competing_slot, competing_root, competing_contents)
        .await
        .expect("competing block should import");

    // The offending block is an ancestor of its own chain but not of the competing one.
    harness.advance_slot();
    let proposal_slot = harness.get_current_slot();
    assert_eq!(proposal_slot, competing_slot + 1);
    assert!(!harness.chain.circuit_breaker.is_banned(
        &pubkey,
        &competing_post_state,
        proposal_slot
    ));

    // Proposing on the competing chain: builder A's bid wins, there is no offence there.
    let winner = produce_with_gossip_bid(
        &harness,
        competing_post_state,
        PayloadStatus::Empty,
        BUILDER_A,
        BID_VALUE,
    )
    .await;
    assert_eq!(winner, BUILDER_A);

    // Proposing on the offending block's chain at the same slot: the bid is filtered.
    let winner = produce_with_gossip_bid(
        &harness,
        block.post_state,
        PayloadStatus::Empty,
        BUILDER_A,
        BID_VALUE,
    )
    .await;
    assert_eq!(winner, BUILDER_INDEX_SELF_BUILD);
}

#[tokio::test]
async fn consecutive_missed_payloads_trip_breaker() {
    let Some(harness) = gloas_harness(ChainConfig::default()) else {
        return;
    };
    Box::pin(finalize(&harness)).await;
    let skips = harness.chain.config.builder_fallback_skips;

    // Exactly the tolerated number of misses: the bid still wins.
    let state = Box::pin(withhold_payloads(&harness, skips)).await;
    harness.advance_slot();
    let winner =
        produce_with_gossip_bid(&harness, state, PayloadStatus::Empty, BUILDER_A, BID_VALUE).await;
    assert_eq!(winner, BUILDER_A);

    // One more miss trips the breaker: the local build wins.
    let state = Box::pin(withhold_payloads(&harness, 1)).await;
    harness.advance_slot();
    let winner =
        produce_with_gossip_bid(&harness, state, PayloadStatus::Empty, BUILDER_A, BID_VALUE).await;
    assert_eq!(winner, BUILDER_INDEX_SELF_BUILD);
}

#[tokio::test]
async fn missed_self_built_payloads_do_not_trip_breaker() {
    let Some(harness) = gloas_harness(ChainConfig::default()) else {
        return;
    };
    Box::pin(finalize(&harness)).await;
    let skips = harness.chain.config.builder_fallback_skips;

    // Self-builds bid zero, so no builder is ever charged for them: not a builder failure.
    let state = Box::pin(withhold_self_built_payloads(&harness, skips + 1)).await;
    harness.advance_slot();
    let winner =
        produce_with_gossip_bid(&harness, state, PayloadStatus::Empty, BUILDER_A, BID_VALUE).await;
    assert_eq!(winner, BUILDER_A);
}

#[tokio::test]
async fn missed_payloads_below_quorum_do_not_trip_breaker() {
    let Some(harness) = gloas_harness(ChainConfig {
        // A single charged missed payload would trip the consecutive rule.
        builder_fallback_skips: 0,
        ..ChainConfig::default()
    }) else {
        return;
    };
    Box::pin(finalize(&harness)).await;

    // Nobody attested to the block, so the builder is not charged and may honestly withhold.
    let block = Box::pin(import_builder_block(&harness, false)).await;
    harness.advance_slot();
    let winner = produce_with_gossip_bid(
        &harness,
        block.post_state,
        PayloadStatus::Empty,
        BUILDER_A,
        BID_VALUE,
    )
    .await;
    assert_eq!(winner, BUILDER_A);
}

#[tokio::test]
async fn consecutive_missed_payloads_ignored_with_checks_disabled() {
    let Some(harness) = gloas_harness(ChainConfig {
        builder_fallback_disable_checks: true,
        ..ChainConfig::default()
    }) else {
        return;
    };
    Box::pin(finalize(&harness)).await;
    let skips = harness.chain.config.builder_fallback_skips;

    let state = Box::pin(withhold_payloads(&harness, skips + 1)).await;
    harness.advance_slot();
    let winner =
        produce_with_gossip_bid(&harness, state, PayloadStatus::Empty, BUILDER_A, BID_VALUE).await;
    assert_eq!(winner, BUILDER_A);
}

#[tokio::test]
async fn empty_slots_are_not_missed_payloads() {
    let Some(harness) = gloas_harness(ChainConfig::default()) else {
        return;
    };
    Box::pin(finalize(&harness)).await;
    let skips = harness.chain.config.builder_fallback_skips;

    // Far more empty slots than either rule tolerates, but no block ever accepted a bid, so no
    // payload was ever missed.
    for _ in 0..(skips + 1) {
        harness.advance_slot();
    }
    harness.advance_slot();
    let state = harness.get_current_state();
    let winner =
        produce_with_gossip_bid(&harness, state, PayloadStatus::Full, BUILDER_A, BID_VALUE).await;
    assert_eq!(winner, BUILDER_A);
}

#[tokio::test]
async fn missed_payloads_in_window_trip_breaker_and_roll_off() {
    let Some(harness) = gloas_harness(ChainConfig {
        // Only the window rule can trip.
        builder_fallback_skips: usize::MAX,
        builder_fallback_skips_per_epoch: 2,
        ..ChainConfig::default()
    }) else {
        return;
    };
    Box::pin(finalize(&harness)).await;

    // Three non-consecutive misses inside the last `SLOTS_PER_EPOCH` (8) slots.
    Box::pin(withhold_payloads(&harness, 1)).await;
    Box::pin(reveal_payloads(&harness, 1)).await;
    Box::pin(withhold_payloads(&harness, 1)).await;
    Box::pin(reveal_payloads(&harness, 1)).await;
    Box::pin(withhold_payloads(&harness, 1)).await;

    harness.advance_slot();
    let state = harness.get_current_state();
    let winner =
        produce_with_gossip_bid(&harness, state, PayloadStatus::Empty, BUILDER_A, BID_VALUE).await;
    assert_eq!(winner, BUILDER_INDEX_SELF_BUILD);

    // Reveal enough payloads that the oldest miss leaves the window: two misses remain, which is
    // tolerated.
    Box::pin(reveal_payloads(&harness, 4)).await;
    harness.advance_slot();
    let state = harness.get_current_state();
    let winner =
        produce_with_gossip_bid(&harness, state, PayloadStatus::Full, BUILDER_A, BID_VALUE).await;
    assert_eq!(winner, BUILDER_A);
}

#[tokio::test]
async fn tripped_breaker_falls_back_to_gossip_bid_when_local_build_fails() {
    let Some(harness) = gloas_harness(ChainConfig {
        // A single missed payload trips the consecutive rule.
        builder_fallback_skips: 0,
        ..ChainConfig::default()
    }) else {
        return;
    };
    Box::pin(finalize(&harness)).await;
    let state = Box::pin(withhold_payloads(&harness, 1)).await;
    harness.advance_slot();
    let slot = harness.get_current_slot();

    // The breaker has tripped, so the bid is demoted below the local build. With the local build
    // failing it still wins rather than the slot being missed.
    assert_breaker_tripped(&harness, &state, slot).await;
    fail_local_builds_on(&harness, empty_parent_block_hash(&state));
    let (block_contents, _post_state) = Box::pin(harness.make_block_with_gossip_bid(
        state,
        slot,
        PayloadStatus::Empty,
        BUILDER_A,
        BID_VALUE,
    ))
    .await;
    assert_eq!(block_builder_index(&block_contents.0), BUILDER_A);
}

#[tokio::test]
async fn tripped_breaker_never_falls_back_to_banned_builder() {
    let Some(harness) = gloas_harness(ChainConfig {
        // A single missed payload trips the consecutive rule.
        builder_fallback_skips: 0,
        ..ChainConfig::default()
    }) else {
        return;
    };
    Box::pin(finalize(&harness)).await;

    // Builder A withholds the payload for a well-attested block: it is banned on this chain, and
    // the missed payload trips the breaker for the next proposal.
    let block = Box::pin(import_builder_block(&harness, true)).await;
    harness.advance_slot();
    harness.chain.per_slot_task().await;
    assert_eq!(harness.chain.circuit_breaker.num_ban_entries(), 1);
    let slot = harness.get_current_slot();

    // With the local build failing, builder A's bid is still refused, so production fails.
    assert_breaker_tripped(&harness, &block.post_state, slot).await;
    fail_local_builds_on(&harness, empty_parent_block_hash(&block.post_state));
    observe_gossip_bid(
        &harness,
        &block.post_state,
        PayloadStatus::Empty,
        BUILDER_A,
        BID_VALUE,
    );
    let result = Box::pin(harness.try_make_gloas_block_with_envelope_on(
        block.post_state.clone(),
        slot,
        PayloadStatus::Empty,
    ))
    .await;
    assert!(
        matches!(result, Err(BlockProductionError::NoViablePayloadBid)),
        "production should fail with no viable bid"
    );

    // An unbanned builder's bid is an acceptable fallback.
    let (block_contents, _post_state) = Box::pin(harness.make_block_with_gossip_bid(
        block.post_state,
        slot,
        PayloadStatus::Empty,
        BUILDER_B,
        BID_VALUE + 1,
    ))
    .await;
    assert_eq!(block_builder_index(&block_contents.0), BUILDER_B);
}
