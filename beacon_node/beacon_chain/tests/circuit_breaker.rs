//! Tests for the post-Gloas builder circuit breaker: the missed-payload skip rules that gate
//! external bids during block production, and the bans recorded for builders that fail to reveal.

use beacon_chain::ChainConfig;
use beacon_chain::circuit_breaker::BanEntry;
use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
    PayloadAttestationVote, fork_name_from_env, test_spec,
};
use bls::PublicKeyBytes;
use fork_choice::PayloadVerificationStatus;
use proto_array::PayloadStatus;
use std::sync::Arc;
use types::consts::gloas::BUILDER_INDEX_SELF_BUILD;
use types::{BeaconState, BuilderIndex, EthSpec, Hash256, MinimalEthSpec, SignedBeaconBlock, Slot};

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

/// What `import_builder_block` produced: the block at `slot`, the state after it, and the head
/// state it was built on (useful for building a competing fork).
struct BuilderBlock {
    root: Hash256,
    slot: Slot,
    post_state: BeaconState<E>,
    pre_state: BeaconState<E>,
}

/// Import a block carrying builder A's bid at the next slot. With `attest`, every validator in
/// that slot's committees attests to it, which is well above the builder payment quorum.
async fn import_builder_block(harness: &Harness, attest: bool) -> BuilderBlock {
    harness.advance_slot();
    let slot = harness.get_current_slot();
    let pre_state = harness.get_current_state();
    let (block_contents, post_state) = Box::pin(harness.make_block_with_gossip_bid(
        pre_state.clone(),
        slot,
        PayloadStatus::Full,
        BUILDER_A,
        BID_VALUE,
    ))
    .await;
    let root = block_contents.0.canonical_root();
    let state_root = block_contents.0.state_root();
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
        post_state,
        pre_state,
    }
}

/// Build `count` self-built blocks in consecutive slots and never process their envelopes, so
/// each one's payload goes missing. Returns the state after the last block.
async fn withhold_payloads(harness: &Harness, count: usize) -> BeaconState<E> {
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

/// Produce a block at the next slot on `state` with a gossip bid from `builder_index` in the
/// cache, and return the builder index that won.
async fn produce_with_gossip_bid(
    harness: &Harness,
    state: BeaconState<E>,
    parent_payload_status: PayloadStatus,
    builder_index: BuilderIndex,
    value: u64,
) -> BuilderIndex {
    let slot = harness.get_current_slot();
    let signed_bid =
        harness.make_signed_gossip_bid(&state, slot, parent_payload_status, builder_index, value);
    assert!(harness.chain.gossip_verified_payload_bid_cache.observe_bid(
        beacon_chain::payload_bid_verification::gossip_verified_bid::GossipVerifiedPayloadBid {
            signed_bid: Arc::new(signed_bid),
        }
    ));
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
