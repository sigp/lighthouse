use beacon_chain::{
    test_utils::{AttestationStrategy, BlockStrategy},
    GossipVerifiedBlock,
};
use eth2::types::{BeaconBlock, BroadcastValidation, SignedBeaconBlock};
use http_api::test_utils::InteractiveTester;
use std::sync::Arc;
use types::{Epoch, MainnetEthSpec, Slot, H256};

use eth2::reqwest::StatusCode;

type E = MainnetEthSpec;

/*
 * We have the following test cases:
 *
 * -  `broadcast_validation=gossip`
 *   -  Invalid (400)
 *   -  Full Pass (200)
 *   -  Partial Pass (202)
 *  -  `broadcast_validation=consensus`
 *    -  Invalid (400)
 *    -  Only gossip (400)
 *    -  Only consensus pass (i.e., equivocates) (200)
 *    -  Full pass (200)
 *  -  `broadcast_validation=consensus_and_equivocation`
 *    -  Invalid (400)
 *    -  Invalid due to early equivocation (400)
 *    -  Only gossip (400)
 *    -  Only consensus (400)
 *    -  Pass (200)
 *
 */

/// This test checks that a block that is **invalid** from a gossip perspective gets rejected when using `broadcast_validation=gossip`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn gossip_invalid() {
    /* this test targets gossip-level validation */
    let validation_level: Option<BroadcastValidation> = Some(BroadcastValidation::Gossip);

    // Validator count needs to be at least 32 or proposer boost gets set to 0 when computing
    // `validator_count // 32`.
    let validator_count = 64;
    let num_initial: u64 = 31;
    let tester = InteractiveTester::<E>::new(None, validator_count).await;

    // Create some chain depth.
    tester.harness.advance_slot();
    tester
        .harness
        .extend_chain(
            num_initial as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let chain_state_before = tester.harness.get_current_state();
    let slot = chain_state_before.slot() + 1;

    tester.harness.advance_slot();

    let (block, _): (SignedBeaconBlock<E>, _) = tester
        .harness
        .make_block_with_modifier(chain_state_before, slot, |b| {
            *b.state_root_mut() = H256::zero();
            *b.parent_root_mut() = H256::zero();
        })
        .await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&block, validation_level)
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    /* mandated by Beacon API spec */
    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));

    assert!(
        matches!(error_response, eth2::Error::ServerMessage(err) if err.message == "BAD_REQUEST: NotFinalizedDescendant { block_parent_root: 0x0000000000000000000000000000000000000000000000000000000000000000 }".to_string())
    );
}

/// This test checks that a block that is valid from a gossip perspective is accepted when using `broadcast_validation=gossip`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn gossip_partial_pass() {
    /* this test targets gossip-level validation */
    let validation_level: Option<BroadcastValidation> = Some(BroadcastValidation::Gossip);

    // Validator count needs to be at least 32 or proposer boost gets set to 0 when computing
    // `validator_count // 32`.
    let validator_count = 64;
    let num_initial: u64 = 31;
    let tester = InteractiveTester::<E>::new(None, validator_count).await;

    // Create some chain depth.
    tester.harness.advance_slot();
    tester
        .harness
        .extend_chain(
            num_initial as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let chain_state_before = tester.harness.get_current_state();
    let slot = chain_state_before.slot() + 1;

    tester.harness.advance_slot();

    let (block, _): (SignedBeaconBlock<E>, _) = tester
        .harness
        .make_block_with_modifier(chain_state_before, slot, |b| {
            *b.state_root_mut() = H256::random()
        })
        .await;

    /* assert that the block is actually gossip-valid */
    //assert!(GossipVerifiedBlock::new(Arc::new(block.clone()), &tester.harness.chain).is_ok());

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&block, validation_level)
        .await;
    assert!(response.is_ok());
}

// This test checks that a block that is valid from both a gossip and consensus perspective is accepted when using `broadcast_validation=gossip`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn gossip_full_pass() {
    /* this test targets gossip-level validation */
    let validation_level: Option<BroadcastValidation> = Some(BroadcastValidation::Gossip);

    // Validator count needs to be at least 32 or proposer boost gets set to 0 when computing
    // `validator_count // 32`.
    let validator_count = 64;
    let num_initial: u64 = 31;
    let tester = InteractiveTester::<E>::new(None, validator_count).await;

    // Create some chain depth.
    tester.harness.advance_slot();
    tester
        .harness
        .extend_chain(
            num_initial as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;

    let state_a = tester.harness.get_current_state();
    let (block, _): (SignedBeaconBlock<E>, _) = tester.harness.make_block(state_a, slot_b).await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&block, validation_level)
        .await;
    assert!(response.is_ok());
}

/// This test checks that a block that is only valid from a gossip perspective is rejected when using `broadcast_validation=consensus`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn consensus_gossip() {
    /* this test targets gossip-level validation */
    let validation_level: Option<BroadcastValidation> = Some(BroadcastValidation::Consensus);

    // Validator count needs to be at least 32 or proposer boost gets set to 0 when computing
    // `validator_count // 32`.
    let validator_count = 64;
    let num_initial: u64 = 31;
    let tester = InteractiveTester::<E>::new(None, validator_count).await;

    // Create some chain depth.
    tester.harness.advance_slot();
    tester
        .harness
        .extend_chain(
            num_initial as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;

    let state_a = tester.harness.get_current_state();
    let (mut block, _): (SignedBeaconBlock<E>, _) =
        tester.harness.make_block(state_a, slot_b).await;

    /* an incorrect proposer index should cause consensus checks to fail (due to
        https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
    ), which is the aim of this test */
    *block.message_mut().proposer_index_mut() += 1;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&block, validation_level)
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    /* mandated by Beacon API spec */
    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));

    assert!(
        matches!(error_response, eth2::Error::ServerMessage(err) if err.message == "BAD_REQUEST: FutureSlot { present_slot: Slot(31), block_slot: Slot(32) }".to_string())
    );
}

/// This test checks that a block that is valid from both a gossip and consensus perspective is accepted when using `broadcast_validation=consensus`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn consensus_partial_pass_only_consensus() {
    /* this test targets gossip-level validation */
    let validation_level: Option<BroadcastValidation> = Some(BroadcastValidation::Consensus);

    // Validator count needs to be at least 32 or proposer boost gets set to 0 when computing
    // `validator_count // 32`.
    let validator_count = 64;
    let num_initial: u64 = 31;
    let tester = InteractiveTester::<E>::new(None, validator_count).await;

    // Create some chain depth.
    tester.harness.advance_slot();
    tester
        .harness
        .extend_chain(
            num_initial as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;

    let state_a = tester.harness.get_current_state();
    let (block, _): (SignedBeaconBlock<E>, _) = tester.harness.make_block(state_a, slot_b).await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&block, validation_level)
        .await;
    assert!(response.is_ok());
}
