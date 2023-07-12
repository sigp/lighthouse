use beacon_chain::{
    test_utils::{AttestationStrategy, BlockStrategy},
    GossipVerifiedBlock,
};
use eth2::types::{BroadcastValidation, SignedBeaconBlock, SignedBlindedBeaconBlock};
use http_api::test_utils::InteractiveTester;
use http_api::{publish_blinded_block, publish_block, reconstruct_block, ProvenancedBlock};
use tree_hash::TreeHash;
use types::{Hash256, MainnetEthSpec, Slot};
use warp::Rejection;
use warp_utils::reject::CustomBadRequest;

use eth2::reqwest::StatusCode;

type E = MainnetEthSpec;

/*
 * We have the following test cases, which are duplicated for the blinded variant of the route:
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
            *b.state_root_mut() = Hash256::zero();
            *b.parent_root_mut() = Hash256::zero();
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
            *b.state_root_mut() = Hash256::random()
        })
        .await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&block, validation_level)
        .await;
    assert!(response.is_err());

    let error_response = response.unwrap_err();

    assert_eq!(error_response.status(), Some(StatusCode::ACCEPTED));
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
    tester.harness.advance_slot();

    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;

    let state_a = tester.harness.get_current_state();
    let (block, _): (SignedBeaconBlock<E>, _) = tester.harness.make_block(state_a, slot_b).await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&block, validation_level)
        .await;

    assert!(response.is_ok());
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block.canonical_root()));
}

/// This test checks that a block that is **invalid** from a gossip perspective gets rejected when using `broadcast_validation=consensus`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn consensus_invalid() {
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

    let chain_state_before = tester.harness.get_current_state();
    let slot = chain_state_before.slot() + 1;

    tester.harness.advance_slot();

    let (block, _): (SignedBeaconBlock<E>, _) = tester
        .harness
        .make_block_with_modifier(chain_state_before, slot, |b| {
            *b.state_root_mut() = Hash256::zero();
            *b.parent_root_mut() = Hash256::zero();
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
    tester.harness.advance_slot();

    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;

    let state_a = tester.harness.get_current_state();
    let (block, _): (SignedBeaconBlock<E>, _) = tester
        .harness
        .make_block_with_modifier(state_a, slot_b, |b| *b.state_root_mut() = Hash256::zero())
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
        matches!(error_response, eth2::Error::ServerMessage(err) if err.message == "BAD_REQUEST: Invalid block: StateRootMismatch { block: 0x0000000000000000000000000000000000000000000000000000000000000000, local: 0xfc675d642ff7a06458eb33c7d7b62a5813e34d1b2bb1aee3e395100b579da026 }".to_string())
    );
}

/// This test checks that a block that is valid from both a gossip and consensus perspective, but nonetheless equivocates, is accepted when using `broadcast_validation=consensus`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn consensus_partial_pass_only_consensus() {
    /* this test targets gossip-level validation */
    let validation_level: Option<BroadcastValidation> = Some(BroadcastValidation::Consensus);

    // Validator count needs to be at least 32 or proposer boost gets set to 0 when computing
    // `validator_count // 32`.
    let validator_count = 64;
    let num_initial: u64 = 31;
    let tester = InteractiveTester::<E>::new(None, validator_count).await;
    let test_logger = tester.harness.logger().clone();

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
    tester.harness.advance_slot();

    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;

    let state_a = tester.harness.get_current_state();
    let (block_a, state_after_a): (SignedBeaconBlock<E>, _) =
        tester.harness.make_block(state_a.clone(), slot_b).await;
    let (block_b, state_after_b): (SignedBeaconBlock<E>, _) =
        tester.harness.make_block(state_a, slot_b).await;

    /* check for `make_block` curios */
    assert_eq!(block_a.state_root(), state_after_a.tree_hash_root());
    assert_eq!(block_b.state_root(), state_after_b.tree_hash_root());
    assert_ne!(block_a.state_root(), block_b.state_root());

    let gossip_block_b = GossipVerifiedBlock::new(block_b.clone().into(), &tester.harness.chain);
    assert!(gossip_block_b.is_ok());
    let gossip_block_a = GossipVerifiedBlock::new(block_a.clone().into(), &tester.harness.chain);
    assert!(gossip_block_a.is_err());

    /* submit `block_b` which should induce equivocation */
    let channel = tokio::sync::mpsc::unbounded_channel();

    let publication_result: Result<(), Rejection> = publish_block(
        None,
        ProvenancedBlock::local(gossip_block_b.unwrap()),
        tester.harness.chain.clone(),
        &channel.0,
        test_logger,
        validation_level.unwrap(),
    )
    .await;

    assert!(publication_result.is_ok());
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block_b.canonical_root()));
}

/// This test checks that a block that is valid from both a gossip and consensus perspective is accepted when using `broadcast_validation=consensus`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn consensus_full_pass() {
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
    tester.harness.advance_slot();

    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;

    let state_a = tester.harness.get_current_state();
    let (block, _): (SignedBeaconBlock<E>, _) = tester.harness.make_block(state_a, slot_b).await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&block, validation_level)
        .await;

    assert!(response.is_ok());
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block.canonical_root()));
}

/// This test checks that a block that is **invalid** from a gossip perspective gets rejected when using `broadcast_validation=consensus_and_equivocation`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn equivocation_invalid() {
    /* this test targets gossip-level validation */
    let validation_level: Option<BroadcastValidation> =
        Some(BroadcastValidation::ConsensusAndEquivocation);

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
            *b.state_root_mut() = Hash256::zero();
            *b.parent_root_mut() = Hash256::zero();
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

/// This test checks that a block that is valid from both a gossip and consensus perspective is rejected when using `broadcast_validation=consensus_and_equivocation`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn equivocation_consensus_early_equivocation() {
    /* this test targets gossip-level validation */
    let validation_level: Option<BroadcastValidation> =
        Some(BroadcastValidation::ConsensusAndEquivocation);

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
    tester.harness.advance_slot();

    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;

    let state_a = tester.harness.get_current_state();
    let (block_a, state_after_a): (SignedBeaconBlock<E>, _) =
        tester.harness.make_block(state_a.clone(), slot_b).await;
    let (block_b, state_after_b): (SignedBeaconBlock<E>, _) =
        tester.harness.make_block(state_a, slot_b).await;

    /* check for `make_block` curios */
    assert_eq!(block_a.state_root(), state_after_a.tree_hash_root());
    assert_eq!(block_b.state_root(), state_after_b.tree_hash_root());
    assert_ne!(block_a.state_root(), block_b.state_root());

    /* submit `block_a` as valid */
    assert!(tester
        .client
        .post_beacon_blocks_v2(&block_a, validation_level)
        .await
        .is_ok());
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block_a.canonical_root()));

    /* submit `block_b` which should induce equivocation */
    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&block_b, validation_level)
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));

    assert!(
        matches!(error_response, eth2::Error::ServerMessage(err) if err.message ==  "BAD_REQUEST: Slashable".to_string())
    );
}

/// This test checks that a block that is only valid from a gossip perspective is rejected when using `broadcast_validation=consensus_and_equivocation`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn equivocation_gossip() {
    /* this test targets gossip-level validation */
    let validation_level: Option<BroadcastValidation> =
        Some(BroadcastValidation::ConsensusAndEquivocation);

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
    tester.harness.advance_slot();

    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;

    let state_a = tester.harness.get_current_state();
    let (block, _): (SignedBeaconBlock<E>, _) = tester
        .harness
        .make_block_with_modifier(state_a, slot_b, |b| *b.state_root_mut() = Hash256::zero())
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
        matches!(error_response, eth2::Error::ServerMessage(err) if err.message == "BAD_REQUEST: Invalid block: StateRootMismatch { block: 0x0000000000000000000000000000000000000000000000000000000000000000, local: 0xfc675d642ff7a06458eb33c7d7b62a5813e34d1b2bb1aee3e395100b579da026 }".to_string())
    );
}

/// This test checks that a block that is valid from both a gossip and consensus perspective but that equivocates **late** is rejected when using `broadcast_validation=consensus_and_equivocation`.
///
/// This test is unique in that we can't actually test the HTTP API directly, but instead have to hook into the `publish_blocks` code manually. This is in order to handle the late equivocation case.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn equivocation_consensus_late_equivocation() {
    /* this test targets gossip-level validation */
    let validation_level: Option<BroadcastValidation> =
        Some(BroadcastValidation::ConsensusAndEquivocation);

    // Validator count needs to be at least 32 or proposer boost gets set to 0 when computing
    // `validator_count // 32`.
    let validator_count = 64;
    let num_initial: u64 = 31;
    let tester = InteractiveTester::<E>::new(None, validator_count).await;
    let test_logger = tester.harness.logger().clone();

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
    tester.harness.advance_slot();

    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;

    let state_a = tester.harness.get_current_state();
    let (block_a, state_after_a): (SignedBeaconBlock<E>, _) =
        tester.harness.make_block(state_a.clone(), slot_b).await;
    let (block_b, state_after_b): (SignedBeaconBlock<E>, _) =
        tester.harness.make_block(state_a, slot_b).await;

    /* check for `make_block` curios */
    assert_eq!(block_a.state_root(), state_after_a.tree_hash_root());
    assert_eq!(block_b.state_root(), state_after_b.tree_hash_root());
    assert_ne!(block_a.state_root(), block_b.state_root());

    let gossip_block_b = GossipVerifiedBlock::new(block_b.clone().into(), &tester.harness.chain);
    assert!(gossip_block_b.is_ok());
    let gossip_block_a = GossipVerifiedBlock::new(block_a.clone().into(), &tester.harness.chain);
    assert!(gossip_block_a.is_err());

    let channel = tokio::sync::mpsc::unbounded_channel();

    let publication_result: Result<(), Rejection> = publish_block(
        None,
        ProvenancedBlock::local(gossip_block_b.unwrap()),
        tester.harness.chain,
        &channel.0,
        test_logger,
        validation_level.unwrap(),
    )
    .await;

    assert!(publication_result.is_err());

    let publication_error = publication_result.unwrap_err();

    assert!(publication_error.find::<CustomBadRequest>().is_some());

    assert_eq!(
        *publication_error.find::<CustomBadRequest>().unwrap().0,
        "proposal for this slot and proposer has already been seen".to_string()
    );
}

/// This test checks that a block that is valid from both a gossip and consensus perspective (and does not equivocate) is accepted when using `broadcast_validation=consensus_and_equivocation`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn equivocation_full_pass() {
    /* this test targets gossip-level validation */
    let validation_level: Option<BroadcastValidation> =
        Some(BroadcastValidation::ConsensusAndEquivocation);

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
    tester.harness.advance_slot();

    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;

    let state_a = tester.harness.get_current_state();
    let (block, _): (SignedBeaconBlock<E>, _) = tester.harness.make_block(state_a, slot_b).await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&block, validation_level)
        .await;

    assert!(response.is_ok());
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block.canonical_root()));
}

/// This test checks that a block that is **invalid** from a gossip perspective gets rejected when using `broadcast_validation=gossip`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn blinded_gossip_invalid() {
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
            *b.state_root_mut() = Hash256::zero();
            *b.parent_root_mut() = Hash256::zero();
        })
        .await;

    let blinded_block: SignedBlindedBeaconBlock<E> = block.into();

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blinded_blocks_v2(&blinded_block, validation_level)
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
pub async fn blinded_gossip_partial_pass() {
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
            *b.state_root_mut() = Hash256::zero()
        })
        .await;

    let blinded_block: SignedBlindedBeaconBlock<E> = block.into();

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blinded_blocks_v2(&blinded_block, validation_level)
        .await;
    assert!(response.is_err());

    let error_response = response.unwrap_err();

    assert_eq!(error_response.status(), Some(StatusCode::ACCEPTED));
}

// This test checks that a block that is valid from both a gossip and consensus perspective is accepted when using `broadcast_validation=gossip`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn blinded_gossip_full_pass() {
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
    tester.harness.advance_slot();

    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;

    let state_a = tester.harness.get_current_state();
    let (block, _): (SignedBlindedBeaconBlock<E>, _) =
        tester.harness.make_blinded_block(state_a, slot_b).await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blinded_blocks_v2(&block, validation_level)
        .await;

    assert!(response.is_ok());
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block.canonical_root()));
}

/// This test checks that a block that is **invalid** from a gossip perspective gets rejected when using `broadcast_validation=consensus`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn blinded_consensus_invalid() {
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

    let chain_state_before = tester.harness.get_current_state();
    let slot = chain_state_before.slot() + 1;

    tester.harness.advance_slot();

    let (block, _): (SignedBeaconBlock<E>, _) = tester
        .harness
        .make_block_with_modifier(chain_state_before, slot, |b| {
            *b.state_root_mut() = Hash256::zero();
            *b.parent_root_mut() = Hash256::zero();
        })
        .await;

    let blinded_block: SignedBlindedBeaconBlock<E> = block.into();

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blinded_blocks_v2(&blinded_block, validation_level)
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    /* mandated by Beacon API spec */
    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));

    assert!(
        matches!(error_response, eth2::Error::ServerMessage(err) if err.message == "BAD_REQUEST: NotFinalizedDescendant { block_parent_root: 0x0000000000000000000000000000000000000000000000000000000000000000 }".to_string())
    );
}

/// This test checks that a block that is only valid from a gossip perspective is rejected when using `broadcast_validation=consensus`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn blinded_consensus_gossip() {
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
    tester.harness.advance_slot();

    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;

    let state_a = tester.harness.get_current_state();
    let (block, _): (SignedBeaconBlock<E>, _) = tester
        .harness
        .make_block_with_modifier(state_a, slot_b, |b| *b.state_root_mut() = Hash256::zero())
        .await;

    let blinded_block: SignedBlindedBeaconBlock<E> = block.into();

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blinded_blocks_v2(&blinded_block, validation_level)
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    /* mandated by Beacon API spec */
    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));

    assert!(
        matches!(error_response, eth2::Error::ServerMessage(err) if err.message == "BAD_REQUEST: Invalid block: StateRootMismatch { block: 0x0000000000000000000000000000000000000000000000000000000000000000, local: 0xfc675d642ff7a06458eb33c7d7b62a5813e34d1b2bb1aee3e395100b579da026 }".to_string())
    );
}

/// This test checks that a block that is valid from both a gossip and consensus perspective is accepted when using `broadcast_validation=consensus`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn blinded_consensus_full_pass() {
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
    tester.harness.advance_slot();

    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;

    let state_a = tester.harness.get_current_state();
    let (block, _): (SignedBlindedBeaconBlock<E>, _) =
        tester.harness.make_blinded_block(state_a, slot_b).await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blinded_blocks_v2(&block, validation_level)
        .await;

    assert!(response.is_ok());
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block.canonical_root()));
}

/// This test checks that a block that is **invalid** from a gossip perspective gets rejected when using `broadcast_validation=consensus_and_equivocation`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn blinded_equivocation_invalid() {
    /* this test targets gossip-level validation */
    let validation_level: Option<BroadcastValidation> =
        Some(BroadcastValidation::ConsensusAndEquivocation);

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
            *b.state_root_mut() = Hash256::zero();
            *b.parent_root_mut() = Hash256::zero();
        })
        .await;

    let blinded_block: SignedBlindedBeaconBlock<E> = block.into();

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blinded_blocks_v2(&blinded_block, validation_level)
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    /* mandated by Beacon API spec */
    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));

    assert!(
        matches!(error_response, eth2::Error::ServerMessage(err) if err.message == "BAD_REQUEST: NotFinalizedDescendant { block_parent_root: 0x0000000000000000000000000000000000000000000000000000000000000000 }".to_string())
    );
}

/// This test checks that a block that is valid from both a gossip and consensus perspective is rejected when using `broadcast_validation=consensus_and_equivocation`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn blinded_equivocation_consensus_early_equivocation() {
    /* this test targets gossip-level validation */
    let validation_level: Option<BroadcastValidation> =
        Some(BroadcastValidation::ConsensusAndEquivocation);

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
    tester.harness.advance_slot();

    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;

    let state_a = tester.harness.get_current_state();
    let (block_a, state_after_a): (SignedBlindedBeaconBlock<E>, _) = tester
        .harness
        .make_blinded_block(state_a.clone(), slot_b)
        .await;
    let (block_b, state_after_b): (SignedBlindedBeaconBlock<E>, _) =
        tester.harness.make_blinded_block(state_a, slot_b).await;

    /* check for `make_blinded_block` curios */
    assert_eq!(block_a.state_root(), state_after_a.tree_hash_root());
    assert_eq!(block_b.state_root(), state_after_b.tree_hash_root());
    assert_ne!(block_a.state_root(), block_b.state_root());

    /* submit `block_a` as valid */
    assert!(tester
        .client
        .post_beacon_blinded_blocks_v2(&block_a, validation_level)
        .await
        .is_ok());
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block_a.canonical_root()));

    /* submit `block_b` which should induce equivocation */
    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blinded_blocks_v2(&block_b, validation_level)
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));

    assert!(
        matches!(error_response, eth2::Error::ServerMessage(err) if err.message ==  "BAD_REQUEST: Slashable".to_string())
    );
}

/// This test checks that a block that is only valid from a gossip perspective is rejected when using `broadcast_validation=consensus_and_equivocation`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn blinded_equivocation_gossip() {
    /* this test targets gossip-level validation */
    let validation_level: Option<BroadcastValidation> =
        Some(BroadcastValidation::ConsensusAndEquivocation);

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
    tester.harness.advance_slot();

    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;

    let state_a = tester.harness.get_current_state();
    let (block, _): (SignedBeaconBlock<E>, _) = tester
        .harness
        .make_block_with_modifier(state_a, slot_b, |b| *b.state_root_mut() = Hash256::zero())
        .await;

    let blinded_block: SignedBlindedBeaconBlock<E> = block.into();

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blinded_blocks_v2(&blinded_block, validation_level)
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    /* mandated by Beacon API spec */
    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));

    assert!(
        matches!(error_response, eth2::Error::ServerMessage(err) if err.message == "BAD_REQUEST: Invalid block: StateRootMismatch { block: 0x0000000000000000000000000000000000000000000000000000000000000000, local: 0xfc675d642ff7a06458eb33c7d7b62a5813e34d1b2bb1aee3e395100b579da026 }".to_string())
    );
}

/// This test checks that a block that is valid from both a gossip and consensus perspective but that equivocates **late** is rejected when using `broadcast_validation=consensus_and_equivocation`.
///
/// This test is unique in that we can't actually test the HTTP API directly, but instead have to hook into the `publish_blocks` code manually. This is in order to handle the late equivocation case.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn blinded_equivocation_consensus_late_equivocation() {
    /* this test targets gossip-level validation */
    let validation_level: Option<BroadcastValidation> =
        Some(BroadcastValidation::ConsensusAndEquivocation);

    // Validator count needs to be at least 32 or proposer boost gets set to 0 when computing
    // `validator_count // 32`.
    let validator_count = 64;
    let num_initial: u64 = 31;
    let tester = InteractiveTester::<E>::new(None, validator_count).await;
    let test_logger = tester.harness.logger().clone();

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
    tester.harness.advance_slot();

    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;

    let state_a = tester.harness.get_current_state();
    let (block_a, state_after_a): (SignedBlindedBeaconBlock<E>, _) = tester
        .harness
        .make_blinded_block(state_a.clone(), slot_b)
        .await;
    let (block_b, state_after_b): (SignedBlindedBeaconBlock<E>, _) =
        tester.harness.make_blinded_block(state_a, slot_b).await;

    /* check for `make_blinded_block` curios */
    assert_eq!(block_a.state_root(), state_after_a.tree_hash_root());
    assert_eq!(block_b.state_root(), state_after_b.tree_hash_root());
    assert_ne!(block_a.state_root(), block_b.state_root());

    let unblinded_block_a = reconstruct_block(
        tester.harness.chain.clone(),
        block_a.state_root(),
        block_a,
        test_logger.clone(),
    )
    .await
    .unwrap();
    let unblinded_block_b = reconstruct_block(
        tester.harness.chain.clone(),
        block_b.clone().state_root(),
        block_b.clone(),
        test_logger.clone(),
    )
    .await
    .unwrap();

    let inner_block_a = match unblinded_block_a {
        ProvenancedBlock::Local(a, _) => a,
        ProvenancedBlock::Builder(a, _) => a,
    };
    let inner_block_b = match unblinded_block_b {
        ProvenancedBlock::Local(b, _) => b,
        ProvenancedBlock::Builder(b, _) => b,
    };

    let gossip_block_b = GossipVerifiedBlock::new(inner_block_b, &tester.harness.chain);
    assert!(gossip_block_b.is_ok());
    let gossip_block_a = GossipVerifiedBlock::new(inner_block_a, &tester.harness.chain);
    assert!(gossip_block_a.is_err());

    let channel = tokio::sync::mpsc::unbounded_channel();

    let publication_result: Result<(), Rejection> = publish_blinded_block(
        block_b,
        tester.harness.chain,
        &channel.0,
        test_logger,
        validation_level.unwrap(),
    )
    .await;

    assert!(publication_result.is_err());

    let publication_error: Rejection = publication_result.unwrap_err();

    assert!(publication_error.find::<CustomBadRequest>().is_some());
}

/// This test checks that a block that is valid from both a gossip and consensus perspective (and does not equivocate) is accepted when using `broadcast_validation=consensus_and_equivocation`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn blinded_equivocation_full_pass() {
    /* this test targets gossip-level validation */
    let validation_level: Option<BroadcastValidation> =
        Some(BroadcastValidation::ConsensusAndEquivocation);

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
    tester.harness.advance_slot();

    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;

    let state_a = tester.harness.get_current_state();
    let (block, _): (SignedBlindedBeaconBlock<E>, _) =
        tester.harness.make_blinded_block(state_a, slot_b).await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&block, validation_level)
        .await;

    assert!(response.is_ok());
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block.canonical_root()));
}
