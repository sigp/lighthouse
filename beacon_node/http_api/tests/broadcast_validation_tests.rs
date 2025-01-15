use beacon_chain::blob_verification::GossipVerifiedBlob;
use beacon_chain::{
    test_utils::{AttestationStrategy, BlockStrategy},
    GossipVerifiedBlock, IntoGossipVerifiedBlock,
};
use eth2::reqwest::StatusCode;
use eth2::types::{BroadcastValidation, PublishBlockRequest};
use http_api::test_utils::InteractiveTester;
use http_api::{publish_blinded_block, publish_block, reconstruct_block, Config, ProvenancedBlock};
use std::sync::Arc;
use types::{
    BlobSidecar, Epoch, EthSpec, FixedBytesExtended, ForkName, Hash256, MainnetEthSpec, Slot,
};
use warp::Rejection;
use warp_utils::reject::CustomBadRequest;

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

    let ((block, blobs), _) = tester
        .harness
        .make_block_with_modifier(chain_state_before, slot, |b| {
            *b.state_root_mut() = Hash256::zero();
            *b.parent_root_mut() = Hash256::zero();
        })
        .await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&PublishBlockRequest::new(block, blobs), validation_level)
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    /* mandated by Beacon API spec */
    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));

    assert_server_message_error(error_response, "BAD_REQUEST: NotFinalizedDescendant { block_parent_root: 0x0000000000000000000000000000000000000000000000000000000000000000 }".to_string());
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

    let ((block, blobs), _) = tester
        .harness
        .make_block_with_modifier(chain_state_before, slot, |b| {
            *b.state_root_mut() = Hash256::random()
        })
        .await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&PublishBlockRequest::new(block, blobs), validation_level)
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
    let ((block, blobs), _) = tester.harness.make_block(state_a, slot_b).await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(
            &PublishBlockRequest::new(block.clone(), blobs),
            validation_level,
        )
        .await;

    assert!(response.is_ok());
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block.canonical_root()));
}

// This test checks that a block that is valid from both a gossip and consensus perspective is accepted when using `broadcast_validation=gossip`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn gossip_full_pass_ssz() {
    /* this test targets gossip-level validation */
    let validation_level: Option<BroadcastValidation> = Some(BroadcastValidation::Gossip);

    // Validator count needs to be at least 32 or proposer boost gets set to 0 when computing
    // `validator_count // 32`.
    let validator_count = 64;
    let num_initial: u64 = 31;
    // Deneb epoch set ahead of block slot, to test fork-based decoding
    let mut spec = ForkName::Capella.make_genesis_spec(MainnetEthSpec::default_spec());
    spec.deneb_fork_epoch = Some(Epoch::new(4));
    let tester = InteractiveTester::<E>::new(Some(spec), validator_count).await;

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
    let (block_contents_tuple, _) = tester.harness.make_block(state_a, slot_b).await;
    let block_contents = block_contents_tuple.into();

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2_ssz(&block_contents, validation_level)
        .await;

    assert!(response.is_ok());
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block_contents.signed_block().canonical_root()));
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

    let ((block, blobs), _) = tester
        .harness
        .make_block_with_modifier(chain_state_before, slot, |b| {
            *b.state_root_mut() = Hash256::zero();
            *b.parent_root_mut() = Hash256::zero();
        })
        .await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&PublishBlockRequest::new(block, blobs), validation_level)
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    /* mandated by Beacon API spec */
    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));
    assert_server_message_error(error_response, "BAD_REQUEST: NotFinalizedDescendant { block_parent_root: 0x0000000000000000000000000000000000000000000000000000000000000000 }".to_string());
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
    let ((block, blobs), _) = tester
        .harness
        .make_block_with_modifier(state_a, slot_b, |b| *b.state_root_mut() = Hash256::zero())
        .await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&PublishBlockRequest::new(block, blobs), validation_level)
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    /* mandated by Beacon API spec */
    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));
    assert_server_message_error(error_response, "BAD_REQUEST: Invalid block: StateRootMismatch { block: 0x0000000000000000000000000000000000000000000000000000000000000000, local: 0xfc675d642ff7a06458eb33c7d7b62a5813e34d1b2bb1aee3e395100b579da026 }".to_string());
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
    let ((block_a, _), mut state_after_a) =
        tester.harness.make_block(state_a.clone(), slot_b).await;
    let ((block_b, blobs_b), mut state_after_b) = tester.harness.make_block(state_a, slot_b).await;
    let block_b_root = block_b.canonical_root();

    /* check for `make_block` curios */
    assert_eq!(
        block_a.state_root(),
        state_after_a.canonical_root().unwrap()
    );
    assert_eq!(
        block_b.state_root(),
        state_after_b.canonical_root().unwrap()
    );
    assert_ne!(block_a.state_root(), block_b.state_root());

    let gossip_block_b = block_b.into_gossip_verified_block(&tester.harness.chain);
    assert!(gossip_block_b.is_ok());
    let gossip_block_a = block_a.into_gossip_verified_block(&tester.harness.chain);
    assert!(gossip_block_a.is_err());

    /* submit `block_b` which should induce equivocation */
    let channel = tokio::sync::mpsc::unbounded_channel();
    let network_globals = tester.ctx.network_globals.clone().unwrap();

    let publication_result = publish_block(
        None,
        ProvenancedBlock::local(gossip_block_b.unwrap(), blobs_b),
        tester.harness.chain.clone(),
        &channel.0,
        test_logger,
        validation_level.unwrap(),
        StatusCode::ACCEPTED,
        network_globals,
    )
    .await;

    assert!(publication_result.is_ok(), "{publication_result:?}");
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block_b_root));
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
    let ((block, blobs), _) = tester.harness.make_block(state_a, slot_b).await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(
            &PublishBlockRequest::new(block.clone(), blobs),
            validation_level,
        )
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

    let ((block, blobs), _) = tester
        .harness
        .make_block_with_modifier(chain_state_before, slot, |b| {
            *b.state_root_mut() = Hash256::zero();
            *b.parent_root_mut() = Hash256::zero();
        })
        .await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&PublishBlockRequest::new(block, blobs), validation_level)
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    /* mandated by Beacon API spec */
    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));
    assert_server_message_error(error_response, "BAD_REQUEST: NotFinalizedDescendant { block_parent_root: 0x0000000000000000000000000000000000000000000000000000000000000000 }".to_string());
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
    let ((block_a, blobs_a), mut state_after_a) =
        tester.harness.make_block(state_a.clone(), slot_b).await;
    let ((block_b, blobs_b), mut state_after_b) = tester.harness.make_block(state_a, slot_b).await;

    /* check for `make_block` curios */
    assert_eq!(
        block_a.state_root(),
        state_after_a.canonical_root().unwrap()
    );
    assert_eq!(
        block_b.state_root(),
        state_after_b.canonical_root().unwrap()
    );
    assert_ne!(block_a.state_root(), block_b.state_root());

    /* submit `block_a` as valid */
    assert!(tester
        .client
        .post_beacon_blocks_v2(
            &PublishBlockRequest::new(block_a.clone(), blobs_a),
            validation_level
        )
        .await
        .is_ok());
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block_a.canonical_root()));

    /* submit `block_b` which should induce equivocation */
    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(
            &PublishBlockRequest::new(block_b.clone(), blobs_b),
            validation_level,
        )
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));
    assert_server_message_error(error_response, "BAD_REQUEST: Slashable".to_string());
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
    let ((block, blobs), _) = tester
        .harness
        .make_block_with_modifier(state_a, slot_b, |b| *b.state_root_mut() = Hash256::zero())
        .await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&PublishBlockRequest::new(block, blobs), validation_level)
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    /* mandated by Beacon API spec */
    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));
    assert_server_message_error(error_response, "BAD_REQUEST: Invalid block: StateRootMismatch { block: 0x0000000000000000000000000000000000000000000000000000000000000000, local: 0xfc675d642ff7a06458eb33c7d7b62a5813e34d1b2bb1aee3e395100b579da026 }".to_string());
}

/// This test checks that a block that is valid from both a gossip and consensus perspective but
/// that equivocates **late** is rejected when using `broadcast_validation=consensus_and_equivocation`.
///
/// This test is unique in that we can't actually test the HTTP API directly, but instead have to
/// hook into the `publish_blocks` code manually. This is in order to handle the late equivocation case.
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
    let ((block_a, _blobs_a), mut state_after_a) =
        tester.harness.make_block(state_a.clone(), slot_b).await;
    let ((block_b, blobs_b), mut state_after_b) = tester.harness.make_block(state_a, slot_b).await;

    /* check for `make_block` curios */
    assert_eq!(
        block_a.state_root(),
        state_after_a.canonical_root().unwrap()
    );
    assert_eq!(
        block_b.state_root(),
        state_after_b.canonical_root().unwrap()
    );
    assert_ne!(block_a.state_root(), block_b.state_root());

    let gossip_block_b = block_b.into_gossip_verified_block(&tester.harness.chain);
    assert!(gossip_block_b.is_ok());

    let gossip_block_a = block_a.into_gossip_verified_block(&tester.harness.chain);
    assert!(gossip_block_a.is_err());

    let channel = tokio::sync::mpsc::unbounded_channel();
    let network_globals = tester.ctx.network_globals.clone().unwrap();

    let publication_result = publish_block(
        None,
        ProvenancedBlock::local(gossip_block_b.unwrap(), blobs_b),
        tester.harness.chain,
        &channel.0,
        test_logger,
        validation_level.unwrap(),
        StatusCode::ACCEPTED,
        network_globals,
    )
    .await;

    assert!(publication_result.is_err());

    let publication_error = publication_result.unwrap_err();

    assert!(publication_error.find::<CustomBadRequest>().is_some());

    assert_eq!(
        publication_error.find::<CustomBadRequest>().unwrap().0,
        "proposal for this slot and proposer has already been seen"
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
    let ((block, blobs), _) = tester.harness.make_block(state_a, slot_b).await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(
            &PublishBlockRequest::new(block.clone(), blobs),
            validation_level,
        )
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

    let (block_contents_tuple, _) = tester
        .harness
        .make_block_with_modifier(chain_state_before, slot, |b| {
            *b.state_root_mut() = Hash256::zero();
            *b.parent_root_mut() = Hash256::zero();
        })
        .await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blinded_blocks_v2(&block_contents_tuple.0.clone_as_blinded(), validation_level)
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    /* mandated by Beacon API spec */
    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));
    assert_server_message_error(error_response, "BAD_REQUEST: NotFinalizedDescendant { block_parent_root: 0x0000000000000000000000000000000000000000000000000000000000000000 }".to_string());
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

    let (block_contents_tuple, _) = tester
        .harness
        .make_block_with_modifier(chain_state_before, slot, |b| {
            *b.state_root_mut() = Hash256::zero()
        })
        .await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blinded_blocks_v2(&block_contents_tuple.0.clone_as_blinded(), validation_level)
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
    let (blinded_block, _) = tester.harness.make_blinded_block(state_a, slot_b).await;
    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blinded_blocks_v2(&blinded_block, validation_level)
        .await;

    assert!(response.is_ok());
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&blinded_block.canonical_root()));
}

// This test checks that a block that is valid from both a gossip and consensus perspective is accepted when using `broadcast_validation=gossip`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn blinded_gossip_full_pass_ssz() {
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
    let (blinded_block, _) = tester.harness.make_blinded_block(state_a, slot_b).await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blinded_blocks_v2_ssz(&blinded_block, validation_level)
        .await;

    assert!(response.is_ok());
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&blinded_block.canonical_root()));
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

    let (block_contents_tuple, _) = tester
        .harness
        .make_block_with_modifier(chain_state_before, slot, |b| {
            *b.state_root_mut() = Hash256::zero();
            *b.parent_root_mut() = Hash256::zero();
        })
        .await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blinded_blocks_v2(&block_contents_tuple.0.clone_as_blinded(), validation_level)
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    /* mandated by Beacon API spec */
    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));
    assert_server_message_error(error_response, "BAD_REQUEST: NotFinalizedDescendant { block_parent_root: 0x0000000000000000000000000000000000000000000000000000000000000000 }".to_string());
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
    let (block_contents_tuple, _) = tester
        .harness
        .make_block_with_modifier(state_a, slot_b, |b| *b.state_root_mut() = Hash256::zero())
        .await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blinded_blocks_v2(&block_contents_tuple.0.clone_as_blinded(), validation_level)
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    /* mandated by Beacon API spec */
    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));
    assert_server_message_error(error_response, "BAD_REQUEST: Invalid block: StateRootMismatch { block: 0x0000000000000000000000000000000000000000000000000000000000000000, local: 0xfc675d642ff7a06458eb33c7d7b62a5813e34d1b2bb1aee3e395100b579da026 }".to_string());
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
    let (blinded_block, _) = tester.harness.make_blinded_block(state_a, slot_b).await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blinded_blocks_v2(&blinded_block, validation_level)
        .await;

    assert!(response.is_ok());
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&blinded_block.canonical_root()));
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

    let (block_contents_tuple, _) = tester
        .harness
        .make_block_with_modifier(chain_state_before, slot, |b| {
            *b.state_root_mut() = Hash256::zero();
            *b.parent_root_mut() = Hash256::zero();
        })
        .await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blinded_blocks_v2(&block_contents_tuple.0.clone_as_blinded(), validation_level)
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    /* mandated by Beacon API spec */
    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));
    assert_server_message_error(error_response, "BAD_REQUEST: NotFinalizedDescendant { block_parent_root: 0x0000000000000000000000000000000000000000000000000000000000000000 }".to_string());
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
    let (block_a, mut state_after_a) = tester
        .harness
        .make_blinded_block(state_a.clone(), slot_b)
        .await;
    let (block_b, mut state_after_b) = tester.harness.make_blinded_block(state_a, slot_b).await;

    /* check for `make_blinded_block` curios */
    assert_eq!(
        block_a.state_root(),
        state_after_a.canonical_root().unwrap()
    );
    assert_eq!(
        block_b.state_root(),
        state_after_b.canonical_root().unwrap()
    );
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
    assert_server_message_error(error_response, "BAD_REQUEST: Slashable".to_string());
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
    let (block_contents_tuple, _) = tester
        .harness
        .make_block_with_modifier(state_a, slot_b, |b| *b.state_root_mut() = Hash256::zero())
        .await;

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blinded_blocks_v2(&block_contents_tuple.0.clone_as_blinded(), validation_level)
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    /* mandated by Beacon API spec */
    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));

    assert_server_message_error(error_response, "BAD_REQUEST: Invalid block: StateRootMismatch { block: 0x0000000000000000000000000000000000000000000000000000000000000000, local: 0xfc675d642ff7a06458eb33c7d7b62a5813e34d1b2bb1aee3e395100b579da026 }".to_string());
}

/// This test checks that a block that is valid from both a gossip and
/// consensus perspective but that equivocates **late** is rejected when using
/// `broadcast_validation=consensus_and_equivocation`.
///
/// This test is unique in that we can't actually test the HTTP API directly,
/// but instead have to hook into the `publish_blocks` code manually. This is
/// in order to handle the late equivocation case.
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
    let (block_a, mut state_after_a) = tester
        .harness
        .make_blinded_block(state_a.clone(), slot_b)
        .await;
    let (block_b, mut state_after_b) = tester.harness.make_blinded_block(state_a, slot_b).await;
    let block_b = Arc::new(block_b);

    /* check for `make_blinded_block` curios */
    assert_eq!(
        block_a.state_root(),
        state_after_a.canonical_root().unwrap()
    );
    assert_eq!(
        block_b.state_root(),
        state_after_b.canonical_root().unwrap()
    );
    assert_ne!(block_a.state_root(), block_b.state_root());

    let unblinded_block_a = reconstruct_block(
        tester.harness.chain.clone(),
        block_a.canonical_root(),
        Arc::new(block_a),
        test_logger.clone(),
    )
    .await
    .unwrap();
    let unblinded_block_b = reconstruct_block(
        tester.harness.chain.clone(),
        block_b.canonical_root(),
        block_b.clone(),
        test_logger.clone(),
    )
    .await
    .unwrap();

    let inner_block_a = match unblinded_block_a {
        ProvenancedBlock::Local(a, _, _) => a,
        ProvenancedBlock::Builder(a, _, _) => a,
    };
    let inner_block_b = match unblinded_block_b {
        ProvenancedBlock::Local(b, _, _) => b,
        ProvenancedBlock::Builder(b, _, _) => b,
    };

    let gossip_block_b = GossipVerifiedBlock::new(inner_block_b, &tester.harness.chain);
    assert!(gossip_block_b.is_ok());
    let gossip_block_a = GossipVerifiedBlock::new(inner_block_a, &tester.harness.chain);
    assert!(gossip_block_a.is_err());

    let channel = tokio::sync::mpsc::unbounded_channel();
    let network_globals = tester.ctx.network_globals.clone().unwrap();

    let publication_result = publish_blinded_block(
        block_b,
        tester.harness.chain,
        &channel.0,
        test_logger,
        validation_level.unwrap(),
        StatusCode::ACCEPTED,
        network_globals,
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
    let (block, _) = tester.harness.make_blinded_block(state_a, slot_b).await;

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

/// This test checks that an HTTP POST request with the block & blobs succeeds with a 200 response
/// even if the block has already been seen on gossip without any blobs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn block_seen_on_gossip_without_blobs() {
    let validation_level: Option<BroadcastValidation> = Some(BroadcastValidation::Gossip);

    // Validator count needs to be at least 32 or proposer boost gets set to 0 when computing
    // `validator_count // 32`.
    let validator_count = 64;
    let num_initial: u64 = 31;
    let spec = ForkName::latest().make_genesis_spec(E::default_spec());
    let tester = InteractiveTester::<E>::new(Some(spec), validator_count).await;

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
    let ((block, blobs), _) = tester.harness.make_block(state_a, slot_b).await;
    let blobs = blobs.expect("should have some blobs");
    assert_ne!(blobs.0.len(), 0);

    // Simulate the block being seen on gossip.
    block
        .clone()
        .into_gossip_verified_block(&tester.harness.chain)
        .unwrap();

    // It should not yet be added to fork choice because blobs have not been seen.
    assert!(!tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block.canonical_root()));

    // Post the block *and* blobs to the HTTP API.
    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(
            &PublishBlockRequest::new(block.clone(), Some(blobs)),
            validation_level,
        )
        .await;

    // This should result in the block being fully imported.
    response.unwrap();
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block.canonical_root()));
}

/// This test checks that an HTTP POST request with the block & blobs succeeds with a 200 response
/// even if the block has already been seen on gossip without all blobs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn block_seen_on_gossip_with_some_blobs() {
    let validation_level: Option<BroadcastValidation> = Some(BroadcastValidation::Gossip);

    // Validator count needs to be at least 32 or proposer boost gets set to 0 when computing
    // `validator_count // 32`.
    let validator_count = 64;
    let num_initial: u64 = 31;
    let spec = ForkName::latest().make_genesis_spec(E::default_spec());
    let tester = InteractiveTester::<E>::new(Some(spec), validator_count).await;

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
    let ((block, blobs), _) = tester.harness.make_block(state_a, slot_b).await;
    let blobs = blobs.expect("should have some blobs");
    assert!(
        blobs.0.len() >= 2,
        "need at least 2 blobs for partial reveal"
    );

    let partial_kzg_proofs = vec![blobs.0.get(0).unwrap().clone()];
    let partial_blobs = vec![blobs.1.get(0).unwrap().clone()];

    // Simulate the block being seen on gossip.
    block
        .clone()
        .into_gossip_verified_block(&tester.harness.chain)
        .unwrap();

    // Simulate some of the blobs being seen on gossip.
    for (i, (kzg_proof, blob)) in partial_kzg_proofs
        .into_iter()
        .zip(partial_blobs)
        .enumerate()
    {
        let sidecar = Arc::new(BlobSidecar::new(i, blob, &block, kzg_proof).unwrap());
        let gossip_blob =
            GossipVerifiedBlob::new(sidecar, i as u64, &tester.harness.chain).unwrap();
        tester
            .harness
            .chain
            .process_gossip_blob(gossip_blob)
            .await
            .unwrap();
    }

    // It should not yet be added to fork choice because all blobs have not been seen.
    assert!(!tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block.canonical_root()));

    // Post the block *and* all blobs to the HTTP API.
    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(
            &PublishBlockRequest::new(block.clone(), Some(blobs)),
            validation_level,
        )
        .await;

    // This should result in the block being fully imported.
    response.unwrap();
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block.canonical_root()));
}

/// This test checks that an HTTP POST request with the block & blobs succeeds with a 200 response
/// even if the blobs have already been seen on gossip.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn blobs_seen_on_gossip_without_block() {
    let validation_level: Option<BroadcastValidation> = Some(BroadcastValidation::Gossip);

    // Validator count needs to be at least 32 or proposer boost gets set to 0 when computing
    // `validator_count // 32`.
    let validator_count = 64;
    let num_initial: u64 = 31;
    let spec = ForkName::latest().make_genesis_spec(E::default_spec());
    let tester = InteractiveTester::<E>::new(Some(spec), validator_count).await;

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
    let ((block, blobs), _) = tester.harness.make_block(state_a, slot_b).await;
    let (kzg_proofs, blobs) = blobs.expect("should have some blobs");

    // Simulate the blobs being seen on gossip.
    for (i, (kzg_proof, blob)) in kzg_proofs
        .clone()
        .into_iter()
        .zip(blobs.clone())
        .enumerate()
    {
        let sidecar = Arc::new(BlobSidecar::new(i, blob, &block, kzg_proof).unwrap());
        let gossip_blob =
            GossipVerifiedBlob::new(sidecar, i as u64, &tester.harness.chain).unwrap();
        tester
            .harness
            .chain
            .process_gossip_blob(gossip_blob)
            .await
            .unwrap();
    }

    // It should not yet be added to fork choice because the block has not been seen.
    assert!(!tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block.canonical_root()));

    // Post the block *and* all blobs to the HTTP API.
    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(
            &PublishBlockRequest::new(block.clone(), Some((kzg_proofs, blobs))),
            validation_level,
        )
        .await;

    // This should result in the block being fully imported.
    response.unwrap();
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block.canonical_root()));
}

/// This test checks that an HTTP POST request with the block succeeds with a 200 response
/// if just the blobs have already been seen on gossip.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn blobs_seen_on_gossip_without_block_and_no_http_blobs() {
    let validation_level: Option<BroadcastValidation> = Some(BroadcastValidation::Gossip);

    // Validator count needs to be at least 32 or proposer boost gets set to 0 when computing
    // `validator_count // 32`.
    let validator_count = 64;
    let num_initial: u64 = 31;
    let spec = ForkName::latest().make_genesis_spec(E::default_spec());
    let tester = InteractiveTester::<E>::new(Some(spec), validator_count).await;

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
    let ((block, blobs), _) = tester.harness.make_block(state_a, slot_b).await;
    let (kzg_proofs, blobs) = blobs.expect("should have some blobs");
    assert!(!blobs.is_empty());

    // Simulate the blobs being seen on gossip.
    for (i, (kzg_proof, blob)) in kzg_proofs
        .clone()
        .into_iter()
        .zip(blobs.clone())
        .enumerate()
    {
        let sidecar = Arc::new(BlobSidecar::new(i, blob, &block, kzg_proof).unwrap());
        let gossip_blob =
            GossipVerifiedBlob::new(sidecar, i as u64, &tester.harness.chain).unwrap();
        tester
            .harness
            .chain
            .process_gossip_blob(gossip_blob)
            .await
            .unwrap();
    }

    // It should not yet be added to fork choice because the block has not been seen.
    assert!(!tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block.canonical_root()));

    // Post just the block to the HTTP API (blob lists are empty).
    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(
            &PublishBlockRequest::new(
                block.clone(),
                Some((Default::default(), Default::default())),
            ),
            validation_level,
        )
        .await;

    // This should result in the block being fully imported.
    response.unwrap();
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block.canonical_root()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn slashable_blobs_seen_on_gossip_cause_failure() {
    let validation_level: Option<BroadcastValidation> =
        Some(BroadcastValidation::ConsensusAndEquivocation);

    // Validator count needs to be at least 32 or proposer boost gets set to 0 when computing
    // `validator_count // 32`.
    let validator_count = 64;
    let num_initial: u64 = 31;
    let spec = ForkName::latest().make_genesis_spec(E::default_spec());
    let tester = InteractiveTester::<E>::new(Some(spec), validator_count).await;

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
    let ((block_a, blobs_a), _) = tester.harness.make_block(state_a.clone(), slot_b).await;
    let ((block_b, blobs_b), _) = tester.harness.make_block(state_a, slot_b).await;
    let (kzg_proofs_a, blobs_a) = blobs_a.expect("should have some blobs");
    let (kzg_proofs_b, blobs_b) = blobs_b.expect("should have some blobs");

    // Simulate the blobs of block B being seen on gossip.
    for (i, (kzg_proof, blob)) in kzg_proofs_b.into_iter().zip(blobs_b).enumerate() {
        let sidecar = Arc::new(BlobSidecar::new(i, blob, &block_b, kzg_proof).unwrap());
        let gossip_blob =
            GossipVerifiedBlob::new(sidecar, i as u64, &tester.harness.chain).unwrap();
        tester
            .harness
            .chain
            .process_gossip_blob(gossip_blob)
            .await
            .unwrap();
    }

    // It should not yet be added to fork choice because block B has not been seen.
    assert!(!tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block_b.canonical_root()));

    // Post block A *and* all its blobs to the HTTP API.
    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(
            &PublishBlockRequest::new(block_a.clone(), Some((kzg_proofs_a, blobs_a))),
            validation_level,
        )
        .await;

    // This should not result in block A being fully imported.
    response.unwrap_err();
    assert!(!tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block_a.canonical_root()));
}

/// This test checks that an HTTP POST request with a duplicate block & blobs results in the
/// `duplicate_status_code` being returned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn duplicate_block_status_code() {
    let validation_level: Option<BroadcastValidation> = Some(BroadcastValidation::Gossip);

    // Validator count needs to be at least 32 or proposer boost gets set to 0 when computing
    // `validator_count // 32`.
    let validator_count = 64;
    let num_initial: u64 = 31;
    let spec = ForkName::latest().make_genesis_spec(E::default_spec());
    let duplicate_block_status_code = StatusCode::IM_A_TEAPOT;
    let tester = InteractiveTester::<E>::new_with_initializer_and_mutator(
        Some(spec),
        validator_count,
        None,
        None,
        Config {
            duplicate_block_status_code,
            ..Config::default()
        },
    )
    .await;

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
    let ((block, blobs), _) = tester.harness.make_block(state_a, slot_b).await;
    let (kzg_proofs, blobs) = blobs.expect("should have some blobs");

    // Post the block blobs to the HTTP API once.
    let block_request = PublishBlockRequest::new(block.clone(), Some((kzg_proofs, blobs)));
    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&block_request, validation_level)
        .await;

    // This should result in the block being fully imported.
    response.unwrap();
    assert!(tester
        .harness
        .chain
        .block_is_known_to_fork_choice(&block.canonical_root()));

    // Post again.
    let duplicate_response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&block_request, validation_level)
        .await;
    let err = duplicate_response.unwrap_err();
    assert_eq!(err.status().unwrap(), duplicate_block_status_code);
}

fn assert_server_message_error(error_response: eth2::Error, expected_message: String) {
    let eth2::Error::ServerMessage(err) = error_response else {
        panic!("Not a eth2::Error::ServerMessage");
    };
    assert_eq!(err.message, expected_message);
}
