use beacon_chain::test_utils::{AttestationStrategy, BlockStrategy};
use eth2::types::{BeaconBlock, BroadcastValidation, SignedBeaconBlock};
use http_api::test_utils::InteractiveTester;
use types::{Epoch, MainnetEthSpec, Slot};

use eth2::reqwest::StatusCode;

type E = MainnetEthSpec;

/// This test checks that a block that is **invalid** from a gossip perspective gets rejected when using `broadcast_validation=gossip`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn gossip_reject() {
    /* this test targets gossip-level validation */
    let validation_level: Option<BroadcastValidation> = Some(BroadcastValidation::Gossip);

    // Validator count needs to be at least 32 or proposer boost gets set to 0 when computing
    // `validator_count // 32`.
    let validator_count = 64;
    let num_initial: u64 = 31;
    let tester = InteractiveTester::<E>::new(None, validator_count).await;

    /* produce a block wih zero parent and state roots in order to reproduce the initial exploit */
    let block: SignedBeaconBlock<E> = BeaconBlock::empty(&tester.harness.chain.spec).sign(
        &tester.harness.validator_keypairs[0].sk,
        &tester
            .harness
            .chain
            .spec
            .fork_at_epoch(Epoch::new(Slot::new(num_initial).into())),
        tester.harness.chain.genesis_validators_root,
        &tester.harness.chain.spec,
    );

    let response: Result<(), eth2::Error> = tester
        .client
        .post_beacon_blocks_v2(&block, validation_level)
        .await;
    assert!(response.is_err());

    let error_response: eth2::Error = response.err().unwrap();

    /* mandated by Beacon API spec */
    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));
}

/// This test checks that a block that is valid from a gossip perspective is accepted when using `broadcast_validation=gossip`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn gossip_accept_gossip() {
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
    assert!(response.is_ok());
}

/// This test checks that a block that is valid from both a gossip and consensus perspective is accepted when using `broadcast_validation=gossip`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn gossip_accept_consensus() {
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
pub async fn consensus_accept_gossip() {
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
}

/// This test checks that a block that is valid from both a gossip and consensus perspective is accepted when using `broadcast_validation=consensus`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn consensus_accept_consensus() {
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

    let error_response: eth2::Error = response.err().unwrap();

    /* mandated by Beacon API spec */
    assert_eq!(error_response.status(), Some(StatusCode::BAD_REQUEST));
}
