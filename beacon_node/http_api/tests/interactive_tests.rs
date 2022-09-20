//! Generic tests that make use of the (newer) `InteractiveApiTester`
use crate::common::*;
use beacon_chain::test_utils::{AttestationStrategy, BlockStrategy};
use eth2::types::DepositContractData;
use slot_clock::SlotClock;
use state_processing::state_advance::complete_state_advance;
use tree_hash::TreeHash;
use types::{EthSpec, FullPayload, MainnetEthSpec, Slot};

type E = MainnetEthSpec;

// Test that the deposit_contract endpoint returns the correct chain_id and address.
// Regression test for https://github.com/sigp/lighthouse/issues/2657
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deposit_contract_custom_network() {
    let validator_count = 24;
    let mut spec = E::default_spec();

    // Rinkeby, which we don't use elsewhere.
    spec.deposit_chain_id = 4;
    spec.deposit_network_id = 4;
    // Arbitrary contract address.
    spec.deposit_contract_address = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse().unwrap();

    let tester = InteractiveTester::<E>::new(Some(spec.clone()), validator_count).await;
    let client = &tester.client;

    let result = client.get_config_deposit_contract().await.unwrap().data;

    let expected = DepositContractData {
        address: spec.deposit_contract_address,
        chain_id: spec.deposit_chain_id,
    };

    assert_eq!(result, expected);
}

// Test that the beacon node will try to perform proposer boost re-orgs on late blocks when
// configured.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_zero_weight() {
    proposer_boost_re_org_test(Slot::new(30), None, Some(10), true).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_epoch_boundary() {
    proposer_boost_re_org_test(Slot::new(31), None, Some(10), false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn proposer_boost_re_org_bad_ffg() {
    proposer_boost_re_org_test(Slot::new(64 + 22), None, Some(10), false).await
}

pub async fn proposer_boost_re_org_test(
    head_slot: Slot,
    num_head_votes: Option<u64>,
    re_org_threshold: Option<u64>,
    should_re_org: bool,
) {
    assert!(head_slot > 0);

    // Validator count needs to be at least 32 or proposer boost gets set to 0 when computing
    // `validator_count // 32`.
    let validator_count = 32;
    let num_initial = head_slot.as_u64() - 1;

    let tester = InteractiveTester::<E>::new_with_mutator(
        None,
        validator_count,
        Some(Box::new(move |builder| {
            builder.proposer_re_org_threshold(re_org_threshold)
        })),
    )
    .await;
    let harness = &tester.harness;
    let slot_clock = &harness.chain.slot_clock;

    // Create some chain depth.
    harness.advance_slot();
    harness
        .extend_chain(
            num_initial as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // We set up the following block graph, where B is a block that arrives late and is re-orged
    // by C.
    //
    // A | B | - |
    // ^ | - | C |
    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;
    let slot_c = slot_a + 2;

    let block_a_root = harness.head_block_root();
    let state_a = harness.get_current_state();

    // Produce block B and process it halfway through the slot.
    let (block_b, mut state_b) = harness.make_block(state_a.clone(), slot_b).await;
    let block_b_root = block_b.canonical_root();

    let obs_time = slot_clock.start_of(slot_b).unwrap() + slot_clock.slot_duration() / 2;
    slot_clock.set_current_time(obs_time);
    harness.chain.block_times_cache.write().set_time_observed(
        block_b_root,
        slot_b,
        obs_time,
        None,
        None,
    );
    harness.process_block_result(block_b).await.unwrap();

    // Add attestations to block B.
    /* FIXME(sproul): implement attestations
    if let Some(num_head_votes) = num_head_votes {
        harness.attest_block(
            &state_b,
            state_b.canonical_root(),
            block_b_root,
            &block_b,
            &[]
        )
    }
    */

    // Produce block C.
    while harness.get_current_slot() != slot_c {
        harness.advance_slot();
        harness.chain.per_slot_task().await;
    }

    // Advance state_b so we can get the proposer.
    complete_state_advance(&mut state_b, None, slot_c, &harness.chain.spec).unwrap();

    let proposer_index = state_b
        .get_beacon_proposer_index(slot_c, &harness.chain.spec)
        .unwrap();
    let randao_reveal = harness
        .sign_randao_reveal(&state_b, proposer_index, slot_c)
        .into();
    let unsigned_block_c = tester
        .client
        .get_validator_blocks(slot_c, &randao_reveal, None)
        .await
        .unwrap()
        .data;
    let block_c = harness.sign_beacon_block(unsigned_block_c, &state_b);

    if should_re_org {
        // Block C should build on A.
        assert_eq!(block_c.parent_root(), block_a_root);
    } else {
        // Block C should build on B.
        assert_eq!(block_c.parent_root(), block_b_root);
    }

    // Applying block C should cause it to become head regardless (re-org or continuation).
    let block_root_c = harness.process_block_result(block_c).await.unwrap().into();
    assert_eq!(harness.head_block_root(), block_root_c);
}

// Test that running fork choice before proposing results in selection of the correct head.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
pub async fn fork_choice_before_proposal() {
    // Validator count needs to be at least 32 or proposer boost gets set to 0 when computing
    // `validator_count // 32`.
    let validator_count = 32;
    let all_validators = (0..validator_count).collect::<Vec<_>>();
    let num_initial: u64 = 31;

    let tester = InteractiveTester::<E>::new(None, validator_count).await;
    let harness = &tester.harness;

    // Create some chain depth.
    harness.advance_slot();
    harness
        .extend_chain(
            num_initial as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // We set up the following block graph, where B is a block that is temporarily orphaned by C,
    // but is then reinstated and built upon by D.
    //
    // A | B | - | D |
    // ^ | - | C |
    let slot_a = Slot::new(num_initial);
    let slot_b = slot_a + 1;
    let slot_c = slot_a + 2;
    let slot_d = slot_a + 3;

    let state_a = harness.get_current_state();
    let (block_b, state_b) = harness.make_block(state_a.clone(), slot_b).await;
    let block_root_b = harness.process_block(slot_b, block_b).await.unwrap();

    // Create attestations to B but keep them in reserve until after C has been processed.
    let attestations_b = harness.make_attestations(
        &all_validators,
        &state_b,
        state_b.tree_hash_root(),
        block_root_b,
        slot_b,
    );

    let (block_c, state_c) = harness.make_block(state_a, slot_c).await;
    let block_root_c = harness
        .process_block(slot_c, block_c.clone())
        .await
        .unwrap();

    // Create attestations to C from a small number of validators and process them immediately.
    let attestations_c = harness.make_attestations(
        &all_validators[..validator_count / 2],
        &state_c,
        state_c.tree_hash_root(),
        block_root_c,
        slot_c,
    );
    harness.process_attestations(attestations_c);

    // Apply the attestations to B, but don't re-run fork choice.
    harness.process_attestations(attestations_b);

    // Due to proposer boost, the head should be C during slot C.
    assert_eq!(
        harness.chain.canonical_head.cached_head().head_block_root(),
        block_root_c.into()
    );

    // Ensure that building a block via the HTTP API re-runs fork choice and builds block D upon B.
    // Manually prod the per-slot task, because the slot timer doesn't run in the background in
    // these tests.
    harness.advance_slot();
    harness.chain.per_slot_task().await;

    let proposer_index = state_b
        .get_beacon_proposer_index(slot_d, &harness.chain.spec)
        .unwrap();
    let randao_reveal = harness
        .sign_randao_reveal(&state_b, proposer_index, slot_d)
        .into();
    let block_d = tester
        .client
        .get_validator_blocks::<E, FullPayload<E>>(slot_d, &randao_reveal, None)
        .await
        .unwrap()
        .data;

    // Head is now B.
    assert_eq!(
        harness.chain.canonical_head.cached_head().head_block_root(),
        block_root_b.into()
    );
    // D's parent is B.
    assert_eq!(block_d.parent_root(), block_root_b.into());
}
