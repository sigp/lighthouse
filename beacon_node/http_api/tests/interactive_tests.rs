//! Generic tests that make use of the (newer) `InteractiveApiTester`
use crate::common::*;
use beacon_chain::test_utils::{AttestationStrategy, BlockStrategy};
use eth2::types::DepositContractData;
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
    let block_root_b = harness
        .process_block(slot_b, block_b.canonical_root(), block_b)
        .await
        .unwrap();

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
        .process_block(slot_c, block_c.canonical_root(), block_c.clone())
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
