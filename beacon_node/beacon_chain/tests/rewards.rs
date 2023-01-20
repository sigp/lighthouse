#![cfg(test)]

use std::collections::HashMap;

use beacon_chain::test_utils::{
    generate_deterministic_keypairs, BeaconChainHarness, EphemeralHarnessType,
};
use beacon_chain::{
    test_utils::{AttestationStrategy, BlockStrategy, RelativeSyncCommittee},
    types::{Epoch, EthSpec, Keypair, MinimalEthSpec},
};
use lazy_static::lazy_static;

pub const VALIDATOR_COUNT: usize = 64;

lazy_static! {
    static ref KEYPAIRS: Vec<Keypair> = generate_deterministic_keypairs(VALIDATOR_COUNT);
}

fn get_harness<E: EthSpec>() -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let mut spec = E::default_spec();

    spec.altair_fork_epoch = Some(Epoch::new(0)); // We use altair for all tests

    let harness = BeaconChainHarness::builder(E::default())
        .spec(spec)
        .keypairs(KEYPAIRS.to_vec())
        .fresh_ephemeral_store()
        .build();

    harness.advance_slot();

    harness
}

#[tokio::test]
async fn test_sync_committee_rewards() {
    let num_block_produced = MinimalEthSpec::slots_per_epoch();
    let harness = get_harness::<MinimalEthSpec>();

    let latest_block_root = harness
        .extend_chain(
            num_block_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Create and add sync committee message to op_pool
    let sync_contributions = harness.make_sync_contributions(
        &harness.get_current_state(),
        latest_block_root,
        harness.get_current_slot(),
        RelativeSyncCommittee::Current,
    );

    harness
        .process_sync_contributions(sync_contributions)
        .unwrap();

    // Add block
    let chain = &harness.chain;
    let (head_state, head_state_root) = harness.get_current_state_and_root();
    let target_slot = harness.get_current_slot() + 1;

    let (block_root, mut state) = harness
        .add_attested_block_at_slot(target_slot, head_state, head_state_root, &[])
        .await
        .unwrap();

    let block = harness.get_block(block_root).unwrap();
    let parent_block = chain
        .get_blinded_block(&block.parent_root())
        .unwrap()
        .unwrap();
    let parent_state = chain
        .get_state(&parent_block.state_root(), Some(parent_block.slot()))
        .unwrap()
        .unwrap();

    let reward_payload = chain
        .compute_sync_committee_rewards(block.message(), &mut state)
        .unwrap();

    let rewards = reward_payload
        .iter()
        .map(|reward| (reward.validator_index, reward.reward))
        .collect::<HashMap<_, _>>();

    let proposer_index = state
        .get_beacon_proposer_index(target_slot, &MinimalEthSpec::default_spec())
        .unwrap();

    let mut mismatches = vec![];

    for validator in state.validators() {
        let validator_index = state
            .clone()
            .get_validator_index(&validator.pubkey)
            .unwrap()
            .unwrap();
        let pre_state_balance = parent_state.balances()[validator_index];
        let post_state_balance = state.balances()[validator_index];
        let sync_committee_reward = rewards.get(&(validator_index as u64)).unwrap_or(&0);

        if validator_index == proposer_index {
            continue; // Ignore proposer
        }

        if pre_state_balance as i64 + *sync_committee_reward != post_state_balance as i64 {
            mismatches.push(validator_index.to_string());
        }
    }

    assert_eq!(
        mismatches.len(),
        0,
        "Expect 0 mismatches, but these validators have mismatches on balance: {} ",
        mismatches.join(",")
    );
}
