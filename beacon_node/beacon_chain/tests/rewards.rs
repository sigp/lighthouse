#![cfg(test)]

use std::collections::HashMap;

use beacon_chain::test_utils::{
    generate_deterministic_keypairs, BeaconChainHarness, EphemeralHarnessType,
};
use beacon_chain::{
    test_utils::{AttestationStrategy, BlockStrategy, RelativeSyncCommittee},
    types::{Epoch, EthSpec, Keypair, MinimalEthSpec},
};
use eth2::types::ValidatorId;
use lazy_static::lazy_static;
use task_executor::test_utils::null_logger;
use types::ChainSpec;

pub const VALIDATOR_COUNT: usize = 64;

lazy_static! {
    static ref KEYPAIRS: Vec<Keypair> = generate_deterministic_keypairs(VALIDATOR_COUNT);
}

fn get_harness<E: EthSpec>() -> BeaconChainHarness<EphemeralHarnessType<E>> {
    get_harness_custom_spec(None)
}

fn get_harness_custom_spec<E: EthSpec>(
    maybe_spec: Option<ChainSpec>,
) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let spec = maybe_spec.unwrap_or_else(|| {
        let mut spec = E::default_spec();
        spec.altair_fork_epoch = Some(Epoch::new(0)); // We use altair for all tests
        spec
    });

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

#[tokio::test]
async fn test_verify_attestation_rewards_base() {
    type E = MinimalEthSpec;
    let spec = E::default_spec();

    let harness = get_harness_custom_spec::<E>(Some(spec));

    // epoch 0 (N), only two thirds of validators vote.
    let two_thirds = (VALIDATOR_COUNT / 3) * 2;
    let two_thirds_validators: Vec<usize> = (0..two_thirds).collect();
    harness
        .extend_chain(
            E::slots_per_epoch() as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(two_thirds_validators),
        )
        .await;

    let initial_balances = harness.get_current_state().balances().clone();

    // extend slots to beginning of epoch N + 2
    harness.extend_slots(E::slots_per_epoch() as usize).await;

    // compute reward deltas for all validators in epoch N
    let all_validators: Vec<ValidatorId> = (0..VALIDATOR_COUNT)
        .map(|idx| ValidatorId::Index(idx as u64))
        .collect();
    let mut attestation_rewards = harness
        .chain
        .compute_attestation_rewards(Epoch::new(0), all_validators, null_logger().unwrap())
        .unwrap();
    attestation_rewards
        .total_rewards
        .sort_by_key(|rewards| rewards.validator_index);

    // apply attestation rewards to initial balances
    let expected_balances = initial_balances
        .iter()
        .zip(attestation_rewards.total_rewards)
        .map(|(&initial_balance, rewards)| {
            let expected_balance = initial_balance as i64
                + rewards.head
                + rewards.source
                + rewards.target
                + rewards.inclusion_delay.unwrap_or(0) as i64;
            expected_balance as u64
        })
        .collect::<Vec<u64>>();

    // verify expected balances against actual balances
    let balances: Vec<u64> = harness.get_current_state().balances().clone().into();
    assert_eq!(expected_balances, balances);
}
