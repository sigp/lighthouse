#![cfg(test)]

use std::collections::HashMap;

use beacon_chain::test_utils::{
    generate_deterministic_keypairs, BeaconChainHarness, EphemeralHarnessType,
};
use beacon_chain::{
    test_utils::{AttestationStrategy, BlockStrategy, RelativeSyncCommittee},
    types::{Epoch, EthSpec, Keypair, MinimalEthSpec},
};
use eth2::lighthouse::attestation_rewards::TotalAttestationRewards;
use eth2::lighthouse::StandardAttestationRewards;
use eth2::types::ValidatorId;
use lazy_static::lazy_static;
use types::beacon_state::Error as BeaconStateError;
use types::{BeaconState, ChainSpec};

pub const VALIDATOR_COUNT: usize = 64;

type E = MinimalEthSpec;

lazy_static! {
    static ref KEYPAIRS: Vec<Keypair> = generate_deterministic_keypairs(VALIDATOR_COUNT);
}

fn get_harness(spec: ChainSpec) -> BeaconChainHarness<EphemeralHarnessType<E>> {
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
    let mut spec = E::default_spec();
    spec.altair_fork_epoch = Some(Epoch::new(0));

    let harness = get_harness(spec);
    let num_block_produced = E::slots_per_epoch();

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
    let harness = get_harness(E::default_spec());

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

    let initial_balances: Vec<u64> = harness.get_current_state().balances().clone().into();

    // extend slots to beginning of epoch N + 2
    harness.extend_slots(E::slots_per_epoch() as usize).await;

    // compute reward deltas for all validators in epoch N
    let StandardAttestationRewards {
        ideal_rewards,
        total_rewards,
    } = harness
        .chain
        .compute_attestation_rewards(Epoch::new(0), vec![])
        .unwrap();

    // assert no inactivity penalty for both ideal rewards and individual validators
    assert!(ideal_rewards.iter().all(|reward| reward.inactivity == 0));
    assert!(total_rewards.iter().all(|reward| reward.inactivity == 0));

    // apply attestation rewards to initial balances
    let expected_balances = apply_attestation_rewards(&initial_balances, total_rewards);

    // verify expected balances against actual balances
    let balances: Vec<u64> = harness.get_current_state().balances().clone().into();
    assert_eq!(expected_balances, balances);
}

#[tokio::test]
async fn test_verify_attestation_rewards_base_inactivity_leak() {
    let spec = E::default_spec();
    let harness = get_harness(spec.clone());

    let half = VALIDATOR_COUNT / 2;
    let half_validators: Vec<usize> = (0..half).collect();
    // target epoch is the epoch where the chain enters inactivity leak
    let target_epoch = &spec.min_epochs_to_inactivity_penalty + 1;

    // advance until beginning of epoch N + 1 and get balances
    harness
        .extend_chain(
            (E::slots_per_epoch() * (target_epoch + 1)) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(half_validators.clone()),
        )
        .await;
    let initial_balances: Vec<u64> = harness.get_current_state().balances().clone().into();

    // extend slots to beginning of epoch N + 2
    harness.advance_slot();
    harness
        .extend_chain(
            E::slots_per_epoch() as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(half_validators),
        )
        .await;
    let _slot = harness.get_current_slot();

    // compute reward deltas for all validators in epoch N
    let StandardAttestationRewards {
        ideal_rewards,
        total_rewards,
    } = harness
        .chain
        .compute_attestation_rewards(Epoch::new(target_epoch), vec![])
        .unwrap();

    // assert inactivity penalty for both ideal rewards and individual validators
    assert!(ideal_rewards.iter().all(|reward| reward.inactivity < 0));
    assert!(total_rewards.iter().all(|reward| reward.inactivity < 0));

    // apply attestation rewards to initial balances
    let expected_balances = apply_attestation_rewards(&initial_balances, total_rewards);

    // verify expected balances against actual balances
    let balances: Vec<u64> = harness.get_current_state().balances().clone().into();
    assert_eq!(expected_balances, balances);
}

#[tokio::test]
async fn test_verify_attestation_rewards_base_subset_only() {
    let harness = get_harness(E::default_spec());

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

    // a small subset of validators to compute attestation rewards for
    let validators_subset = [0, VALIDATOR_COUNT / 2, VALIDATOR_COUNT - 1];

    // capture balances before transitioning to N + 2
    let initial_balances = get_validator_balances(harness.get_current_state(), &validators_subset);

    // extend slots to beginning of epoch N + 2
    harness.extend_slots(E::slots_per_epoch() as usize).await;

    let validators_subset_ids: Vec<ValidatorId> = validators_subset
        .into_iter()
        .map(|idx| ValidatorId::Index(idx as u64))
        .collect();

    // compute reward deltas for the subset of validators in epoch N
    let StandardAttestationRewards {
        ideal_rewards: _,
        total_rewards,
    } = harness
        .chain
        .compute_attestation_rewards(Epoch::new(0), validators_subset_ids)
        .unwrap();

    // apply attestation rewards to initial balances
    let expected_balances = apply_attestation_rewards(&initial_balances, total_rewards);

    // verify expected balances against actual balances
    let balances = get_validator_balances(harness.get_current_state(), &validators_subset);
    assert_eq!(expected_balances, balances);
}

/// Apply a vec of `TotalAttestationRewards` to initial balances, and return
fn apply_attestation_rewards(
    initial_balances: &[u64],
    attestation_rewards: Vec<TotalAttestationRewards>,
) -> Vec<u64> {
    initial_balances
        .iter()
        .zip(attestation_rewards)
        .map(|(&initial_balance, rewards)| {
            let expected_balance = initial_balance as i64
                + rewards.head
                + rewards.source
                + rewards.target
                + rewards.inclusion_delay.map(|q| q.value).unwrap_or(0) as i64
                + rewards.inactivity;
            expected_balance as u64
        })
        .collect::<Vec<u64>>()
}

fn get_validator_balances(state: BeaconState<E>, validators: &[usize]) -> Vec<u64> {
    validators
        .iter()
        .flat_map(|&id| {
            state
                .balances()
                .get(id)
                .cloned()
                .ok_or(BeaconStateError::BalancesOutOfBounds(id))
        })
        .collect()
}
