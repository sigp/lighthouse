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
use types::{BeaconState, ChainSpec, ForkName, Slot};

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
        let pre_state_balance = *parent_state.balances().get(validator_index).unwrap();
        let post_state_balance = *state.balances().get(validator_index).unwrap();
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

    let initial_balances: Vec<u64> = harness.get_current_state().balances().to_vec();

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
    let balances: Vec<u64> = harness.get_current_state().balances().to_vec();
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
    let initial_balances: Vec<u64> = harness.get_current_state().balances().to_vec();

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
    let balances: Vec<u64> = harness.get_current_state().balances().to_vec();
    assert_eq!(expected_balances, balances);
}

#[tokio::test]
async fn test_verify_attestation_rewards_base_inactivity_leak_justification_epoch() {
    let spec = E::default_spec();
    let harness = get_harness(spec.clone());

    let half = VALIDATOR_COUNT / 2;
    let half_validators: Vec<usize> = (0..half).collect();
    // target epoch is the epoch where the chain enters inactivity leak
    let mut target_epoch = &spec.min_epochs_to_inactivity_penalty + 2;

    // advance until beginning of epoch N + 2
    harness
        .extend_chain(
            (E::slots_per_epoch() * (target_epoch + 1)) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(half_validators.clone()),
        )
        .await;

    // advance to create first justification epoch and get initial balances
    harness.extend_slots(E::slots_per_epoch() as usize).await;
    target_epoch += 1;
    let initial_balances: Vec<u64> = harness.get_current_state().balances().to_vec();

    //assert previous_justified_checkpoint matches 0 as we were in inactivity leak from beginning
    assert_eq!(
        0,
        harness
            .get_current_state()
            .previous_justified_checkpoint()
            .epoch
            .as_u64()
    );

    // extend slots to beginning of epoch N + 1
    harness.extend_slots(E::slots_per_epoch() as usize).await;

    //assert target epoch and previous_justified_checkpoint match
    assert_eq!(
        target_epoch,
        harness
            .get_current_state()
            .previous_justified_checkpoint()
            .epoch
            .as_u64()
    );

    // compute reward deltas for all validators in epoch N
    let StandardAttestationRewards {
        ideal_rewards,
        total_rewards,
    } = harness
        .chain
        .compute_attestation_rewards(Epoch::new(target_epoch), vec![])
        .unwrap();

    // assert we successfully get ideal rewards for justified epoch out of inactivity leak
    assert!(ideal_rewards
        .iter()
        .all(|reward| reward.head > 0 && reward.target > 0 && reward.source > 0));

    // apply attestation rewards to initial balances
    let expected_balances = apply_attestation_rewards(&initial_balances, total_rewards);

    // verify expected balances against actual balances
    let balances: Vec<u64> = harness.get_current_state().balances().to_vec();
    assert_eq!(expected_balances, balances);
}

#[tokio::test]
async fn test_verify_attestation_rewards_altair() {
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec.clone());
    let target_epoch = 0;

    // advance until epoch N + 1 and get initial balances
    harness
        .extend_slots((E::slots_per_epoch() * (target_epoch + 1)) as usize)
        .await;
    let initial_balances: Vec<u64> = harness.get_current_state().balances().to_vec();

    // advance until epoch N + 2 and build proposal rewards map
    let mut proposal_rewards_map: HashMap<u64, u64> = HashMap::new();
    let mut sync_committee_rewards_map: HashMap<u64, i64> = HashMap::new();
    for _ in 0..E::slots_per_epoch() {
        let state = harness.get_current_state();
        let slot = state.slot() + Slot::new(1);

        // calculate beacon block rewards / penalties
        let ((signed_block, _maybe_blob_sidecars), mut state) =
            harness.make_block_return_pre_state(state, slot).await;
        let beacon_block_reward = harness
            .chain
            .compute_beacon_block_reward(
                signed_block.message(),
                signed_block.canonical_root(),
                &mut state,
            )
            .unwrap();

        let total_proposer_reward = proposal_rewards_map
            .get(&beacon_block_reward.proposer_index)
            .unwrap_or(&0u64)
            + beacon_block_reward.total;

        proposal_rewards_map.insert(beacon_block_reward.proposer_index, total_proposer_reward);

        // calculate sync committee rewards / penalties
        let reward_payload = harness
            .chain
            .compute_sync_committee_rewards(signed_block.message(), &mut state)
            .unwrap();

        reward_payload.iter().for_each(|reward| {
            let mut amount = *sync_committee_rewards_map
                .get(&reward.validator_index)
                .unwrap_or(&0);
            amount += reward.reward;
            sync_committee_rewards_map.insert(reward.validator_index, amount);
        });

        harness.extend_slots(1).await;
    }

    // compute reward deltas for all validators in epoch N
    let StandardAttestationRewards {
        ideal_rewards,
        total_rewards,
    } = harness
        .chain
        .compute_attestation_rewards(Epoch::new(target_epoch), vec![])
        .unwrap();

    // assert ideal rewards are greater than 0
    assert!(ideal_rewards
        .iter()
        .all(|reward| reward.head > 0 && reward.target > 0 && reward.source > 0));

    // apply attestation, proposal, and sync committee rewards and penalties to initial balances
    let expected_balances = apply_attestation_rewards(&initial_balances, total_rewards);
    let expected_balances = apply_beacon_block_rewards(&proposal_rewards_map, expected_balances);
    let expected_balances =
        apply_sync_committee_rewards(&sync_committee_rewards_map, expected_balances);

    // verify expected balances against actual balances
    let balances: Vec<u64> = harness.get_current_state().balances().to_vec();

    assert_eq!(expected_balances, balances);
}

#[tokio::test]
async fn test_verify_attestation_rewards_altair_inactivity_leak() {
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec.clone());

    let half = VALIDATOR_COUNT / 2;
    let half_validators: Vec<usize> = (0..half).collect();
    // target epoch is the epoch where the chain enters inactivity leak
    let target_epoch = &spec.min_epochs_to_inactivity_penalty + 1;

    // advance until beginning of epoch N + 1 and get balances
    harness
        .extend_slots_some_validators(
            (E::slots_per_epoch() * (target_epoch + 1)) as usize,
            half_validators.clone(),
        )
        .await;
    let initial_balances: Vec<u64> = harness.get_current_state().balances().to_vec();

    // advance until epoch N + 2 and build proposal rewards map
    let mut proposal_rewards_map: HashMap<u64, u64> = HashMap::new();
    let mut sync_committee_rewards_map: HashMap<u64, i64> = HashMap::new();
    for _ in 0..E::slots_per_epoch() {
        let state = harness.get_current_state();
        let slot = state.slot() + Slot::new(1);

        // calculate beacon block rewards / penalties
        let ((signed_block, _maybe_blob_sidecars), mut state) =
            harness.make_block_return_pre_state(state, slot).await;
        let beacon_block_reward = harness
            .chain
            .compute_beacon_block_reward(
                signed_block.message(),
                signed_block.canonical_root(),
                &mut state,
            )
            .unwrap();

        let total_proposer_reward = proposal_rewards_map
            .get(&beacon_block_reward.proposer_index)
            .unwrap_or(&0u64)
            + beacon_block_reward.total;

        proposal_rewards_map.insert(beacon_block_reward.proposer_index, total_proposer_reward);

        // calculate sync committee rewards / penalties
        let reward_payload = harness
            .chain
            .compute_sync_committee_rewards(signed_block.message(), &mut state)
            .unwrap();

        reward_payload.iter().for_each(|reward| {
            let mut amount = *sync_committee_rewards_map
                .get(&reward.validator_index)
                .unwrap_or(&0);
            amount += reward.reward;
            sync_committee_rewards_map.insert(reward.validator_index, amount);
        });

        harness
            .extend_slots_some_validators(1, half_validators.clone())
            .await;
    }

    // compute reward deltas for all validators in epoch N
    let StandardAttestationRewards {
        ideal_rewards,
        total_rewards,
    } = harness
        .chain
        .compute_attestation_rewards(Epoch::new(target_epoch), vec![])
        .unwrap();

    // assert inactivity penalty for both ideal rewards and individual validators
    assert!(ideal_rewards.iter().all(|reward| reward.inactivity == 0));
    assert!(total_rewards[..half]
        .iter()
        .all(|reward| reward.inactivity == 0));
    assert!(total_rewards[half..]
        .iter()
        .all(|reward| reward.inactivity < 0));

    // apply attestation, proposal, and sync committee rewards and penalties to initial balances
    let expected_balances = apply_attestation_rewards(&initial_balances, total_rewards);
    let expected_balances = apply_beacon_block_rewards(&proposal_rewards_map, expected_balances);
    let expected_balances =
        apply_sync_committee_rewards(&sync_committee_rewards_map, expected_balances);

    // verify expected balances against actual balances
    let balances: Vec<u64> = harness.get_current_state().balances().to_vec();

    assert_eq!(expected_balances, balances);
}

#[tokio::test]
async fn test_verify_attestation_rewards_altair_inactivity_leak_justification_epoch() {
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec.clone());

    let half = VALIDATOR_COUNT / 2;
    let half_validators: Vec<usize> = (0..half).collect();
    // target epoch is the epoch where the chain enters inactivity leak + 1
    let mut target_epoch = &spec.min_epochs_to_inactivity_penalty + 2;

    // advance until beginning of epoch N + 1
    harness
        .extend_slots_some_validators(
            (E::slots_per_epoch() * (target_epoch + 1)) as usize,
            half_validators.clone(),
        )
        .await;

    let validator_inactivity_score = harness
        .get_current_state()
        .get_inactivity_score(VALIDATOR_COUNT - 1)
        .unwrap();

    //assert to ensure we are in inactivity leak
    assert_eq!(4, validator_inactivity_score);

    // advance for first justification epoch and get balances
    harness.extend_slots(E::slots_per_epoch() as usize).await;
    target_epoch += 1;
    let initial_balances: Vec<u64> = harness.get_current_state().balances().to_vec();

    // advance until epoch N + 2 and build proposal rewards map
    let mut proposal_rewards_map: HashMap<u64, u64> = HashMap::new();
    let mut sync_committee_rewards_map: HashMap<u64, i64> = HashMap::new();
    for _ in 0..E::slots_per_epoch() {
        let state = harness.get_current_state();
        let slot = state.slot() + Slot::new(1);

        // calculate beacon block rewards / penalties
        let ((signed_block, _maybe_blob_sidecars), mut state) =
            harness.make_block_return_pre_state(state, slot).await;
        let beacon_block_reward = harness
            .chain
            .compute_beacon_block_reward(
                signed_block.message(),
                signed_block.canonical_root(),
                &mut state,
            )
            .unwrap();

        let total_proposer_reward = proposal_rewards_map
            .get(&beacon_block_reward.proposer_index)
            .unwrap_or(&0u64)
            + beacon_block_reward.total;

        proposal_rewards_map.insert(beacon_block_reward.proposer_index, total_proposer_reward);

        // calculate sync committee rewards / penalties
        let reward_payload = harness
            .chain
            .compute_sync_committee_rewards(signed_block.message(), &mut state)
            .unwrap();

        reward_payload.iter().for_each(|reward| {
            let mut amount = *sync_committee_rewards_map
                .get(&reward.validator_index)
                .unwrap_or(&0);
            amount += reward.reward;
            sync_committee_rewards_map.insert(reward.validator_index, amount);
        });

        harness.extend_slots(1).await;
    }

    //assert target epoch and previous_justified_checkpoint match
    assert_eq!(
        target_epoch,
        harness
            .get_current_state()
            .previous_justified_checkpoint()
            .epoch
            .as_u64()
    );

    // compute reward deltas for all validators in epoch N
    let StandardAttestationRewards {
        ideal_rewards,
        total_rewards,
    } = harness
        .chain
        .compute_attestation_rewards(Epoch::new(target_epoch), vec![])
        .unwrap();

    // assert ideal rewards are greater than 0
    assert!(ideal_rewards
        .iter()
        .all(|reward| reward.head > 0 && reward.target > 0 && reward.source > 0));

    // apply attestation, proposal, and sync committee rewards and penalties to initial balances
    let expected_balances = apply_attestation_rewards(&initial_balances, total_rewards);
    let expected_balances = apply_beacon_block_rewards(&proposal_rewards_map, expected_balances);
    let expected_balances =
        apply_sync_committee_rewards(&sync_committee_rewards_map, expected_balances);

    // verify expected balances against actual balances
    let balances: Vec<u64> = harness.get_current_state().balances().to_vec();
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

fn apply_beacon_block_rewards(
    proposal_rewards_map: &HashMap<u64, u64>,
    expected_balances: Vec<u64>,
) -> Vec<u64> {
    let calculated_balances = expected_balances
        .iter()
        .enumerate()
        .map(|(i, balance)| balance + proposal_rewards_map.get(&(i as u64)).unwrap_or(&0u64))
        .collect();

    calculated_balances
}

fn apply_sync_committee_rewards(
    sync_committee_rewards_map: &HashMap<u64, i64>,
    expected_balances: Vec<u64>,
) -> Vec<u64> {
    let calculated_balances = expected_balances
        .iter()
        .enumerate()
        .map(|(i, balance)| {
            (*balance as i64 + sync_committee_rewards_map.get(&(i as u64)).unwrap_or(&0i64))
                .unsigned_abs()
        })
        .collect();

    calculated_balances
}
