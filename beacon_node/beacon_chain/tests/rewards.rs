#![cfg(test)]

use beacon_chain::block_verification_types::AsBlock;
use beacon_chain::test_utils::{
    generate_deterministic_keypairs, BeaconChainHarness, EphemeralHarnessType,
};
use beacon_chain::{
    test_utils::{AttestationStrategy, BlockStrategy, RelativeSyncCommittee},
    types::{Epoch, EthSpec, Keypair, MinimalEthSpec},
    BlockError, ChainConfig, StateSkipConfig, WhenSlotSkipped,
};
use eth2::lighthouse::attestation_rewards::TotalAttestationRewards;
use eth2::lighthouse::StandardAttestationRewards;
use eth2::types::ValidatorId;
use state_processing::{BlockReplayError, BlockReplayer};
use std::array::IntoIter;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use types::{ChainSpec, ForkName, Slot};

pub const VALIDATOR_COUNT: usize = 64;

type E = MinimalEthSpec;

static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| generate_deterministic_keypairs(VALIDATOR_COUNT));

fn get_harness(spec: ChainSpec) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let chain_config = ChainConfig {
        reconstruct_historic_states: true,
        ..Default::default()
    };

    let harness = BeaconChainHarness::builder(E::default())
        .spec(Arc::new(spec))
        .keypairs(KEYPAIRS.to_vec())
        .fresh_ephemeral_store()
        .chain_config(chain_config)
        .build();

    harness.advance_slot();

    harness
}

#[tokio::test]
async fn test_sync_committee_rewards() {
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
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
async fn test_rewards_base() {
    let spec = ForkName::Base.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec);
    let initial_balances = harness.get_current_state().balances().to_vec();

    harness
        .extend_slots(E::slots_per_epoch() as usize * 2 - 1)
        .await;

    check_all_base_rewards(&harness, initial_balances).await;
}

#[tokio::test]
async fn test_rewards_base_inactivity_leak() {
    let spec = ForkName::Base.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec.clone());
    let initial_balances = harness.get_current_state().balances().to_vec();

    let half = VALIDATOR_COUNT / 2;
    let half_validators: Vec<usize> = (0..half).collect();
    // target epoch is the epoch where the chain enters inactivity leak
    let target_epoch = &spec.min_epochs_to_inactivity_penalty + 1;

    // advance until end of target epoch
    harness
        .extend_slots_some_validators(
            ((E::slots_per_epoch() * target_epoch) - 1) as usize,
            half_validators.clone(),
        )
        .await;

    check_all_base_rewards(&harness, initial_balances).await;
}

#[tokio::test]
async fn test_rewards_base_inactivity_leak_justification_epoch() {
    let spec = ForkName::Base.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec.clone());
    let initial_balances = harness.get_current_state().balances().to_vec();

    let half = VALIDATOR_COUNT / 2;
    let half_validators: Vec<usize> = (0..half).collect();
    // target epoch is the epoch where the chain enters inactivity leak
    let mut target_epoch = &spec.min_epochs_to_inactivity_penalty + 1;

    // advance until end of target epoch
    harness
        .extend_chain(
            ((E::slots_per_epoch() * target_epoch) - 1) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(half_validators.clone()),
        )
        .await;

    // advance to create first justification epoch
    harness.extend_slots(E::slots_per_epoch() as usize).await;
    target_epoch += 1;

    // assert previous_justified_checkpoint matches 0 as we were in inactivity leak from beginning
    assert_eq!(
        0,
        harness
            .get_current_state()
            .previous_justified_checkpoint()
            .epoch
            .as_u64()
    );

    // extend slots to end of epoch target_epoch + 2
    harness.extend_slots(E::slots_per_epoch() as usize).await;

    check_all_base_rewards(&harness, initial_balances).await;

    // assert target epoch and previous_justified_checkpoint match
    assert_eq!(
        target_epoch,
        harness
            .get_current_state()
            .previous_justified_checkpoint()
            .epoch
            .as_u64()
    );
}

#[tokio::test]
async fn test_rewards_base_slashings() {
    let spec = ForkName::Base.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec);
    let mut initial_balances = harness.get_current_state().balances().to_vec();

    harness
        .extend_slots(E::slots_per_epoch() as usize - 1)
        .await;

    harness.add_attester_slashing(vec![0]).unwrap();
    let slashed_balance = initial_balances.get_mut(0).unwrap();
    *slashed_balance -= *slashed_balance / harness.spec.min_slashing_penalty_quotient;

    harness.extend_slots(E::slots_per_epoch() as usize).await;

    check_all_base_rewards(&harness, initial_balances).await;
}

#[tokio::test]
async fn test_rewards_base_multi_inclusion() {
    let spec = ForkName::Base.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec);
    let initial_balances = harness.get_current_state().balances().to_vec();

    harness.extend_slots(2).await;

    let prev_block = harness.chain.head_beacon_block();

    harness.extend_slots(1).await;

    harness.advance_slot();
    let slot = harness.get_current_slot();
    let mut block =
        // pin to reduce stack size for clippy
        Box::pin(
            harness.make_block_with_modifier(harness.get_current_state(), slot, |block| {
                // add one attestation from the same block
                let attestations = &mut block.body_base_mut().unwrap().attestations;
                attestations
                    .push(attestations.first().unwrap().clone())
                    .unwrap();

                // add one attestation from the previous block
                let attestation = prev_block
                    .as_block()
                    .message_base()
                    .unwrap()
                    .body
                    .attestations
                    .first()
                    .unwrap()
                    .clone();
                attestations.push(attestation).unwrap();
            }),
        )
        .await
        .0;

    // funky hack: on first try, the state root will mismatch due to our modification
    // thankfully, the correct state root is reported back, so we just take that one :^)
    // there probably is a better way...
    let Err(BlockError::StateRootMismatch { local, .. }) = harness
        .process_block(slot, block.0.canonical_root(), block.clone())
        .await
    else {
        panic!("unexpected match of state root");
    };
    let mut new_block = block.0.message_base().unwrap().clone();
    new_block.state_root = local;
    block.0 = Arc::new(harness.sign_beacon_block(new_block.into(), &harness.get_current_state()));
    harness
        .process_block(slot, block.0.canonical_root(), block.clone())
        .await
        .unwrap();

    harness
        .extend_slots(E::slots_per_epoch() as usize * 2 - 4)
        .await;

    // pin to reduce stack size for clippy
    Box::pin(check_all_base_rewards(&harness, initial_balances)).await;
}

#[tokio::test]
async fn test_rewards_altair() {
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec.clone());
    let target_epoch = 0;

    // advance until epoch N + 1 and get initial balances
    harness
        .extend_slots((E::slots_per_epoch() * (target_epoch + 1)) as usize)
        .await;
    let mut expected_balances = harness.get_current_state().balances().to_vec();

    // advance until epoch N + 2 and build proposal rewards map
    let mut proposal_rewards_map = HashMap::new();
    let mut sync_committee_rewards_map = HashMap::new();
    for _ in 0..E::slots_per_epoch() {
        let state = harness.get_current_state();
        let slot = state.slot() + Slot::new(1);

        // calculate beacon block rewards / penalties
        let ((signed_block, _maybe_blob_sidecars), mut state) =
            harness.make_block_return_pre_state(state, slot).await;
        let beacon_block_reward = harness
            .chain
            .compute_beacon_block_reward(signed_block.message(), &mut state)
            .unwrap();

        let total_proposer_reward = proposal_rewards_map
            .entry(beacon_block_reward.proposer_index)
            .or_insert(0);
        *total_proposer_reward += beacon_block_reward.total as i64;

        // calculate sync committee rewards / penalties
        let reward_payload = harness
            .chain
            .compute_sync_committee_rewards(signed_block.message(), &mut state)
            .unwrap();

        for reward in reward_payload {
            let total_sync_reward = sync_committee_rewards_map
                .entry(reward.validator_index)
                .or_insert(0);
            *total_sync_reward += reward.reward;
        }

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
    apply_attestation_rewards(&mut expected_balances, total_rewards);
    apply_other_rewards(&mut expected_balances, &proposal_rewards_map);
    apply_other_rewards(&mut expected_balances, &sync_committee_rewards_map);

    // verify expected balances against actual balances
    let balances: Vec<u64> = harness.get_current_state().balances().to_vec();

    assert_eq!(expected_balances, balances);
}

#[tokio::test]
async fn test_rewards_altair_inactivity_leak() {
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
    let mut expected_balances = harness.get_current_state().balances().to_vec();

    // advance until epoch N + 2 and build proposal rewards map
    let mut proposal_rewards_map = HashMap::new();
    let mut sync_committee_rewards_map = HashMap::new();
    for _ in 0..E::slots_per_epoch() {
        let state = harness.get_current_state();
        let slot = state.slot() + Slot::new(1);

        // calculate beacon block rewards / penalties
        let ((signed_block, _maybe_blob_sidecars), mut state) =
            harness.make_block_return_pre_state(state, slot).await;
        let beacon_block_reward = harness
            .chain
            .compute_beacon_block_reward(signed_block.message(), &mut state)
            .unwrap();

        let total_proposer_reward = proposal_rewards_map
            .entry(beacon_block_reward.proposer_index)
            .or_insert(0i64);
        *total_proposer_reward += beacon_block_reward.total as i64;

        // calculate sync committee rewards / penalties
        let reward_payload = harness
            .chain
            .compute_sync_committee_rewards(signed_block.message(), &mut state)
            .unwrap();

        for reward in reward_payload {
            let total_sync_reward = sync_committee_rewards_map
                .entry(reward.validator_index)
                .or_insert(0);
            *total_sync_reward += reward.reward;
        }

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
    apply_attestation_rewards(&mut expected_balances, total_rewards);
    apply_other_rewards(&mut expected_balances, &proposal_rewards_map);
    apply_other_rewards(&mut expected_balances, &sync_committee_rewards_map);

    // verify expected balances against actual balances
    let balances: Vec<u64> = harness.get_current_state().balances().to_vec();

    assert_eq!(expected_balances, balances);
}

#[tokio::test]
async fn test_rewards_altair_inactivity_leak_justification_epoch() {
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
    let mut expected_balances = harness.get_current_state().balances().to_vec();

    // advance until epoch N + 2 and build proposal rewards map
    let mut proposal_rewards_map = HashMap::new();
    let mut sync_committee_rewards_map = HashMap::new();
    for _ in 0..E::slots_per_epoch() {
        let state = harness.get_current_state();
        let slot = state.slot() + Slot::new(1);

        // calculate beacon block rewards / penalties
        let ((signed_block, _maybe_blob_sidecars), mut state) =
            harness.make_block_return_pre_state(state, slot).await;
        let beacon_block_reward = harness
            .chain
            .compute_beacon_block_reward(signed_block.message(), &mut state)
            .unwrap();

        let total_proposer_reward = proposal_rewards_map
            .entry(beacon_block_reward.proposer_index)
            .or_insert(0);
        *total_proposer_reward += beacon_block_reward.total as i64;

        // calculate sync committee rewards / penalties
        let reward_payload = harness
            .chain
            .compute_sync_committee_rewards(signed_block.message(), &mut state)
            .unwrap();

        for reward in reward_payload {
            let total_sync_reward = sync_committee_rewards_map
                .entry(reward.validator_index)
                .or_insert(0);
            *total_sync_reward += reward.reward;
        }

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
    apply_attestation_rewards(&mut expected_balances, total_rewards);
    apply_other_rewards(&mut expected_balances, &proposal_rewards_map);
    apply_other_rewards(&mut expected_balances, &sync_committee_rewards_map);

    // verify expected balances against actual balances
    let balances: Vec<u64> = harness.get_current_state().balances().to_vec();
    assert_eq!(expected_balances, balances);
}

#[tokio::test]
async fn test_rewards_base_subset_only() {
    let spec = ForkName::Base.make_genesis_spec(E::default_spec());
    let harness = get_harness(spec);
    let initial_balances = harness.get_current_state().balances().to_vec();

    // a subset of validators to compute attestation rewards for
    let validators_subset = (0..16).chain(56..64).collect::<Vec<_>>();

    // epoch 0 (N), only two thirds of validators vote.
    let two_thirds = (VALIDATOR_COUNT / 3) * 2;
    let two_thirds_validators: Vec<usize> = (0..two_thirds).collect();
    harness
        .extend_slots_some_validators(E::slots_per_epoch() as usize, two_thirds_validators.clone())
        .await;

    check_all_base_rewards_for_subset(&harness, initial_balances, validators_subset).await;
}

async fn check_all_base_rewards(
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    balances: Vec<u64>,
) {
    check_all_base_rewards_for_subset(harness, balances, vec![]).await;
}

async fn check_all_base_rewards_for_subset(
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    mut balances: Vec<u64>,
    validator_subset: Vec<u64>,
) {
    let validator_subset_ids: Vec<ValidatorId> = validator_subset
        .iter()
        .map(|&idx| ValidatorId::Index(idx))
        .collect();

    // capture the amount of epochs generated by the caller
    let epochs = harness.get_current_slot().epoch(E::slots_per_epoch()) + 1;

    // advance two empty epochs to ensure balances are updated by the epoch boundaries
    for _ in 0..E::slots_per_epoch() * 2 {
        harness.advance_slot();
    }
    // fill one slot to ensure state is updated
    harness.extend_slots(1).await;

    // calculate proposal awards
    let mut proposal_rewards_map = HashMap::new();
    for slot in 1..(E::slots_per_epoch() * epochs.as_u64()) {
        if let Some(block) = harness
            .chain
            .block_at_slot(Slot::new(slot), WhenSlotSkipped::None)
            .unwrap()
        {
            let parent_state = harness
                .chain
                .state_at_slot(Slot::new(slot - 1), StateSkipConfig::WithoutStateRoots)
                .unwrap();

            let mut pre_state = BlockReplayer::<E, BlockReplayError, IntoIter<_, 0>>::new(
                parent_state,
                &harness.spec,
            )
            .no_signature_verification()
            .minimal_block_root_verification()
            .apply_blocks(vec![], Some(block.slot()))
            .unwrap()
            .into_state();

            let beacon_block_reward = harness
                .chain
                .compute_beacon_block_reward(block.message(), &mut pre_state)
                .unwrap();
            let total_proposer_reward = proposal_rewards_map
                .entry(beacon_block_reward.proposer_index)
                .or_insert(0);
            *total_proposer_reward += beacon_block_reward.total as i64;
        }
    }
    apply_other_rewards(&mut balances, &proposal_rewards_map);

    for epoch in 0..epochs.as_u64() {
        // compute reward deltas in epoch
        let total_rewards = harness
            .chain
            .compute_attestation_rewards(Epoch::new(epoch), validator_subset_ids.clone())
            .unwrap()
            .total_rewards;

        // apply attestation rewards to balances
        apply_attestation_rewards(&mut balances, total_rewards);
    }

    // verify expected balances against actual balances
    let actual_balances: Vec<u64> = harness.get_current_state().balances().to_vec();
    if validator_subset.is_empty() {
        assert_eq!(balances, actual_balances);
    } else {
        for validator in validator_subset {
            assert_eq!(
                balances[validator as usize],
                actual_balances[validator as usize]
            );
        }
    }
}

/// Apply a vec of `TotalAttestationRewards` to initial balances, and return
fn apply_attestation_rewards(
    balances: &mut [u64],
    attestation_rewards: Vec<TotalAttestationRewards>,
) {
    for rewards in attestation_rewards {
        let balance = balances.get_mut(rewards.validator_index as usize).unwrap();
        *balance = (*balance as i64
            + rewards.head
            + rewards.source
            + rewards.target
            + rewards.inclusion_delay.map(|q| q.value).unwrap_or(0) as i64
            + rewards.inactivity) as u64;
    }
}

fn apply_other_rewards(balances: &mut [u64], rewards_map: &HashMap<u64, i64>) {
    for (i, balance) in balances.iter_mut().enumerate() {
        *balance = balance.saturating_add_signed(*rewards_map.get(&(i as u64)).unwrap_or(&0));
    }
}
