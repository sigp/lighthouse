use crate::common::{altair::get_base_reward_per_increment, increase_balance};
use crate::per_block_processing::errors::{BlockProcessingError, SyncAggregateInvalid};
use crate::per_epoch_processing::altair::rewards_and_penalties::{
    SYNC_REWARD_WEIGHT, WEIGHT_DENOMINATOR,
};
use itertools::Itertools;
use safe_arith::SafeArith;
use tree_hash::TreeHash;
use types::{BeaconState, ChainSpec, Domain, EthSpec, SigningData, SyncAggregate};

pub fn process_sync_committee<T: EthSpec>(
    state: &mut BeaconState<T>,
    aggregate: &SyncAggregate<T>,
    proposer_index: u64,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    // Verify sync committee aggregate signature signing over the previous slot block root
    state.build_current_sync_committee_cache(spec)?;

    let previous_slot = state.slot().saturating_sub(1u64);

    let committee_indices = state.get_current_sync_committee_indices(spec)?;

    let included_indices = committee_indices
        .iter()
        .zip(aggregate.sync_committee_bits.iter())
        .flat_map(|(index, bit)| Some(*index).filter(|_| bit))
        .collect_vec();

    let committee_pubkeys = &state.as_altair()?.current_sync_committee.pubkeys;

    let included_pubkeys = committee_pubkeys
        .iter()
        .zip(aggregate.sync_committee_bits.iter())
        .flat_map(|(pubkey, bit)| {
            if bit {
                // FIXME(altair): accelerate pubkey decompression with a cache
                Some(pubkey.decompress())
            } else {
                None
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SyncAggregateInvalid::PubkeyInvalid)?;

    let domain = spec.get_domain(
        previous_slot.epoch(T::slots_per_epoch()),
        Domain::SyncCommittee,
        &state.fork(),
        state.genesis_validators_root(),
    );

    let signing_root = SigningData {
        object_root: *state.get_block_root(previous_slot)?,
        domain,
    }
    .tree_hash_root();

    let pubkey_refs = included_pubkeys.iter().collect::<Vec<_>>();
    if !aggregate
        .sync_committee_signature
        .eth2_fast_aggregate_verify(signing_root, &pubkey_refs)
    {
        return Err(SyncAggregateInvalid::SignatureInvalid.into());
    }

    // Compute the maximum sync rewards for the slot
    let total_active_balance = state.get_total_active_balance(spec)?;
    let total_active_increments =
        total_active_balance.safe_div(spec.effective_balance_increment)?;
    let total_base_rewards = get_base_reward_per_increment(total_active_balance, spec)?
        .safe_mul(total_active_increments)?;
    let max_epoch_rewards = total_base_rewards
        .safe_mul(SYNC_REWARD_WEIGHT)?
        .safe_div(WEIGHT_DENOMINATOR)?;
    let max_slot_rewards = max_epoch_rewards
        .safe_mul(included_indices.len() as u64)?
        .safe_div(committee_indices.len() as u64)?
        .safe_div(T::slots_per_epoch())?;

    // Compute the participant and proposer sync rewards
    let committee_effective_balance = state.get_total_balance(&included_indices, spec)?;
    for included_index in included_indices {
        let effective_balance = state.validators()[included_index].effective_balance;
        let inclusion_reward = max_slot_rewards
            .safe_mul(effective_balance)?
            .safe_div(committee_effective_balance)?;
        let proposer_reward = inclusion_reward.safe_div(spec.proposer_reward_quotient)?;
        increase_balance(state, proposer_index as usize, proposer_reward)?;
        increase_balance(
            state,
            included_index as usize,
            inclusion_reward.safe_sub(proposer_reward)?,
        )?;
    }

    Ok(())
}
