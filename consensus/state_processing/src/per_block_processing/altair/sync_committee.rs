use crate::common::{altair::get_base_reward_per_increment, decrease_balance, increase_balance};
use crate::per_block_processing::errors::{BlockProcessingError, SyncAggregateInvalid};
use safe_arith::SafeArith;
use tree_hash::TreeHash;
use types::consts::altair::{PROPOSER_WEIGHT, SYNC_REWARD_WEIGHT, WEIGHT_DENOMINATOR};
use types::{BeaconState, ChainSpec, Domain, EthSpec, SigningData, SyncAggregate, Unsigned};

pub fn process_sync_aggregate<T: EthSpec>(
    state: &mut BeaconState<T>,
    aggregate: &SyncAggregate<T>,
    proposer_index: u64,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    // Verify sync committee aggregate signature signing over the previous slot block root
    let previous_slot = state.slot().saturating_sub(1u64);

    let current_sync_committee = state.current_sync_committee()?.clone();
    let committee_pubkeys = &current_sync_committee.pubkeys;

    let participant_pubkeys = committee_pubkeys
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

    let pubkey_refs = participant_pubkeys.iter().collect::<Vec<_>>();
    if !aggregate
        .sync_committee_signature
        .eth2_fast_aggregate_verify(signing_root, &pubkey_refs)
    {
        return Err(SyncAggregateInvalid::SignatureInvalid.into());
    }

    // Compute participant and proposer rewards
    let total_active_balance = state.get_total_active_balance(spec)?;
    let total_active_increments =
        total_active_balance.safe_div(spec.effective_balance_increment)?;
    let total_base_rewards = get_base_reward_per_increment(total_active_balance, spec)?
        .safe_mul(total_active_increments)?;
    let max_participant_rewards = total_base_rewards
        .safe_mul(SYNC_REWARD_WEIGHT)?
        .safe_div(WEIGHT_DENOMINATOR)?
        .safe_div(T::slots_per_epoch())?;
    let participant_reward = max_participant_rewards.safe_div(T::SyncCommitteeSize::to_u64())?;
    let proposer_reward = participant_reward
        .safe_mul(PROPOSER_WEIGHT)?
        .safe_div(WEIGHT_DENOMINATOR.safe_sub(PROPOSER_WEIGHT)?)?;

    // Apply participant and proposer rewards
    let committee_indices = state.get_sync_committee_indices(&current_sync_committee)?;

    for (participant_index, participation_bit) in committee_indices
        .into_iter()
        .zip(aggregate.sync_committee_bits.iter())
    {
        if participation_bit {
            increase_balance(state, participant_index as usize, participant_reward)?;
            increase_balance(state, proposer_index as usize, proposer_reward)?;
        } else {
            decrease_balance(state, participant_index as usize, participant_reward)?;
        }
    }

    Ok(())
}
