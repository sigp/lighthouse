use crate::common::{altair::get_base_reward_per_increment, decrease_balance, increase_balance};
use crate::per_block_processing::errors::{BlockProcessingError, SyncAggregateInvalid};
use crate::{signature_sets::sync_aggregate_signature_set, VerifySignatures};
use safe_arith::SafeArith;
use std::borrow::Cow;
use types::consts::altair::{PROPOSER_WEIGHT, SYNC_REWARD_WEIGHT, WEIGHT_DENOMINATOR};
use types::{BeaconState, ChainSpec, EthSpec, PublicKeyBytes, SyncAggregate, Unsigned};

pub fn process_sync_aggregate<T: EthSpec>(
    state: &mut BeaconState<T>,
    aggregate: &SyncAggregate<T>,
    proposer_index: u64,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    let current_sync_committee = state.current_sync_committee()?.clone();

    // Verify sync committee aggregate signature signing over the previous slot block root
    if verify_signatures.is_true() {
        // This decompression could be avoided with a cache, but we're not likely
        // to encounter this case in practice due to the use of pre-emptive signature
        // verification (which uses the `ValidatorPubkeyCache`).
        let decompressor = |pk_bytes: &PublicKeyBytes| pk_bytes.decompress().ok().map(Cow::Owned);

        // Check that the signature is over the previous block root.
        let previous_slot = state.slot().saturating_sub(1u64);
        let previous_block_root = *state.get_block_root(previous_slot)?;

        let signature_set = sync_aggregate_signature_set(
            decompressor,
            aggregate,
            state.slot(),
            previous_block_root,
            state,
            spec,
        )?;

        // If signature set is `None` then the signature is valid (infinity).
        if signature_set.map_or(false, |signature| !signature.verify()) {
            return Err(SyncAggregateInvalid::SignatureInvalid.into());
        }
    }

    // Compute participant and proposer rewards
    let total_active_balance = state.get_total_active_balance()?;
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
