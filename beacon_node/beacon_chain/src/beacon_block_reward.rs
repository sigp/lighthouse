use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, StateSkipConfig};
use attesting_indices_base::get_attesting_indices;
use eth2::lighthouse::StandardBlockReward;
use safe_arith::SafeArith;
use slog::error;
use state_processing::common::attesting_indices_base;
use state_processing::{
    common::{
        base::{self, SqrtTotalActiveBalance},
        get_attestation_participation_flag_indices, get_attesting_indices_from_state,
    },
    epoch_cache::initialize_epoch_cache,
    per_block_processing::{
        altair::sync_committee::compute_sync_aggregate_rewards, get_slashable_indices,
    },
};
use std::collections::HashSet;
use store::{
    consts::altair::{PARTICIPATION_FLAG_WEIGHTS, PROPOSER_WEIGHT, WEIGHT_DENOMINATOR},
    RelativeEpoch,
};
use types::{AbstractExecPayload, BeaconBlockRef, BeaconState, BeaconStateError, EthSpec};

type BeaconBlockSubRewardValue = u64;

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn compute_beacon_block_reward<Payload: AbstractExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &mut BeaconState<T::EthSpec>,
    ) -> Result<StandardBlockReward, BeaconChainError> {
        if block.slot() != state.slot() {
            return Err(BeaconChainError::BlockRewardSlotError);
        }

        state.build_committee_cache(RelativeEpoch::Previous, &self.spec)?;
        state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;
        initialize_epoch_cache(state, &self.spec)?;

        self.compute_beacon_block_reward_with_cache(block, state)
    }

    // This should only be called after a committee cache has been built
    // for both the previous and current epoch
    fn compute_beacon_block_reward_with_cache<Payload: AbstractExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<StandardBlockReward, BeaconChainError> {
        let proposer_index = block.proposer_index();

        let sync_aggregate_reward =
            self.compute_beacon_block_sync_aggregate_reward(block, state)?;

        let proposer_slashing_reward = self
            .compute_beacon_block_proposer_slashing_reward(block, state)
            .map_err(|e| {
                error!(
                self.log,
                "Error calculating proposer slashing reward";
                "error" => ?e
                );
                BeaconChainError::BlockRewardError
            })?;

        let attester_slashing_reward = self
            .compute_beacon_block_attester_slashing_reward(block, state)
            .map_err(|e| {
                error!(
                self.log,
                "Error calculating attester slashing reward";
                "error" => ?e
                );
                BeaconChainError::BlockRewardError
            })?;

        let block_attestation_reward = if let BeaconState::Base(_) = state {
            self.compute_beacon_block_attestation_reward_base(block, state)
                .map_err(|e| {
                    error!(
                        self.log,
                        "Error calculating base block attestation reward";
                        "error" => ?e
                    );
                    BeaconChainError::BlockRewardAttestationError
                })?
        } else {
            self.compute_beacon_block_attestation_reward_altair_deneb(block, state)
                .map_err(|e| {
                    error!(
                        self.log,
                        "Error calculating altair block attestation reward";
                        "error" => ?e
                    );
                    BeaconChainError::BlockRewardAttestationError
                })?
        };

        let total_reward = sync_aggregate_reward
            .safe_add(proposer_slashing_reward)?
            .safe_add(attester_slashing_reward)?
            .safe_add(block_attestation_reward)?;

        Ok(StandardBlockReward {
            proposer_index,
            total: total_reward,
            attestations: block_attestation_reward,
            sync_aggregate: sync_aggregate_reward,
            proposer_slashings: proposer_slashing_reward,
            attester_slashings: attester_slashing_reward,
        })
    }

    fn compute_beacon_block_sync_aggregate_reward<Payload: AbstractExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<BeaconBlockSubRewardValue, BeaconChainError> {
        if let Ok(sync_aggregate) = block.body().sync_aggregate() {
            let (_, proposer_reward_per_bit) = compute_sync_aggregate_rewards(state, &self.spec)
                .map_err(|_| BeaconChainError::BlockRewardSyncError)?;
            Ok(sync_aggregate.sync_committee_bits.num_set_bits() as u64 * proposer_reward_per_bit)
        } else {
            Ok(0)
        }
    }

    fn compute_beacon_block_proposer_slashing_reward<Payload: AbstractExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<BeaconBlockSubRewardValue, BeaconChainError> {
        let mut proposer_slashing_reward = 0;

        let proposer_slashings = block.body().proposer_slashings();

        for proposer_slashing in proposer_slashings {
            proposer_slashing_reward.safe_add_assign(
                state
                    .get_validator(proposer_slashing.proposer_index() as usize)?
                    .effective_balance
                    .safe_div(self.spec.whistleblower_reward_quotient)?,
            )?;
        }

        Ok(proposer_slashing_reward)
    }

    fn compute_beacon_block_attester_slashing_reward<Payload: AbstractExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<BeaconBlockSubRewardValue, BeaconChainError> {
        let mut attester_slashing_reward = 0;

        let attester_slashings = block.body().attester_slashings();

        for attester_slashing in attester_slashings {
            for attester_index in get_slashable_indices(state, attester_slashing)? {
                attester_slashing_reward.safe_add_assign(
                    state
                        .get_validator(attester_index as usize)?
                        .effective_balance
                        .safe_div(self.spec.whistleblower_reward_quotient)?,
                )?;
            }
        }

        Ok(attester_slashing_reward)
    }

    fn compute_beacon_block_attestation_reward_base<Payload: AbstractExecPayload<T::EthSpec>>(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<BeaconBlockSubRewardValue, BeaconChainError> {
        // In phase0, rewards for including attestations are awarded at epoch boundaries when the corresponding
        // attestations are contained in state.previous_epoch_attestations. So, if an attestation within this block has
        // target = previous_epoch, it is directly inserted into previous_epoch_attestations and we need the state at
        // the end of this epoch, or the attestation has target = current_epoch and thus we need the state at the end
        // of the next epoch.
        // We fetch these lazily, as only one might be needed depending on the block's content.
        let mut current_epoch_end = None;
        let mut next_epoch_end = None;

        let epoch = block.epoch();
        let mut block_reward = 0;

        let mut rewarded_attesters = HashSet::new();

        for attestation in block.body().attestations() {
            let processing_epoch_end = if attestation.data().target.epoch == epoch {
                let next_epoch_end = match &mut next_epoch_end {
                    Some(next_epoch_end) => next_epoch_end,
                    None => {
                        let state = self.state_at_slot(
                            epoch.safe_add(1)?.end_slot(T::EthSpec::slots_per_epoch()),
                            StateSkipConfig::WithoutStateRoots,
                        )?;
                        next_epoch_end.get_or_insert(state)
                    }
                };

                // If the next epoch end is no longer phase0, no proposer rewards are awarded, as Altair epoch boundry
                // processing kicks in. We check this here, as we know that current_epoch_end will always be phase0.
                if !matches!(next_epoch_end, BeaconState::Base(_)) {
                    continue;
                }

                next_epoch_end
            } else if attestation.data().target.epoch == epoch.safe_sub(1)? {
                match &mut current_epoch_end {
                    Some(current_epoch_end) => current_epoch_end,
                    None => {
                        let state = self.state_at_slot(
                            epoch.end_slot(T::EthSpec::slots_per_epoch()),
                            StateSkipConfig::WithoutStateRoots,
                        )?;
                        current_epoch_end.get_or_insert(state)
                    }
                }
            } else {
                return Err(BeaconChainError::BlockRewardAttestationError);
            };

            let inclusion_delay = state.slot().safe_sub(attestation.data().slot)?.as_u64();
            let sqrt_total_active_balance =
                SqrtTotalActiveBalance::new(processing_epoch_end.get_total_active_balance()?);
            for attester in get_attesting_indices_from_state(state, attestation, &self.spec)? {
                let validator = processing_epoch_end.get_validator(attester as usize)?;
                if !validator.slashed
                    && !rewarded_attesters.contains(&attester)
                    && !has_earlier_attestation(
                        state,
                        processing_epoch_end,
                        inclusion_delay,
                        attester,
                    )?
                {
                    let base_reward = base::get_base_reward(
                        validator.effective_balance,
                        sqrt_total_active_balance,
                        &self.spec,
                    )?;
                    let proposer_reward =
                        base_reward.safe_div(self.spec.proposer_reward_quotient)?;
                    block_reward.safe_add_assign(proposer_reward)?;
                    rewarded_attesters.insert(attester);
                }
            }
        }

        Ok(block_reward)
    }

    fn compute_beacon_block_attestation_reward_altair_deneb<
        Payload: AbstractExecPayload<T::EthSpec>,
    >(
        &self,
        block: BeaconBlockRef<'_, T::EthSpec, Payload>,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<BeaconBlockSubRewardValue, BeaconChainError> {
        let mut total_proposer_reward = 0;

        let proposer_reward_denominator = WEIGHT_DENOMINATOR
            .safe_sub(PROPOSER_WEIGHT)?
            .safe_mul(WEIGHT_DENOMINATOR)?
            .safe_div(PROPOSER_WEIGHT)?;

        let mut current_epoch_participation = state.current_epoch_participation()?.clone();
        let mut previous_epoch_participation = state.previous_epoch_participation()?.clone();

        for attestation in block.body().attestations() {
            let data = attestation.data();
            let inclusion_delay = state.slot().safe_sub(data.slot)?.as_u64();
            // [Modified in Deneb:EIP7045]
            let participation_flag_indices = get_attestation_participation_flag_indices(
                state,
                data,
                inclusion_delay,
                &self.spec,
            )?;

            let attesting_indices =
                get_attesting_indices_from_state(state, attestation, &self.spec)?;
            let mut proposer_reward_numerator = 0;
            for index in attesting_indices {
                let index = index as usize;
                for (flag_index, &weight) in PARTICIPATION_FLAG_WEIGHTS.iter().enumerate() {
                    let epoch_participation = if data.target.epoch == state.current_epoch() {
                        &mut current_epoch_participation
                    } else {
                        &mut previous_epoch_participation
                    };

                    let validator_participation = epoch_participation
                        .get_mut(index)
                        .ok_or(BeaconStateError::ParticipationOutOfBounds(index))?;

                    if participation_flag_indices.contains(&flag_index)
                        && !validator_participation.has_flag(flag_index)?
                    {
                        validator_participation.add_flag(flag_index)?;
                        proposer_reward_numerator
                            .safe_add_assign(state.get_base_reward(index)?.safe_mul(weight)?)?;
                    }
                }
            }
            total_proposer_reward.safe_add_assign(
                proposer_reward_numerator.safe_div(proposer_reward_denominator)?,
            )?;
        }

        Ok(total_proposer_reward)
    }
}

fn has_earlier_attestation<E: EthSpec>(
    state: &BeaconState<E>,
    processing_epoch_end: &BeaconState<E>,
    inclusion_delay: u64,
    attester: u64,
) -> Result<bool, BeaconChainError> {
    if inclusion_delay > 1 {
        for epoch_att in processing_epoch_end.previous_epoch_attestations()? {
            if epoch_att.inclusion_delay < inclusion_delay {
                let committee =
                    state.get_beacon_committee(epoch_att.data.slot, epoch_att.data.index)?;
                let earlier_attesters =
                    get_attesting_indices::<E>(committee.committee, &epoch_att.aggregation_bits)?;
                if earlier_attesters.contains(&attester) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}
