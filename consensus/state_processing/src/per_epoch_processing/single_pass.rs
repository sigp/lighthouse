use crate::{
    common::{
        decrease_balance, increase_balance,
        update_progressive_balances_cache::initialize_progressive_balances_cache,
    },
    epoch_cache::{initialize_epoch_cache, PreEpochCache},
    per_block_processing::is_valid_deposit_signature,
    per_epoch_processing::{Delta, Error, ParticipationEpochSummary},
};
use itertools::izip;
use safe_arith::{SafeArith, SafeArithIter};
use std::cmp::{max, min};
use std::collections::{BTreeSet, HashMap};
use types::{
    consts::altair::{
        NUM_FLAG_INDICES, PARTICIPATION_FLAG_WEIGHTS, TIMELY_HEAD_FLAG_INDEX,
        TIMELY_TARGET_FLAG_INDEX, WEIGHT_DENOMINATOR,
    },
    milhouse::Cow,
    ActivationQueue, BeaconState, BeaconStateError, ChainSpec, Checkpoint, DepositData, Epoch,
    EthSpec, ExitCache, ForkName, List, ParticipationFlags, PendingDeposit,
    ProgressiveBalancesCache, RelativeEpoch, Unsigned, Validator,
};

pub struct SinglePassConfig {
    pub inactivity_updates: bool,
    pub rewards_and_penalties: bool,
    pub registry_updates: bool,
    pub slashings: bool,
    pub pending_deposits: bool,
    pub pending_consolidations: bool,
    pub effective_balance_updates: bool,
}

impl Default for SinglePassConfig {
    fn default() -> SinglePassConfig {
        Self::enable_all()
    }
}

impl SinglePassConfig {
    pub fn enable_all() -> SinglePassConfig {
        Self {
            inactivity_updates: true,
            rewards_and_penalties: true,
            registry_updates: true,
            slashings: true,
            pending_deposits: true,
            pending_consolidations: true,
            effective_balance_updates: true,
        }
    }

    pub fn disable_all() -> SinglePassConfig {
        SinglePassConfig {
            inactivity_updates: false,
            rewards_and_penalties: false,
            registry_updates: false,
            slashings: false,
            pending_deposits: false,
            pending_consolidations: false,
            effective_balance_updates: false,
        }
    }
}

/// Values from the state that are immutable throughout epoch processing.
struct StateContext {
    current_epoch: Epoch,
    next_epoch: Epoch,
    finalized_checkpoint: Checkpoint,
    is_in_inactivity_leak: bool,
    total_active_balance: u64,
    churn_limit: u64,
    fork_name: ForkName,
}

struct RewardsAndPenaltiesContext {
    unslashed_participating_increments_array: [u64; NUM_FLAG_INDICES],
    active_increments: u64,
}

struct SlashingsContext {
    adjusted_total_slashing_balance: u64,
    target_withdrawable_epoch: Epoch,
    penalty_per_effective_balance_increment: u64,
}

struct PendingDepositsContext {
    /// The value to set `next_deposit_index` to *after* processing completes.
    next_deposit_index: usize,
    /// The value to set `deposit_balance_to_consume` to *after* processing completes.
    deposit_balance_to_consume: u64,
    /// Total balance increases for each validator due to pending balance deposits.
    validator_deposits_to_process: HashMap<usize, u64>,
    /// The deposits to append to `pending_deposits` after processing all applicable deposits.
    deposits_to_postpone: Vec<PendingDeposit>,
    /// New validators to be added to the state *after* processing completes.
    new_validator_deposits: Vec<PendingDeposit>,
}

struct EffectiveBalancesContext {
    downward_threshold: u64,
    upward_threshold: u64,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ValidatorInfo {
    pub index: usize,
    pub effective_balance: u64,
    pub base_reward: u64,
    pub is_eligible: bool,
    pub is_slashed: bool,
    pub is_active_current_epoch: bool,
    pub is_active_previous_epoch: bool,
    // Used for determining rewards.
    pub previous_epoch_participation: ParticipationFlags,
    // Used for updating the progressive balances cache for next epoch.
    pub current_epoch_participation: ParticipationFlags,
}

impl ValidatorInfo {
    #[inline]
    pub fn is_unslashed_participating_index(&self, flag_index: usize) -> Result<bool, Error> {
        Ok(self.is_active_previous_epoch
            && !self.is_slashed
            && self
                .previous_epoch_participation
                .has_flag(flag_index)
                .map_err(|_| Error::InvalidFlagIndex(flag_index))?)
    }
}

pub fn process_epoch_single_pass<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &ChainSpec,
    conf: SinglePassConfig,
) -> Result<ParticipationEpochSummary<E>, Error> {
    initialize_epoch_cache(state, spec)?;
    initialize_progressive_balances_cache(state, spec)?;
    state.build_exit_cache(spec)?;
    state.build_committee_cache(RelativeEpoch::Previous, spec)?;
    state.build_committee_cache(RelativeEpoch::Current, spec)?;
    state.update_pubkey_cache()?;

    let previous_epoch = state.previous_epoch();
    let current_epoch = state.current_epoch();
    let next_epoch = state.next_epoch()?;
    let is_in_inactivity_leak = state.is_in_inactivity_leak(previous_epoch, spec)?;
    let total_active_balance = state.get_total_active_balance()?;
    let churn_limit = state.get_validator_churn_limit(spec)?;
    let activation_churn_limit = state.get_activation_churn_limit(spec)?;
    let finalized_checkpoint = state.finalized_checkpoint();
    let fork_name = state.fork_name_unchecked();

    let state_ctxt = &StateContext {
        current_epoch,
        next_epoch,
        finalized_checkpoint,
        is_in_inactivity_leak,
        total_active_balance,
        churn_limit,
        fork_name,
    };

    // Contexts that require immutable access to `state`.
    let slashings_ctxt = &SlashingsContext::new(state, state_ctxt, spec)?;
    let mut next_epoch_cache = PreEpochCache::new_for_next_epoch(state)?;

    let pending_deposits_ctxt = if fork_name.electra_enabled() && conf.pending_deposits {
        Some(PendingDepositsContext::new(state, spec, &conf)?)
    } else {
        None
    };

    let mut earliest_exit_epoch = state.earliest_exit_epoch().ok();
    let mut exit_balance_to_consume = state.exit_balance_to_consume().ok();

    // Split the state into several disjoint mutable borrows.
    let (
        validators,
        balances,
        previous_epoch_participation,
        current_epoch_participation,
        inactivity_scores,
        progressive_balances,
        exit_cache,
        epoch_cache,
    ) = state.mutable_validator_fields()?;

    let num_validators = validators.len();

    // Take a snapshot of the validators and participation before mutating. This is used for
    // informational purposes (e.g. by the validator monitor).
    let summary = ParticipationEpochSummary::new(
        validators.clone(),
        previous_epoch_participation.clone(),
        current_epoch_participation.clone(),
        previous_epoch,
        current_epoch,
    );

    // Compute shared values required for different parts of epoch processing.
    let rewards_ctxt = &RewardsAndPenaltiesContext::new(progressive_balances, state_ctxt, spec)?;

    let mut activation_queues = if !fork_name.electra_enabled() {
        let activation_queue = epoch_cache
            .activation_queue()?
            .get_validators_eligible_for_activation(
                finalized_checkpoint.epoch,
                activation_churn_limit as usize,
            );
        let next_epoch_activation_queue = ActivationQueue::default();
        Some((activation_queue, next_epoch_activation_queue))
    } else {
        None
    };
    let effective_balances_ctxt = &EffectiveBalancesContext::new(spec)?;

    // Iterate over the validators and related fields in one pass.
    let mut validators_iter = validators.iter_cow();
    let mut balances_iter = balances.iter_cow();
    let mut inactivity_scores_iter = inactivity_scores.iter_cow();

    for (index, &previous_epoch_participation, &current_epoch_participation) in izip!(
        0..num_validators,
        previous_epoch_participation.iter(),
        current_epoch_participation.iter(),
    ) {
        let (_, mut validator) = validators_iter
            .next_cow()
            .ok_or(BeaconStateError::UnknownValidator(index))?;
        let (_, mut balance) = balances_iter
            .next_cow()
            .ok_or(BeaconStateError::UnknownValidator(index))?;
        let (_, mut inactivity_score) = inactivity_scores_iter
            .next_cow()
            .ok_or(BeaconStateError::UnknownValidator(index))?;

        let is_active_current_epoch = validator.is_active_at(current_epoch);
        let is_active_previous_epoch = validator.is_active_at(previous_epoch);
        let is_eligible = is_active_previous_epoch
            || (validator.slashed && previous_epoch.safe_add(1)? < validator.withdrawable_epoch);

        let base_reward = if is_eligible {
            epoch_cache.get_base_reward(index)?
        } else {
            0
        };

        let validator_info = &ValidatorInfo {
            index,
            effective_balance: validator.effective_balance,
            base_reward,
            is_eligible,
            is_slashed: validator.slashed,
            is_active_current_epoch,
            is_active_previous_epoch,
            previous_epoch_participation,
            current_epoch_participation,
        };

        if current_epoch != E::genesis_epoch() {
            // `process_inactivity_updates`
            if conf.inactivity_updates {
                process_single_inactivity_update(
                    &mut inactivity_score,
                    validator_info,
                    state_ctxt,
                    spec,
                )?;
            }

            // `process_rewards_and_penalties`
            if conf.rewards_and_penalties {
                process_single_reward_and_penalty(
                    &mut balance,
                    &inactivity_score,
                    validator_info,
                    rewards_ctxt,
                    state_ctxt,
                    spec,
                )?;
            }
        }

        // `process_registry_updates`
        if conf.registry_updates {
            let activation_queue_refs = activation_queues
                .as_mut()
                .map(|(current_queue, next_queue)| (&*current_queue, next_queue));
            process_single_registry_update(
                &mut validator,
                validator_info,
                exit_cache,
                activation_queue_refs,
                state_ctxt,
                earliest_exit_epoch.as_mut(),
                exit_balance_to_consume.as_mut(),
                spec,
            )?;
        }

        // `process_slashings`
        if conf.slashings {
            process_single_slashing(&mut balance, &validator, slashings_ctxt, state_ctxt, spec)?;
        }

        // `process_pending_deposits`
        if let Some(pending_balance_deposits_ctxt) = &pending_deposits_ctxt {
            process_pending_deposits_for_validator(
                &mut balance,
                validator_info,
                pending_balance_deposits_ctxt,
            )?;
        }

        // `process_effective_balance_updates`
        if conf.effective_balance_updates {
            process_single_effective_balance_update(
                validator_info.index,
                *balance,
                &mut validator,
                validator_info.current_epoch_participation,
                &mut next_epoch_cache,
                progressive_balances,
                effective_balances_ctxt,
                state_ctxt,
                spec,
            )?;
        }
    }

    if conf.registry_updates && fork_name.electra_enabled() {
        if let Ok(earliest_exit_epoch_state) = state.earliest_exit_epoch_mut() {
            *earliest_exit_epoch_state =
                earliest_exit_epoch.ok_or(Error::MissingEarliestExitEpoch)?;
        }
        if let Ok(exit_balance_to_consume_state) = state.exit_balance_to_consume_mut() {
            *exit_balance_to_consume_state =
                exit_balance_to_consume.ok_or(Error::MissingExitBalanceToConsume)?;
        }
    }

    // Finish processing pending balance deposits if relevant.
    //
    // This *could* be reordered after `process_pending_consolidations` which pushes only to the end
    // of the `pending_deposits` list. But we may as well preserve the write ordering used
    // by the spec and do this first.
    if let Some(ctxt) = pending_deposits_ctxt {
        let mut new_balance_deposits = List::try_from_iter(
            state
                .pending_deposits()?
                .iter_from(ctxt.next_deposit_index)?
                .cloned(),
        )?;
        for deposit in ctxt.deposits_to_postpone {
            new_balance_deposits.push(deposit)?;
        }
        *state.pending_deposits_mut()? = new_balance_deposits;
        *state.deposit_balance_to_consume_mut()? = ctxt.deposit_balance_to_consume;

        // `new_validator_deposits` may contain multiple deposits with the same pubkey where
        // the first deposit creates the new validator and the others are topups.
        // Each item in the vec is a (pubkey, validator_index)
        let mut added_validators = Vec::new();
        for deposit in ctxt.new_validator_deposits {
            let deposit_data = DepositData {
                pubkey: deposit.pubkey,
                withdrawal_credentials: deposit.withdrawal_credentials,
                amount: deposit.amount,
                signature: deposit.signature,
            };
            // Only check the signature if this is the first deposit for the validator,
            // following the logic from `apply_pending_deposit` in the spec.
            if let Some(validator_index) = state.get_validator_index(&deposit_data.pubkey)? {
                state
                    .get_balance_mut(validator_index)?
                    .safe_add_assign(deposit_data.amount)?;
            } else if is_valid_deposit_signature(&deposit_data, spec).is_ok() {
                // Apply the new deposit to the state
                let validator_index = state.add_validator_to_registry(
                    deposit_data.pubkey,
                    deposit_data.withdrawal_credentials,
                    deposit_data.amount,
                    spec,
                )?;
                added_validators.push((deposit_data.pubkey, validator_index));
            }
        }
        if conf.effective_balance_updates {
            // Re-process effective balance updates for validators affected by top-up of new validators.
            let (
                validators,
                balances,
                _,
                current_epoch_participation,
                _,
                progressive_balances,
                _,
                _,
            ) = state.mutable_validator_fields()?;
            for (_, validator_index) in added_validators.iter() {
                let balance = *balances
                    .get(*validator_index)
                    .ok_or(BeaconStateError::UnknownValidator(*validator_index))?;
                let mut validator = validators
                    .get_cow(*validator_index)
                    .ok_or(BeaconStateError::UnknownValidator(*validator_index))?;
                let validator_current_epoch_participation = *current_epoch_participation
                    .get(*validator_index)
                    .ok_or(BeaconStateError::UnknownValidator(*validator_index))?;
                process_single_effective_balance_update(
                    *validator_index,
                    balance,
                    &mut validator,
                    validator_current_epoch_participation,
                    &mut next_epoch_cache,
                    progressive_balances,
                    effective_balances_ctxt,
                    state_ctxt,
                    spec,
                )?;
            }
        }
    }

    // Process consolidations outside the single-pass loop, as they depend on balances for multiple
    // validators and cannot be computed accurately inside the loop.
    if fork_name.electra_enabled() && conf.pending_consolidations {
        process_pending_consolidations(
            state,
            &mut next_epoch_cache,
            effective_balances_ctxt,
            conf.effective_balance_updates,
            state_ctxt,
            spec,
        )?;
    }

    // Finally, finish updating effective balance caches. We need this to happen *after* processing
    // of pending consolidations, which recomputes some effective balances.
    if conf.effective_balance_updates {
        let next_epoch_total_active_balance = next_epoch_cache.get_total_active_balance();
        state.set_total_active_balance(next_epoch, next_epoch_total_active_balance, spec);
        let next_epoch_activation_queue =
            activation_queues.map_or_else(ActivationQueue::default, |(_, queue)| queue);
        *state.epoch_cache_mut() =
            next_epoch_cache.into_epoch_cache(next_epoch_activation_queue, spec)?;
    }

    Ok(summary)
}

fn process_single_inactivity_update(
    inactivity_score: &mut Cow<u64>,
    validator_info: &ValidatorInfo,
    state_ctxt: &StateContext,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if !validator_info.is_eligible {
        return Ok(());
    }

    // Increase inactivity score of inactive validators
    if validator_info.is_unslashed_participating_index(TIMELY_TARGET_FLAG_INDEX)? {
        // Avoid mutating when the inactivity score is 0 and can't go any lower -- the common
        // case.
        if **inactivity_score == 0 {
            return Ok(());
        }
        inactivity_score.make_mut()?.safe_sub_assign(1)?;
    } else {
        inactivity_score
            .make_mut()?
            .safe_add_assign(spec.inactivity_score_bias)?;
    }

    // Decrease the score of all validators for forgiveness when not during a leak
    if !state_ctxt.is_in_inactivity_leak {
        let deduction = min(spec.inactivity_score_recovery_rate, **inactivity_score);
        inactivity_score.make_mut()?.safe_sub_assign(deduction)?;
    }

    Ok(())
}

fn process_single_reward_and_penalty(
    balance: &mut Cow<u64>,
    inactivity_score: &u64,
    validator_info: &ValidatorInfo,
    rewards_ctxt: &RewardsAndPenaltiesContext,
    state_ctxt: &StateContext,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if !validator_info.is_eligible {
        return Ok(());
    }

    let mut delta = Delta::default();
    for flag_index in 0..NUM_FLAG_INDICES {
        get_flag_index_delta(
            &mut delta,
            validator_info,
            flag_index,
            rewards_ctxt,
            state_ctxt,
        )?;
    }
    get_inactivity_penalty_delta(
        &mut delta,
        validator_info,
        inactivity_score,
        state_ctxt,
        spec,
    )?;

    if delta.rewards != 0 || delta.penalties != 0 {
        let balance = balance.make_mut()?;
        balance.safe_add_assign(delta.rewards)?;
        *balance = balance.saturating_sub(delta.penalties);
    }

    Ok(())
}

fn get_flag_index_delta(
    delta: &mut Delta,
    validator_info: &ValidatorInfo,
    flag_index: usize,
    rewards_ctxt: &RewardsAndPenaltiesContext,
    state_ctxt: &StateContext,
) -> Result<(), Error> {
    let base_reward = validator_info.base_reward;
    let weight = get_flag_weight(flag_index)?;
    let unslashed_participating_increments =
        rewards_ctxt.get_unslashed_participating_increments(flag_index)?;

    if validator_info.is_unslashed_participating_index(flag_index)? {
        if !state_ctxt.is_in_inactivity_leak {
            let reward_numerator = base_reward
                .safe_mul(weight)?
                .safe_mul(unslashed_participating_increments)?;
            delta.reward(
                reward_numerator.safe_div(
                    rewards_ctxt
                        .active_increments
                        .safe_mul(WEIGHT_DENOMINATOR)?,
                )?,
            )?;
        }
    } else if flag_index != TIMELY_HEAD_FLAG_INDEX {
        delta.penalize(base_reward.safe_mul(weight)?.safe_div(WEIGHT_DENOMINATOR)?)?;
    }
    Ok(())
}

/// Get the weight for a `flag_index` from the constant list of all weights.
fn get_flag_weight(flag_index: usize) -> Result<u64, Error> {
    PARTICIPATION_FLAG_WEIGHTS
        .get(flag_index)
        .copied()
        .ok_or(Error::InvalidFlagIndex(flag_index))
}

fn get_inactivity_penalty_delta(
    delta: &mut Delta,
    validator_info: &ValidatorInfo,
    inactivity_score: &u64,
    state_ctxt: &StateContext,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if !validator_info.is_unslashed_participating_index(TIMELY_TARGET_FLAG_INDEX)? {
        let penalty_numerator = validator_info
            .effective_balance
            .safe_mul(*inactivity_score)?;
        let penalty_denominator = spec
            .inactivity_score_bias
            .safe_mul(spec.inactivity_penalty_quotient_for_fork(state_ctxt.fork_name))?;
        delta.penalize(penalty_numerator.safe_div(penalty_denominator)?)?;
    }
    Ok(())
}

impl RewardsAndPenaltiesContext {
    fn new(
        progressive_balances: &ProgressiveBalancesCache,
        state_ctxt: &StateContext,
        spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let mut unslashed_participating_increments_array = [0; NUM_FLAG_INDICES];
        for flag_index in 0..NUM_FLAG_INDICES {
            let unslashed_participating_balance =
                progressive_balances.previous_epoch_flag_attesting_balance(flag_index)?;
            let unslashed_participating_increments =
                unslashed_participating_balance.safe_div(spec.effective_balance_increment)?;

            *unslashed_participating_increments_array
                .get_mut(flag_index)
                .ok_or(Error::InvalidFlagIndex(flag_index))? = unslashed_participating_increments;
        }
        let active_increments = state_ctxt
            .total_active_balance
            .safe_div(spec.effective_balance_increment)?;

        Ok(Self {
            unslashed_participating_increments_array,
            active_increments,
        })
    }

    fn get_unslashed_participating_increments(&self, flag_index: usize) -> Result<u64, Error> {
        self.unslashed_participating_increments_array
            .get(flag_index)
            .copied()
            .ok_or(Error::InvalidFlagIndex(flag_index))
    }
}

#[allow(clippy::too_many_arguments)]
fn process_single_registry_update(
    validator: &mut Cow<Validator>,
    validator_info: &ValidatorInfo,
    exit_cache: &mut ExitCache,
    activation_queues: Option<(&BTreeSet<usize>, &mut ActivationQueue)>,
    state_ctxt: &StateContext,
    earliest_exit_epoch: Option<&mut Epoch>,
    exit_balance_to_consume: Option<&mut u64>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if !state_ctxt.fork_name.electra_enabled() {
        let (activation_queue, next_epoch_activation_queue) =
            activation_queues.ok_or(Error::SinglePassMissingActivationQueue)?;
        process_single_registry_update_pre_electra(
            validator,
            validator_info,
            exit_cache,
            activation_queue,
            next_epoch_activation_queue,
            state_ctxt,
            spec,
        )
    } else {
        process_single_registry_update_post_electra(
            validator,
            exit_cache,
            state_ctxt,
            earliest_exit_epoch.ok_or(Error::MissingEarliestExitEpoch)?,
            exit_balance_to_consume.ok_or(Error::MissingExitBalanceToConsume)?,
            spec,
        )
    }
}

fn process_single_registry_update_pre_electra(
    validator: &mut Cow<Validator>,
    validator_info: &ValidatorInfo,
    exit_cache: &mut ExitCache,
    activation_queue: &BTreeSet<usize>,
    next_epoch_activation_queue: &mut ActivationQueue,
    state_ctxt: &StateContext,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let current_epoch = state_ctxt.current_epoch;

    if validator.is_eligible_for_activation_queue(spec, state_ctxt.fork_name) {
        validator.make_mut()?.activation_eligibility_epoch = current_epoch.safe_add(1)?;
    }

    if validator.is_active_at(current_epoch) && validator.effective_balance <= spec.ejection_balance
    {
        initiate_validator_exit(validator, exit_cache, state_ctxt, None, None, spec)?;
    }

    if activation_queue.contains(&validator_info.index) {
        validator.make_mut()?.activation_epoch =
            spec.compute_activation_exit_epoch(current_epoch)?;
    }

    // Caching: add to speculative activation queue for next epoch.
    next_epoch_activation_queue.add_if_could_be_eligible_for_activation(
        validator_info.index,
        validator,
        state_ctxt.next_epoch,
        spec,
    );

    Ok(())
}

fn process_single_registry_update_post_electra(
    validator: &mut Cow<Validator>,
    exit_cache: &mut ExitCache,
    state_ctxt: &StateContext,
    earliest_exit_epoch: &mut Epoch,
    exit_balance_to_consume: &mut u64,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let current_epoch = state_ctxt.current_epoch;

    if validator.is_eligible_for_activation_queue(spec, state_ctxt.fork_name) {
        validator.make_mut()?.activation_eligibility_epoch = current_epoch.safe_add(1)?;
    }

    if validator.is_active_at(current_epoch) && validator.effective_balance <= spec.ejection_balance
    {
        initiate_validator_exit(
            validator,
            exit_cache,
            state_ctxt,
            Some(earliest_exit_epoch),
            Some(exit_balance_to_consume),
            spec,
        )?;
    }

    if validator.is_eligible_for_activation_with_finalized_checkpoint(
        &state_ctxt.finalized_checkpoint,
        spec,
    ) {
        validator.make_mut()?.activation_epoch =
            spec.compute_activation_exit_epoch(current_epoch)?;
    }

    Ok(())
}

fn initiate_validator_exit(
    validator: &mut Cow<Validator>,
    exit_cache: &mut ExitCache,
    state_ctxt: &StateContext,
    earliest_exit_epoch: Option<&mut Epoch>,
    exit_balance_to_consume: Option<&mut u64>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    // Return if the validator already initiated exit
    if validator.exit_epoch != spec.far_future_epoch {
        return Ok(());
    }

    let exit_queue_epoch = if state_ctxt.fork_name.electra_enabled() {
        compute_exit_epoch_and_update_churn(
            validator,
            state_ctxt,
            earliest_exit_epoch.ok_or(Error::MissingEarliestExitEpoch)?,
            exit_balance_to_consume.ok_or(Error::MissingExitBalanceToConsume)?,
            spec,
        )?
    } else {
        // Compute exit queue epoch
        let delayed_epoch = spec.compute_activation_exit_epoch(state_ctxt.current_epoch)?;
        let mut exit_queue_epoch = exit_cache
            .max_epoch()?
            .map_or(delayed_epoch, |epoch| max(epoch, delayed_epoch));
        let exit_queue_churn = exit_cache.get_churn_at(exit_queue_epoch)?;

        if exit_queue_churn >= state_ctxt.churn_limit {
            exit_queue_epoch.safe_add_assign(1)?;
        }
        exit_queue_epoch
    };

    let validator = validator.make_mut()?;
    validator.exit_epoch = exit_queue_epoch;
    validator.withdrawable_epoch =
        exit_queue_epoch.safe_add(spec.min_validator_withdrawability_delay)?;

    exit_cache.record_validator_exit(exit_queue_epoch)?;
    Ok(())
}

fn compute_exit_epoch_and_update_churn(
    validator: &mut Cow<Validator>,
    state_ctxt: &StateContext,
    earliest_exit_epoch_state: &mut Epoch,
    exit_balance_to_consume_state: &mut u64,
    spec: &ChainSpec,
) -> Result<Epoch, Error> {
    let exit_balance = validator.effective_balance;
    let mut earliest_exit_epoch = std::cmp::max(
        *earliest_exit_epoch_state,
        spec.compute_activation_exit_epoch(state_ctxt.current_epoch)?,
    );

    let per_epoch_churn = get_activation_exit_churn_limit(state_ctxt, spec)?;
    // New epoch for exits
    let mut exit_balance_to_consume = if *earliest_exit_epoch_state < earliest_exit_epoch {
        per_epoch_churn
    } else {
        *exit_balance_to_consume_state
    };

    // Exit doesn't fit in the current earliest epoch
    if exit_balance > exit_balance_to_consume {
        let balance_to_process = exit_balance.safe_sub(exit_balance_to_consume)?;
        let additional_epochs = balance_to_process
            .safe_sub(1)?
            .safe_div(per_epoch_churn)?
            .safe_add(1)?;
        earliest_exit_epoch.safe_add_assign(additional_epochs)?;
        exit_balance_to_consume.safe_add_assign(additional_epochs.safe_mul(per_epoch_churn)?)?;
    }
    // Consume the balance and update state variables
    *exit_balance_to_consume_state = exit_balance_to_consume.safe_sub(exit_balance)?;
    *earliest_exit_epoch_state = earliest_exit_epoch;

    Ok(earliest_exit_epoch)
}

fn get_activation_exit_churn_limit(
    state_ctxt: &StateContext,
    spec: &ChainSpec,
) -> Result<u64, Error> {
    Ok(std::cmp::min(
        spec.max_per_epoch_activation_exit_churn_limit,
        get_balance_churn_limit(state_ctxt, spec)?,
    ))
}

fn get_balance_churn_limit(state_ctxt: &StateContext, spec: &ChainSpec) -> Result<u64, Error> {
    let total_active_balance = state_ctxt.total_active_balance;
    let churn = std::cmp::max(
        spec.min_per_epoch_churn_limit_electra,
        total_active_balance.safe_div(spec.churn_limit_quotient)?,
    );

    Ok(churn.safe_sub(churn.safe_rem(spec.effective_balance_increment)?)?)
}

impl SlashingsContext {
    fn new<E: EthSpec>(
        state: &BeaconState<E>,
        state_ctxt: &StateContext,
        spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let sum_slashings = state.get_all_slashings().iter().copied().safe_sum()?;
        let adjusted_total_slashing_balance = min(
            sum_slashings.safe_mul(spec.proportional_slashing_multiplier_for_state(state))?,
            state_ctxt.total_active_balance,
        );

        let target_withdrawable_epoch = state_ctxt
            .current_epoch
            .safe_add(E::EpochsPerSlashingsVector::to_u64().safe_div(2)?)?;

        let penalty_per_effective_balance_increment = adjusted_total_slashing_balance.safe_div(
            state_ctxt
                .total_active_balance
                .safe_div(spec.effective_balance_increment)?,
        )?;

        Ok(Self {
            adjusted_total_slashing_balance,
            target_withdrawable_epoch,
            penalty_per_effective_balance_increment,
        })
    }
}

fn process_single_slashing(
    balance: &mut Cow<u64>,
    validator: &Validator,
    slashings_ctxt: &SlashingsContext,
    state_ctxt: &StateContext,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if validator.slashed && slashings_ctxt.target_withdrawable_epoch == validator.withdrawable_epoch
    {
        let increment = spec.effective_balance_increment;
        let penalty = if state_ctxt.fork_name.electra_enabled() {
            let effective_balance_increments = validator.effective_balance.safe_div(increment)?;
            slashings_ctxt
                .penalty_per_effective_balance_increment
                .safe_mul(effective_balance_increments)?
        } else {
            let penalty_numerator = validator
                .effective_balance
                .safe_div(increment)?
                .safe_mul(slashings_ctxt.adjusted_total_slashing_balance)?;
            penalty_numerator
                .safe_div(state_ctxt.total_active_balance)?
                .safe_mul(increment)?
        };
        *balance.make_mut()? = balance.saturating_sub(penalty);
    }
    Ok(())
}

impl PendingDepositsContext {
    fn new<E: EthSpec>(
        state: &BeaconState<E>,
        spec: &ChainSpec,
        config: &SinglePassConfig,
    ) -> Result<Self, Error> {
        let available_for_processing = state
            .deposit_balance_to_consume()?
            .safe_add(state.get_activation_exit_churn_limit(spec)?)?;
        let current_epoch = state.current_epoch();
        let next_epoch = state.next_epoch()?;
        let mut processed_amount = 0;
        let mut next_deposit_index = 0;
        let mut validator_deposits_to_process = HashMap::new();
        let mut deposits_to_postpone = vec![];
        let mut new_validator_deposits = vec![];
        let mut is_churn_limit_reached = false;
        let finalized_slot = state
            .finalized_checkpoint()
            .epoch
            .start_slot(E::slots_per_epoch());

        let pending_deposits = state.pending_deposits()?;

        for deposit in pending_deposits.iter() {
            // Do not process deposit requests if the Eth1 bridge deposits are not yet applied.
            if deposit.slot > spec.genesis_slot
                && state.eth1_deposit_index() < state.deposit_requests_start_index()?
            {
                break;
            }
            // Do not process is deposit slot has not been finalized.
            if deposit.slot > finalized_slot {
                break;
            }
            // Do not process if we have reached the limit for the number of deposits
            // processed in an epoch.
            if next_deposit_index >= E::max_pending_deposits_per_epoch() {
                break;
            }
            // We have to do a bit of indexing into `validators` here, but I can't see any way
            // around that without changing the spec.
            //
            // We need to work out if `validator.exit_epoch` will be set to a non-default value
            // *after* changes applied by `process_registry_updates`, which in our implementation
            // does not happen until after this (but in the spec happens before). However it's not
            // hard to work out: we don't need to know exactly what value the `exit_epoch` will
            // take, just whether it is non-default. Nor do we need to know the value of
            // `withdrawable_epoch`, because `next_epoch <= withdrawable_epoch` will evaluate to
            // `true` both for the actual value & the default placeholder value (`FAR_FUTURE_EPOCH`).
            let mut is_validator_exited = false;
            let mut is_validator_withdrawn = false;
            let opt_validator_index = state.pubkey_cache().get(&deposit.pubkey);
            if let Some(validator_index) = opt_validator_index {
                let validator = state.get_validator(validator_index)?;
                let already_exited = validator.exit_epoch < spec.far_future_epoch;
                // In the spec process_registry_updates is called before process_pending_deposits
                // so we must account for process_registry_updates ejecting the validator for low balance
                // and setting the exit_epoch to < far_future_epoch. Note that in the spec the effective
                // balance update does not happen until *after* the registry update, so we don't need to
                // account for changes to the effective balance that would push it below the ejection
                // balance here.
                // Note: we only consider this if registry_updates are enabled in the config.
                // EF tests require us to run epoch_processing functions in isolation.
                let will_be_exited = config.registry_updates
                    && (validator.is_active_at(current_epoch)
                        && validator.effective_balance <= spec.ejection_balance);
                is_validator_exited = already_exited || will_be_exited;
                is_validator_withdrawn = validator.withdrawable_epoch < next_epoch;
            }

            if is_validator_withdrawn {
                // Deposited balance will never become active. Queue a balance increase but do not
                // consume churn. Validator index must be known if the validator is known to be
                // withdrawn (see calculation of `is_validator_withdrawn` above).
                let validator_index =
                    opt_validator_index.ok_or(Error::PendingDepositsLogicError)?;
                validator_deposits_to_process
                    .entry(validator_index)
                    .or_insert(0)
                    .safe_add_assign(deposit.amount)?;
            } else if is_validator_exited {
                // Validator is exiting, postpone the deposit until after withdrawable epoch
                deposits_to_postpone.push(deposit.clone());
            } else {
                // Check if deposit fits in the churn, otherwise, do no more deposit processing in this epoch.
                is_churn_limit_reached =
                    processed_amount.safe_add(deposit.amount)? > available_for_processing;
                if is_churn_limit_reached {
                    break;
                }
                processed_amount.safe_add_assign(deposit.amount)?;

                // Deposit fits in the churn, process it. Increase balance and consume churn.
                if let Some(validator_index) = state.pubkey_cache().get(&deposit.pubkey) {
                    validator_deposits_to_process
                        .entry(validator_index)
                        .or_insert(0)
                        .safe_add_assign(deposit.amount)?;
                } else {
                    // The `PendingDeposit` is for a new validator
                    new_validator_deposits.push(deposit.clone());
                }
            }

            // Regardless of how the deposit was handled, we move on in the queue.
            next_deposit_index.safe_add_assign(1)?;
        }

        // Accumulate churn only if the churn limit has been hit.
        let deposit_balance_to_consume = if is_churn_limit_reached {
            available_for_processing.safe_sub(processed_amount)?
        } else {
            0
        };

        Ok(Self {
            next_deposit_index,
            deposit_balance_to_consume,
            validator_deposits_to_process,
            deposits_to_postpone,
            new_validator_deposits,
        })
    }
}

fn process_pending_deposits_for_validator(
    balance: &mut Cow<u64>,
    validator_info: &ValidatorInfo,
    pending_balance_deposits_ctxt: &PendingDepositsContext,
) -> Result<(), Error> {
    if let Some(deposit_amount) = pending_balance_deposits_ctxt
        .validator_deposits_to_process
        .get(&validator_info.index)
    {
        balance.make_mut()?.safe_add_assign(*deposit_amount)?;
    }
    Ok(())
}

/// We process pending consolidations after all of single-pass epoch processing, and then patch up
/// the effective balances for affected validators.
///
/// This is safe because processing consolidations does not depend on the `effective_balance`.
fn process_pending_consolidations<E: EthSpec>(
    state: &mut BeaconState<E>,
    next_epoch_cache: &mut PreEpochCache,
    effective_balances_ctxt: &EffectiveBalancesContext,
    perform_effective_balance_updates: bool,
    state_ctxt: &StateContext,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let mut next_pending_consolidation: usize = 0;
    let next_epoch = state.next_epoch()?;
    let pending_consolidations = state.pending_consolidations()?.clone();

    let mut affected_validators = BTreeSet::new();

    for pending_consolidation in &pending_consolidations {
        let source_index = pending_consolidation.source_index as usize;
        let target_index = pending_consolidation.target_index as usize;
        let source_validator = state.get_validator(source_index)?;
        if source_validator.slashed {
            next_pending_consolidation.safe_add_assign(1)?;
            continue;
        }
        if source_validator.withdrawable_epoch > next_epoch {
            break;
        }

        // Calculate the consolidated balance
        let source_effective_balance = std::cmp::min(
            *state
                .balances()
                .get(source_index)
                .ok_or(BeaconStateError::UnknownValidator(source_index))?,
            source_validator.effective_balance,
        );

        // Move active balance to target. Excess balance is withdrawable.
        decrease_balance(state, source_index, source_effective_balance)?;
        increase_balance(state, target_index, source_effective_balance)?;

        affected_validators.insert(source_index);
        affected_validators.insert(target_index);

        next_pending_consolidation.safe_add_assign(1)?;
    }

    let new_pending_consolidations = List::try_from_iter(
        state
            .pending_consolidations()?
            .iter_from(next_pending_consolidation)?
            .cloned(),
    )?;
    *state.pending_consolidations_mut()? = new_pending_consolidations;

    // the spec tests require we don't perform effective balance updates when testing pending_consolidations
    if !perform_effective_balance_updates {
        return Ok(());
    }

    // Re-process effective balance updates for validators affected by consolidations.
    let (validators, balances, _, current_epoch_participation, _, progressive_balances, _, _) =
        state.mutable_validator_fields()?;
    for validator_index in affected_validators {
        let balance = *balances
            .get(validator_index)
            .ok_or(BeaconStateError::UnknownValidator(validator_index))?;
        let mut validator = validators
            .get_cow(validator_index)
            .ok_or(BeaconStateError::UnknownValidator(validator_index))?;
        let validator_current_epoch_participation = *current_epoch_participation
            .get(validator_index)
            .ok_or(BeaconStateError::UnknownValidator(validator_index))?;

        process_single_effective_balance_update(
            validator_index,
            balance,
            &mut validator,
            validator_current_epoch_participation,
            next_epoch_cache,
            progressive_balances,
            effective_balances_ctxt,
            state_ctxt,
            spec,
        )?;
    }
    Ok(())
}

impl EffectiveBalancesContext {
    fn new(spec: &ChainSpec) -> Result<Self, Error> {
        let hysteresis_increment = spec
            .effective_balance_increment
            .safe_div(spec.hysteresis_quotient)?;
        let downward_threshold =
            hysteresis_increment.safe_mul(spec.hysteresis_downward_multiplier)?;
        let upward_threshold = hysteresis_increment.safe_mul(spec.hysteresis_upward_multiplier)?;

        Ok(Self {
            downward_threshold,
            upward_threshold,
        })
    }
}

/// This function abstracts over phase0 and Electra effective balance processing.
#[allow(clippy::too_many_arguments)]
fn process_single_effective_balance_update(
    validator_index: usize,
    balance: u64,
    validator: &mut Cow<Validator>,
    validator_current_epoch_participation: ParticipationFlags,
    next_epoch_cache: &mut PreEpochCache,
    progressive_balances: &mut ProgressiveBalancesCache,
    eb_ctxt: &EffectiveBalancesContext,
    state_ctxt: &StateContext,
    spec: &ChainSpec,
) -> Result<(), Error> {
    // Use the higher effective balance limit if post-Electra and compounding withdrawal credentials
    // are set.
    let effective_balance_limit = validator.get_max_effective_balance(spec, state_ctxt.fork_name);

    let old_effective_balance = validator.effective_balance;
    let new_effective_balance = if balance.safe_add(eb_ctxt.downward_threshold)?
        < validator.effective_balance
        || validator
            .effective_balance
            .safe_add(eb_ctxt.upward_threshold)?
            < balance
    {
        min(
            balance.safe_sub(balance.safe_rem(spec.effective_balance_increment)?)?,
            effective_balance_limit,
        )
    } else {
        validator.effective_balance
    };

    let is_active_next_epoch = validator.is_active_at(state_ctxt.next_epoch);

    if new_effective_balance != old_effective_balance {
        validator.make_mut()?.effective_balance = new_effective_balance;

        // Update progressive balances cache for the *current* epoch, which will soon become the
        // previous epoch once the epoch transition completes.
        progressive_balances.on_effective_balance_change(
            validator.slashed,
            validator_current_epoch_participation,
            old_effective_balance,
            new_effective_balance,
        )?;
    }

    // Caching: update next epoch effective balances and total active balance.
    next_epoch_cache.update_effective_balance(
        validator_index,
        new_effective_balance,
        is_active_next_epoch,
    )?;

    Ok(())
}
