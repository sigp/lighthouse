use safe_arith::{ArithError, SafeArith};
use std::collections::HashMap;
use types::{
    consts::altair::{
        NUM_FLAG_INDICES, TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX,
        TIMELY_TARGET_FLAG_INDEX,
    },
    BeaconState, BeaconStateError, ChainSpec, Epoch, EthSpec, ParticipationFlags, RelativeEpoch,
};

#[derive(PartialEq, Debug, Clone, Copy)]
struct Balance {
    raw: u64,
    minimum: u64,
}

impl Balance {
    pub fn zero(minimum: u64) -> Self {
        Self { raw: 0, minimum }
    }

    pub fn get(&self) -> u64 {
        std::cmp::max(self.raw, self.minimum)
    }

    pub fn safe_add_assign(&mut self, other: u64) -> Result<(), ArithError> {
        self.raw.safe_add_assign(other)
    }
}

#[derive(PartialEq, Debug)]
struct EpochParticipation {
    unslashed_participating_indices: HashMap<usize, ParticipationFlags>,
    total_flag_balances: [Balance; NUM_FLAG_INDICES],
    total_active_balance: Balance,
}

impl EpochParticipation {
    pub fn new(hashmap_len: usize, spec: &ChainSpec) -> Self {
        let zero_balance = Balance::zero(spec.effective_balance_increment);

        Self {
            unslashed_participating_indices: HashMap::with_capacity(hashmap_len),
            total_flag_balances: [zero_balance; NUM_FLAG_INDICES],
            total_active_balance: zero_balance,
        }
    }

    pub fn process_active_validator<T: EthSpec>(
        &mut self,
        val_index: usize,
        state: &BeaconState<T>,
        epoch_participation: &[ParticipationFlags],
    ) -> Result<(), BeaconStateError> {
        let val_balance = state.get_effective_balance(val_index)?;
        self.total_active_balance.safe_add_assign(val_balance)?;

        if state.get_validator(val_index)?.slashed {
            return Ok(());
        }

        // Iterate through all the flags and increment total balances.
        self.total_flag_balances
            .iter_mut()
            .enumerate()
            .try_for_each(|(flag, balance)| {
                if epoch_participation
                    .get(val_index)
                    .ok_or(BeaconStateError::ParticipationOutOfBounds(val_index))?
                    .has_flag(flag)?
                {
                    balance.safe_add_assign(val_balance)?;
                }

                Ok::<_, BeaconStateError>(())
            })?;

        // The validator is active an unslashed, add their `ParticipationFlags` to the map.
        self.unslashed_participating_indices.insert(
            val_index,
            *epoch_participation
                .get(val_index)
                .ok_or(BeaconStateError::ParticipationOutOfBounds(val_index))?,
        );

        Ok(())
    }
}

#[derive(PartialEq, Debug)]
pub struct ParticipationCache {
    current_epoch: Epoch,
    current_epoch_participation: EpochParticipation,
    previous_epoch: Epoch,
    previous_epoch_participation: EpochParticipation,
    eligible_indices: Vec<usize>,
}

impl ParticipationCache {
    pub fn new<T: EthSpec>(
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<Self, BeaconStateError> {
        let current_epoch = state.current_epoch();
        let previous_epoch = state.previous_epoch();

        let num_previous_epoch_active_vals = state
            .get_cached_active_validator_indices(RelativeEpoch::Previous)?
            .len();
        let num_current_epoch_active_vals = state
            .get_cached_active_validator_indices(RelativeEpoch::Current)?
            .len();

        let mut current_epoch_participation =
            EpochParticipation::new(num_current_epoch_active_vals, spec);
        let mut previous_epoch_participation =
            EpochParticipation::new(num_previous_epoch_active_vals, spec);
        let mut eligible_indices = Vec::with_capacity(state.validators().len());

        for (val_index, val) in state.validators().iter().enumerate() {
            if val.is_active_at(current_epoch) {
                current_epoch_participation.process_active_validator(
                    val_index,
                    state,
                    state.current_epoch_participation()?,
                )?;
            }

            if val.is_active_at(previous_epoch) {
                previous_epoch_participation.process_active_validator(
                    val_index,
                    state,
                    state.previous_epoch_participation()?,
                )?;
            }

            if state.is_eligible_validator(val_index)? {
                eligible_indices.push(val_index)
            }
        }

        eligible_indices.shrink_to_fit();

        Ok(Self {
            current_epoch,
            current_epoch_participation,
            previous_epoch,
            previous_epoch_participation,
            eligible_indices,
        })
    }

    pub fn eligible_validator_indices(&self) -> &[usize] {
        &self.eligible_indices
    }

    pub fn previous_epoch_total_active_balance(&self) -> u64 {
        self.previous_epoch_participation.total_active_balance.get()
    }

    fn previous_epoch_flag_attesting_balance(
        &self,
        flag_index: usize,
    ) -> Result<u64, BeaconStateError> {
        self.previous_epoch_participation
            .total_flag_balances
            .get(flag_index)
            .map(Balance::get)
            // FIXME(paul): inconsistent use of ParticipationOutOfBounds?
            .ok_or(BeaconStateError::ParticipationOutOfBounds(flag_index))
    }

    pub fn previous_epoch_target_attesting_balance(&self) -> Result<u64, BeaconStateError> {
        self.previous_epoch_flag_attesting_balance(TIMELY_TARGET_FLAG_INDEX)
    }

    pub fn previous_epoch_head_attesting_balance(&self) -> Result<u64, BeaconStateError> {
        self.previous_epoch_flag_attesting_balance(TIMELY_HEAD_FLAG_INDEX)
    }

    pub fn current_epoch_total_active_balance(&self) -> u64 {
        self.current_epoch_participation.total_active_balance.get()
    }

    pub fn get_unslashed_participating_indices(
        &self,
        flag_index: usize,
        epoch: Epoch,
    ) -> Result<UnslashedParticipatingIndices, BeaconStateError> {
        let participation = if epoch == self.current_epoch {
            &self.current_epoch_participation
        } else if epoch == self.previous_epoch {
            &self.previous_epoch_participation
        } else {
            return Err(BeaconStateError::EpochOutOfBounds);
        };

        Ok(UnslashedParticipatingIndices {
            participation,
            flag_index,
        })
    }

    pub fn is_active_in_previous_epoch(&self, val_index: usize) -> bool {
        self.previous_epoch_participation
            .unslashed_participating_indices
            .contains_key(&val_index)
    }

    pub fn is_active_in_current_epoch(&self, val_index: usize) -> bool {
        self.current_epoch_participation
            .unslashed_participating_indices
            .contains_key(&val_index)
    }

    fn has_previous_epoch_flag(&self, val_index: usize, flag_index: usize) -> bool {
        self.previous_epoch_participation
            .unslashed_participating_indices
            .get(&val_index)
            .and_then(|participation_flags| participation_flags.has_flag(flag_index).ok())
            .unwrap_or(false)
    }

    pub fn is_previous_epoch_timely_source_attester(&self, val_index: usize) -> bool {
        self.has_previous_epoch_flag(val_index, TIMELY_SOURCE_FLAG_INDEX)
    }

    pub fn is_previous_epoch_timely_target_attester(&self, val_index: usize) -> bool {
        self.has_previous_epoch_flag(val_index, TIMELY_TARGET_FLAG_INDEX)
    }

    pub fn is_previous_epoch_timely_head_attester(&self, val_index: usize) -> bool {
        self.has_previous_epoch_flag(val_index, TIMELY_HEAD_FLAG_INDEX)
    }

    fn has_current_epoch_flag(&self, val_index: usize, flag_index: usize) -> bool {
        self.current_epoch_participation
            .unslashed_participating_indices
            .get(&val_index)
            .and_then(|participation_flags| participation_flags.has_flag(flag_index).ok())
            .unwrap_or(false)
    }

    pub fn is_current_epoch_timely_source_attester(&self, val_index: usize) -> bool {
        self.has_current_epoch_flag(val_index, TIMELY_SOURCE_FLAG_INDEX)
    }

    pub fn is_current_epoch_timely_target_attester(&self, val_index: usize) -> bool {
        self.has_current_epoch_flag(val_index, TIMELY_TARGET_FLAG_INDEX)
    }

    pub fn is_current_epoch_timely_head_attester(&self, val_index: usize) -> bool {
        self.has_current_epoch_flag(val_index, TIMELY_HEAD_FLAG_INDEX)
    }
}

pub struct UnslashedParticipatingIndices<'a> {
    participation: &'a EpochParticipation,
    flag_index: usize,
}

impl<'a> UnslashedParticipatingIndices<'a> {
    pub fn contains(&self, val_index: usize) -> Result<bool, ArithError> {
        self.participation
            .unslashed_participating_indices
            .get(&val_index)
            .map(|participation_flags| participation_flags.has_flag(self.flag_index))
            .unwrap_or(Ok(false))
    }

    pub fn total_balance(&self) -> Result<u64, BeaconStateError> {
        self.participation
            .total_flag_balances
            .get(self.flag_index)
            .map(Balance::get)
            // FIXME(paul): inconsistent use of ParticipationOutOfBounds?
            .ok_or(BeaconStateError::ParticipationOutOfBounds(self.flag_index))
    }
}
