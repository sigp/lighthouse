use safe_arith::{ArithError, SafeArith};
use std::collections::HashMap;
use types::{
    consts::altair::{
        NUM_FLAG_INDICES, TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX,
        TIMELY_TARGET_FLAG_INDEX,
    },
    BeaconState, BeaconStateError, ChainSpec, Epoch, EthSpec, ParticipationFlags,
};

#[derive(PartialEq, Debug)]
struct EpochParticipation {
    eligible_indices: Vec<usize>,
    unslashed_participating_indices: HashMap<usize, ParticipationFlags>,
    total_flag_balances: [u64; NUM_FLAG_INDICES],
    total_active_balance: u64,
}

#[derive(PartialEq, Debug)]
pub struct ParticipationCache {
    current_epoch: Epoch,
    current_epoch_participation: EpochParticipation,
    previous_epoch: Epoch,
    previous_epoch_participation: EpochParticipation,
}

impl ParticipationCache {
    pub fn new<T: EthSpec>(
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<Self, BeaconStateError> {
        let current_epoch = state.current_epoch();
        let previous_epoch = state.previous_epoch();

        Ok(Self {
            current_epoch,
            current_epoch_participation: get_epoch_participation(state, current_epoch, spec)?,
            previous_epoch,
            previous_epoch_participation: get_epoch_participation(state, previous_epoch, spec)?,
        })
    }

    pub fn previous_epoch_total_active_balance(&self) -> u64 {
        self.previous_epoch_participation.total_active_balance
    }

    fn previous_epoch_flag_attesting_balance(
        &self,
        flag_index: usize,
    ) -> Result<u64, BeaconStateError> {
        self.previous_epoch_participation
            .total_flag_balances
            .get(flag_index)
            .copied()
            .ok_or(BeaconStateError::ParticipationOutOfBounds(flag_index))
    }

    pub fn previous_epoch_target_attesting_balance(&self) -> Result<u64, BeaconStateError> {
        self.previous_epoch_flag_attesting_balance(TIMELY_TARGET_FLAG_INDEX)
    }

    pub fn previous_epoch_head_attesting_balance(&self) -> Result<u64, BeaconStateError> {
        self.previous_epoch_flag_attesting_balance(TIMELY_HEAD_FLAG_INDEX)
    }

    pub fn current_epoch_total_active_balance(&self) -> u64 {
        self.current_epoch_participation.total_active_balance
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

        // Note: protects the iterator.
        if flag_index >= NUM_FLAG_INDICES {
            return Err(ArithError::Overflow.into());
        }

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
            .copied()
            // FIXME(paul): inconsistent use of ParticipationOutOfBounds?
            .ok_or(BeaconStateError::ParticipationOutOfBounds(self.flag_index))
    }
}

fn get_epoch_participation<T: EthSpec>(
    state: &BeaconState<T>,
    epoch: Epoch,
    spec: &ChainSpec,
) -> Result<EpochParticipation, BeaconStateError> {
    let epoch_participation = if epoch == state.current_epoch() {
        state.current_epoch_participation()?
    } else if epoch == state.previous_epoch() {
        state.previous_epoch_participation()?
    } else {
        return Err(BeaconStateError::EpochOutOfBounds);
    };

    // Might be too large due to slashed boiz.
    let active_validator_indices = state.get_active_validator_indices(epoch, spec)?;
    let mut unslashed_participating_indices =
        HashMap::with_capacity(active_validator_indices.len());
    let mut total_flag_balances = [0; NUM_FLAG_INDICES];
    let mut total_active_balance = 0;

    for val_index in active_validator_indices {
        // FIXME(paul): double check that total active balance is always unslashed.
        let val_balance = state.get_effective_balance(val_index)?;
        total_active_balance.safe_add_assign(val_balance)?;

        if !state.get_validator(val_index)?.slashed {
            total_flag_balances
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

            unslashed_participating_indices.insert(
                val_index,
                *epoch_participation
                    .get(val_index)
                    .ok_or(BeaconStateError::ParticipationOutOfBounds(val_index))?,
            );
        }
    }

    Ok(EpochParticipation {
        unslashed_participating_indices,
        total_flag_balances,
        total_active_balance,
    })
}
