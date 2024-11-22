use super::base::{validator_statuses::InclusionInfo, TotalBalances, ValidatorStatus};
use crate::metrics;
use std::sync::Arc;
use types::{
    consts::altair::{TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX},
    BeaconStateError, Epoch, EthSpec, List, ParticipationFlags, ProgressiveBalancesCache,
    SyncCommittee, Validator,
};

/// Provides a summary of validator participation during the epoch.
#[derive(PartialEq, Debug)]
pub enum EpochProcessingSummary<E: EthSpec> {
    Base {
        total_balances: TotalBalances,
        statuses: Vec<ValidatorStatus>,
    },
    Altair {
        progressive_balances: ProgressiveBalancesCache,
        current_epoch_total_active_balance: u64,
        participation: ParticipationEpochSummary<E>,
        sync_committee: Arc<SyncCommittee<E>>,
    },
}

#[derive(PartialEq, Debug)]
pub struct ParticipationEpochSummary<E: EthSpec> {
    /// Copy of the validator registry prior to mutation.
    validators: List<Validator, E::ValidatorRegistryLimit>,
    /// Copy of the participation flags for the previous epoch.
    previous_epoch_participation: List<ParticipationFlags, E::ValidatorRegistryLimit>,
    /// Copy of the participation flags for the current epoch.
    current_epoch_participation: List<ParticipationFlags, E::ValidatorRegistryLimit>,
    previous_epoch: Epoch,
    current_epoch: Epoch,
}

impl<E: EthSpec> ParticipationEpochSummary<E> {
    pub fn new(
        validators: List<Validator, E::ValidatorRegistryLimit>,
        previous_epoch_participation: List<ParticipationFlags, E::ValidatorRegistryLimit>,
        current_epoch_participation: List<ParticipationFlags, E::ValidatorRegistryLimit>,
        previous_epoch: Epoch,
        current_epoch: Epoch,
    ) -> Self {
        Self {
            validators,
            previous_epoch_participation,
            current_epoch_participation,
            previous_epoch,
            current_epoch,
        }
    }

    pub fn is_active_and_unslashed(&self, val_index: usize, epoch: Epoch) -> bool {
        self.validators
            .get(val_index)
            .map(|validator| !validator.slashed && validator.is_active_at(epoch))
            .unwrap_or(false)
    }

    pub fn is_previous_epoch_unslashed_participating_index(
        &self,
        val_index: usize,
        flag_index: usize,
    ) -> Result<bool, BeaconStateError> {
        Ok(self.is_active_and_unslashed(val_index, self.previous_epoch)
            && self
                .previous_epoch_participation
                .get(val_index)
                .ok_or(BeaconStateError::UnknownValidator(val_index))?
                .has_flag(flag_index)?)
    }

    pub fn is_current_epoch_unslashed_participating_index(
        &self,
        val_index: usize,
        flag_index: usize,
    ) -> Result<bool, BeaconStateError> {
        Ok(self.is_active_and_unslashed(val_index, self.current_epoch)
            && self
                .current_epoch_participation
                .get(val_index)
                .ok_or(BeaconStateError::UnknownValidator(val_index))?
                .has_flag(flag_index)?)
    }
}

impl<E: EthSpec> EpochProcessingSummary<E> {
    /// Updates some Prometheus metrics with some values in `self`.
    pub fn observe_metrics(&self) -> Result<(), BeaconStateError> {
        metrics::set_gauge(
            &metrics::PARTICIPATION_PREV_EPOCH_HEAD_ATTESTING_GWEI_TOTAL,
            self.previous_epoch_head_attesting_balance()? as i64,
        );
        metrics::set_gauge(
            &metrics::PARTICIPATION_PREV_EPOCH_TARGET_ATTESTING_GWEI_TOTAL,
            self.previous_epoch_target_attesting_balance()? as i64,
        );
        metrics::set_gauge(
            &metrics::PARTICIPATION_PREV_EPOCH_SOURCE_ATTESTING_GWEI_TOTAL,
            self.previous_epoch_source_attesting_balance()? as i64,
        );
        metrics::set_gauge(
            &metrics::PARTICIPATION_CURRENT_EPOCH_TOTAL_ACTIVE_GWEI_TOTAL,
            self.current_epoch_total_active_balance() as i64,
        );

        Ok(())
    }

    /// Returns the sync committee indices for the current epoch for altair.
    pub fn sync_committee(&self) -> Option<&SyncCommittee<E>> {
        match self {
            EpochProcessingSummary::Altair { sync_committee, .. } => Some(sync_committee),
            EpochProcessingSummary::Base { .. } => None,
        }
    }

    /// Returns the sum of the effective balance of all validators in the current epoch.
    pub fn current_epoch_total_active_balance(&self) -> u64 {
        match self {
            EpochProcessingSummary::Base { total_balances, .. } => total_balances.current_epoch(),
            EpochProcessingSummary::Altair {
                current_epoch_total_active_balance,
                ..
            } => *current_epoch_total_active_balance,
        }
    }

    /// Returns the sum of the effective balance of all validators in the current epoch who
    /// included an attestation that matched the target.
    pub fn current_epoch_target_attesting_balance(&self) -> Result<u64, BeaconStateError> {
        match self {
            EpochProcessingSummary::Base { total_balances, .. } => {
                Ok(total_balances.current_epoch_target_attesters())
            }
            EpochProcessingSummary::Altair {
                progressive_balances,
                ..
            } => progressive_balances.current_epoch_target_attesting_balance(),
        }
    }

    /// Returns `true` if `val_index` was included in the active validator indices in the current
    /// epoch *and* the validator is not slashed.
    ///
    /// ## Notes
    ///
    /// Always returns `false` for an unknown `val_index`.
    pub fn is_active_unslashed_in_current_epoch(&self, val_index: usize) -> bool {
        match self {
            EpochProcessingSummary::Base { statuses, .. } => statuses
                .get(val_index)
                .map_or(false, |s| s.is_active_in_current_epoch && !s.is_slashed),
            EpochProcessingSummary::Altair { participation, .. } => {
                participation.is_active_and_unslashed(val_index, participation.current_epoch)
            }
        }
    }

    /// Returns `true` if `val_index` had a target-matching attestation included on chain in the
    /// current epoch.
    ///
    /// ## Differences between Base and Altair
    ///
    /// - Base: active validators return `true`.
    /// - Altair: only active and *unslashed* validators return `true`.
    ///
    /// ## Notes
    ///
    /// Always returns `false` for an unknown `val_index`.
    pub fn is_current_epoch_target_attester(
        &self,
        val_index: usize,
    ) -> Result<bool, BeaconStateError> {
        match self {
            EpochProcessingSummary::Base { statuses, .. } => Ok(statuses
                .get(val_index)
                .map_or(false, |s| s.is_current_epoch_target_attester)),
            EpochProcessingSummary::Altair { participation, .. } => participation
                .is_current_epoch_unslashed_participating_index(
                    val_index,
                    TIMELY_TARGET_FLAG_INDEX,
                ),
        }
    }

    /// Returns the sum of the effective balance of all validators in the previous epoch who
    /// included an attestation that matched the target.
    pub fn previous_epoch_target_attesting_balance(&self) -> Result<u64, BeaconStateError> {
        match self {
            EpochProcessingSummary::Base { total_balances, .. } => {
                Ok(total_balances.previous_epoch_target_attesters())
            }
            EpochProcessingSummary::Altair {
                progressive_balances,
                ..
            } => progressive_balances.previous_epoch_target_attesting_balance(),
        }
    }

    /// Returns the sum of the effective balance of all validators in the previous epoch who
    /// included an attestation that matched the head.
    ///
    /// ## Differences between Base and Altair
    ///
    /// - Base: any attestation can match the head.
    /// - Altair: only "timely" attestations can match the head.
    pub fn previous_epoch_head_attesting_balance(&self) -> Result<u64, BeaconStateError> {
        match self {
            EpochProcessingSummary::Base { total_balances, .. } => {
                Ok(total_balances.previous_epoch_head_attesters())
            }
            EpochProcessingSummary::Altair {
                progressive_balances,
                ..
            } => progressive_balances.previous_epoch_head_attesting_balance(),
        }
    }

    /// Returns the sum of the effective balance of all validators in the previous epoch who
    /// included an attestation that matched the source.
    ///
    /// ## Differences between Base and Altair
    ///
    /// - Base: any attestation can match the source.
    /// - Altair: only "timely" attestations can match the source.
    pub fn previous_epoch_source_attesting_balance(&self) -> Result<u64, BeaconStateError> {
        match self {
            EpochProcessingSummary::Base { total_balances, .. } => {
                Ok(total_balances.previous_epoch_attesters())
            }
            EpochProcessingSummary::Altair {
                progressive_balances,
                ..
            } => progressive_balances.previous_epoch_source_attesting_balance(),
        }
    }

    /// Returns `true` if `val_index` was included in the active validator indices in the previous
    /// epoch *and* the validator is not slashed.
    ///
    /// ## Notes
    ///
    /// Always returns `false` for an unknown `val_index`.
    pub fn is_active_unslashed_in_previous_epoch(&self, val_index: usize) -> bool {
        match self {
            EpochProcessingSummary::Base { statuses, .. } => statuses
                .get(val_index)
                .map_or(false, |s| s.is_active_in_previous_epoch && !s.is_slashed),
            EpochProcessingSummary::Altair { participation, .. } => {
                participation.is_active_and_unslashed(val_index, participation.previous_epoch)
            }
        }
    }

    /// Returns `true` if `val_index` had a target-matching attestation included on chain in the
    /// previous epoch.
    ///
    /// ## Notes
    ///
    /// Always returns `false` for an unknown `val_index`.
    pub fn is_previous_epoch_target_attester(
        &self,
        val_index: usize,
    ) -> Result<bool, BeaconStateError> {
        match self {
            EpochProcessingSummary::Base { statuses, .. } => Ok(statuses
                .get(val_index)
                .map_or(false, |s| s.is_previous_epoch_target_attester)),
            EpochProcessingSummary::Altair { participation, .. } => participation
                .is_previous_epoch_unslashed_participating_index(
                    val_index,
                    TIMELY_TARGET_FLAG_INDEX,
                ),
        }
    }

    /// Returns `true` if `val_index` had a head-matching attestation included on chain in the
    /// previous epoch.
    ///
    /// ## Differences between Base and Altair
    ///
    /// - Base: any attestation can match the head.
    /// - Altair: only "timely" attestations can match the head.
    ///
    /// ## Notes
    ///
    /// Always returns `false` for an unknown `val_index`.
    pub fn is_previous_epoch_head_attester(
        &self,
        val_index: usize,
    ) -> Result<bool, BeaconStateError> {
        match self {
            EpochProcessingSummary::Base { statuses, .. } => Ok(statuses
                .get(val_index)
                .map_or(false, |s| s.is_previous_epoch_head_attester)),
            EpochProcessingSummary::Altair { participation, .. } => participation
                .is_previous_epoch_unslashed_participating_index(val_index, TIMELY_HEAD_FLAG_INDEX),
        }
    }

    /// Returns `true` if `val_index` had a source-matching attestation included on chain in the
    /// previous epoch.
    ///
    /// ## Differences between Base and Altair
    ///
    /// - Base: any attestation can match the head.
    /// - Altair: only "timely" attestations can match the source.
    ///
    /// ## Notes
    ///
    /// Always returns `false` for an unknown `val_index`.
    pub fn is_previous_epoch_source_attester(
        &self,
        val_index: usize,
    ) -> Result<bool, BeaconStateError> {
        match self {
            EpochProcessingSummary::Base { statuses, .. } => Ok(statuses
                .get(val_index)
                .map_or(false, |s| s.is_previous_epoch_attester)),
            EpochProcessingSummary::Altair { participation, .. } => participation
                .is_previous_epoch_unslashed_participating_index(
                    val_index,
                    TIMELY_SOURCE_FLAG_INDEX,
                ),
        }
    }

    /// Returns information about the inclusion distance for `val_index` for the previous epoch.
    ///
    /// ## Differences between Base and Altair
    ///
    /// - Base: always returns `Some` if the validator had an attestation included on-chain.
    /// - Altair: always returns `None`.
    ///
    /// ## Notes
    ///
    /// Always returns `false` for an unknown `val_index`.
    pub fn previous_epoch_inclusion_info(&self, val_index: usize) -> Option<InclusionInfo> {
        match self {
            EpochProcessingSummary::Base { statuses, .. } => {
                statuses.get(val_index).and_then(|s| s.inclusion_info)
            }
            EpochProcessingSummary::Altair { .. } => None,
        }
    }
}
