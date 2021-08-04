use super::*;
use crate::bls_setting::BlsSetting;
use crate::case_result::compare_beacon_state_results_without_caches;
use crate::decode::{ssz_decode_state, yaml_decode_file};
use crate::type_name;
use crate::type_name::TypeName;
use serde_derive::Deserialize;
use state_processing::per_epoch_processing::{
    altair, base,
    effective_balance_updates::process_effective_balance_updates,
    historical_roots_update::process_historical_roots_update,
    process_registry_updates, process_slashings,
    resets::{process_eth1_data_reset, process_randao_mixes_reset, process_slashings_reset},
};
use state_processing::EpochProcessingError;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use types::{BeaconState, ChainSpec, EthSpec, ForkName};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Metadata {
    pub description: Option<String>,
    pub bls_setting: Option<BlsSetting>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct EpochProcessing<E: EthSpec, T: EpochTransition<E>> {
    pub path: PathBuf,
    pub metadata: Metadata,
    pub pre: BeaconState<E>,
    pub post: Option<BeaconState<E>>,
    #[serde(skip_deserializing)]
    _phantom: PhantomData<T>,
}

pub trait EpochTransition<E: EthSpec>: TypeName + Debug + Sync {
    fn run(state: &mut BeaconState<E>, spec: &ChainSpec) -> Result<(), EpochProcessingError>;
}

#[derive(Debug)]
pub struct JustificationAndFinalization;
#[derive(Debug)]
pub struct RewardsAndPenalties;
#[derive(Debug)]
pub struct RegistryUpdates;
#[derive(Debug)]
pub struct Slashings;
#[derive(Debug)]
pub struct Eth1DataReset;
#[derive(Debug)]
pub struct EffectiveBalanceUpdates;
#[derive(Debug)]
pub struct SlashingsReset;
#[derive(Debug)]
pub struct RandaoMixesReset;
#[derive(Debug)]
pub struct HistoricalRootsUpdate;
#[derive(Debug)]
pub struct ParticipationRecordUpdates;
#[derive(Debug)]
pub struct SyncCommitteeUpdates;
#[derive(Debug)]
pub struct InactivityUpdates;
#[derive(Debug)]
pub struct ParticipationFlagUpdates;

type_name!(
    JustificationAndFinalization,
    "justification_and_finalization"
);
type_name!(RewardsAndPenalties, "rewards_and_penalties");
type_name!(RegistryUpdates, "registry_updates");
type_name!(Slashings, "slashings");
type_name!(Eth1DataReset, "eth1_data_reset");
type_name!(EffectiveBalanceUpdates, "effective_balance_updates");
type_name!(SlashingsReset, "slashings_reset");
type_name!(RandaoMixesReset, "randao_mixes_reset");
type_name!(HistoricalRootsUpdate, "historical_roots_update");
type_name!(ParticipationRecordUpdates, "participation_record_updates");
type_name!(SyncCommitteeUpdates, "sync_committee_updates");
type_name!(InactivityUpdates, "inactivity_updates");
type_name!(ParticipationFlagUpdates, "participation_flag_updates");

impl<E: EthSpec> EpochTransition<E> for JustificationAndFinalization {
    fn run(state: &mut BeaconState<E>, spec: &ChainSpec) -> Result<(), EpochProcessingError> {
        match state {
            BeaconState::Base(_) => {
                let mut validator_statuses = base::ValidatorStatuses::new(state, spec)?;
                validator_statuses.process_attestations(state)?;
                base::process_justification_and_finalization(
                    state,
                    &validator_statuses.total_balances,
                    spec,
                )
            }
            BeaconState::Altair(_) => altair::process_justification_and_finalization(
                state,
                &altair::ParticipationCache::new(state, spec).unwrap(),
            ),
        }
    }
}

impl<E: EthSpec> EpochTransition<E> for RewardsAndPenalties {
    fn run(state: &mut BeaconState<E>, spec: &ChainSpec) -> Result<(), EpochProcessingError> {
        match state {
            BeaconState::Base(_) => {
                let mut validator_statuses = base::ValidatorStatuses::new(state, spec)?;
                validator_statuses.process_attestations(state)?;
                base::process_rewards_and_penalties(state, &mut validator_statuses, spec)
            }
            BeaconState::Altair(_) => altair::process_rewards_and_penalties(
                state,
                &altair::ParticipationCache::new(state, spec).unwrap(),
                spec,
            ),
        }
    }
}

impl<E: EthSpec> EpochTransition<E> for RegistryUpdates {
    fn run(state: &mut BeaconState<E>, spec: &ChainSpec) -> Result<(), EpochProcessingError> {
        process_registry_updates(state, spec)
    }
}

impl<E: EthSpec> EpochTransition<E> for Slashings {
    fn run(state: &mut BeaconState<E>, spec: &ChainSpec) -> Result<(), EpochProcessingError> {
        match state {
            BeaconState::Base(_) => {
                let mut validator_statuses = base::ValidatorStatuses::new(state, spec)?;
                validator_statuses.process_attestations(state)?;
                process_slashings(
                    state,
                    validator_statuses.total_balances.current_epoch(),
                    spec.proportional_slashing_multiplier,
                    spec,
                )?;
            }
            BeaconState::Altair(_) => {
                process_slashings(
                    state,
                    altair::ParticipationCache::new(state, spec)
                        .unwrap()
                        .current_epoch_total_active_balance(),
                    spec.proportional_slashing_multiplier_altair,
                    spec,
                )?;
            }
        };
        Ok(())
    }
}

impl<E: EthSpec> EpochTransition<E> for Eth1DataReset {
    fn run(state: &mut BeaconState<E>, _spec: &ChainSpec) -> Result<(), EpochProcessingError> {
        process_eth1_data_reset(state)
    }
}

impl<E: EthSpec> EpochTransition<E> for EffectiveBalanceUpdates {
    fn run(state: &mut BeaconState<E>, spec: &ChainSpec) -> Result<(), EpochProcessingError> {
        process_effective_balance_updates(state, spec)
    }
}

impl<E: EthSpec> EpochTransition<E> for SlashingsReset {
    fn run(state: &mut BeaconState<E>, _spec: &ChainSpec) -> Result<(), EpochProcessingError> {
        process_slashings_reset(state)
    }
}

impl<E: EthSpec> EpochTransition<E> for RandaoMixesReset {
    fn run(state: &mut BeaconState<E>, _spec: &ChainSpec) -> Result<(), EpochProcessingError> {
        process_randao_mixes_reset(state)
    }
}

impl<E: EthSpec> EpochTransition<E> for HistoricalRootsUpdate {
    fn run(state: &mut BeaconState<E>, _spec: &ChainSpec) -> Result<(), EpochProcessingError> {
        process_historical_roots_update(state)
    }
}

impl<E: EthSpec> EpochTransition<E> for ParticipationRecordUpdates {
    fn run(state: &mut BeaconState<E>, _spec: &ChainSpec) -> Result<(), EpochProcessingError> {
        if let BeaconState::Base(_) = state {
            base::process_participation_record_updates(state)
        } else {
            Ok(())
        }
    }
}

impl<E: EthSpec> EpochTransition<E> for SyncCommitteeUpdates {
    fn run(state: &mut BeaconState<E>, spec: &ChainSpec) -> Result<(), EpochProcessingError> {
        match state {
            BeaconState::Base(_) => Ok(()),
            BeaconState::Altair(_) => altair::process_sync_committee_updates(state, spec),
        }
    }
}

impl<E: EthSpec> EpochTransition<E> for InactivityUpdates {
    fn run(state: &mut BeaconState<E>, spec: &ChainSpec) -> Result<(), EpochProcessingError> {
        match state {
            BeaconState::Base(_) => Ok(()),
            BeaconState::Altair(_) => altair::process_inactivity_updates(
                state,
                &altair::ParticipationCache::new(state, spec).unwrap(),
                spec,
            ),
        }
    }
}

impl<E: EthSpec> EpochTransition<E> for ParticipationFlagUpdates {
    fn run(state: &mut BeaconState<E>, _: &ChainSpec) -> Result<(), EpochProcessingError> {
        match state {
            BeaconState::Base(_) => Ok(()),
            BeaconState::Altair(_) => altair::process_participation_flag_updates(state),
        }
    }
}

impl<E: EthSpec, T: EpochTransition<E>> LoadCase for EpochProcessing<E, T> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let spec = &testing_spec::<E>(fork_name);
        let metadata_path = path.join("meta.yaml");
        let metadata: Metadata = if metadata_path.is_file() {
            yaml_decode_file(&metadata_path)?
        } else {
            Metadata::default()
        };
        let pre = ssz_decode_state(&path.join("pre.ssz_snappy"), spec)?;
        let post_file = path.join("post.ssz_snappy");
        let post = if post_file.is_file() {
            Some(ssz_decode_state(&post_file, spec)?)
        } else {
            None
        };

        Ok(Self {
            path: path.into(),
            metadata,
            pre,
            post,
            _phantom: PhantomData,
        })
    }
}

impl<E: EthSpec, T: EpochTransition<E>> Case for EpochProcessing<E, T> {
    fn description(&self) -> String {
        self.metadata
            .description
            .clone()
            .unwrap_or_else(String::new)
    }

    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        match fork_name {
            // No Altair tests for genesis fork.
            ForkName::Base => {
                T::name() != "sync_committee_updates"
                    && T::name() != "inactivity_updates"
                    && T::name() != "participation_flag_updates"
            }
            ForkName::Altair => true,
        }
    }

    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        self.metadata.bls_setting.unwrap_or_default().check()?;

        let mut state = self.pre.clone();
        let mut expected = self.post.clone();

        let spec = &testing_spec::<E>(fork_name);

        let mut result = (|| {
            // Processing requires the committee caches.
            state.build_all_committee_caches(spec)?;

            T::run(&mut state, spec).map(|_| state)
        })();

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
