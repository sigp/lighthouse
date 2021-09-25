use super::*;
use crate::case_result::compare_result_detailed;
use crate::decode::{ssz_decode_file, ssz_decode_state, yaml_decode_file};
use compare_fields_derive::CompareFields;
use serde_derive::Deserialize;
use ssz_derive::{Decode, Encode};
use state_processing::{
    per_epoch_processing::{
        altair::{self, rewards_and_penalties::get_flag_index_deltas, ParticipationCache},
        base::{self, rewards_and_penalties::AttestationDelta, ValidatorStatuses},
        Delta,
    },
    EpochProcessingError,
};
use std::path::{Path, PathBuf};
use types::{
    consts::altair::{TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX},
    BeaconState, EthSpec, ForkName,
};

#[derive(Debug, Clone, PartialEq, Decode, Encode, CompareFields)]
pub struct Deltas {
    #[compare_fields(as_slice)]
    rewards: Vec<u64>,
    #[compare_fields(as_slice)]
    penalties: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, CompareFields)]
pub struct AllDeltas {
    source_deltas: Deltas,
    target_deltas: Deltas,
    head_deltas: Deltas,
    inclusion_delay_deltas: Option<Deltas>,
    inactivity_penalty_deltas: Deltas,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Metadata {
    pub description: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RewardsTest<E: EthSpec> {
    pub path: PathBuf,
    pub metadata: Metadata,
    pub pre: BeaconState<E>,
    pub deltas: AllDeltas,
}

/// Function that extracts a delta for a single component from an `AttestationDelta`.
type Accessor = fn(&AttestationDelta) -> &Delta;

fn load_optional_deltas_file(path: &Path) -> Result<Option<Deltas>, Error> {
    let deltas = if path.is_file() {
        Some(ssz_decode_file(path)?)
    } else {
        None
    };
    Ok(deltas)
}

impl<E: EthSpec> LoadCase for RewardsTest<E> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let spec = &testing_spec::<E>(fork_name);
        let metadata_path = path.join("meta.yaml");
        let metadata: Metadata = if metadata_path.is_file() {
            yaml_decode_file(&metadata_path)?
        } else {
            Metadata::default()
        };
        let pre = ssz_decode_state(&path.join("pre.ssz_snappy"), spec)?;
        let source_deltas = ssz_decode_file(&path.join("source_deltas.ssz_snappy"))?;
        let target_deltas = ssz_decode_file(&path.join("target_deltas.ssz_snappy"))?;
        let head_deltas = ssz_decode_file(&path.join("head_deltas.ssz_snappy"))?;
        let inclusion_delay_deltas =
            load_optional_deltas_file(&path.join("inclusion_delay_deltas.ssz_snappy"))?;
        let inactivity_penalty_deltas =
            ssz_decode_file(&path.join("inactivity_penalty_deltas.ssz_snappy"))?;

        let deltas = AllDeltas {
            source_deltas,
            target_deltas,
            head_deltas,
            inclusion_delay_deltas,
            inactivity_penalty_deltas,
        };

        Ok(Self {
            path: path.into(),
            metadata,
            pre,
            deltas,
        })
    }
}

impl<E: EthSpec> Case for RewardsTest<E> {
    fn description(&self) -> String {
        self.metadata
            .description
            .clone()
            .unwrap_or_else(String::new)
    }

    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let mut state = self.pre.clone();
        let spec = &testing_spec::<E>(fork_name);

        let deltas: Result<AllDeltas, EpochProcessingError> = (|| {
            // Processing requires the committee caches.
            state.build_all_committee_caches(spec)?;

            if let BeaconState::Base(_) = state {
                let mut validator_statuses = ValidatorStatuses::new(&state, spec)?;
                validator_statuses.process_attestations(&state)?;

                let deltas = base::rewards_and_penalties::get_attestation_deltas(
                    &state,
                    &validator_statuses,
                    spec,
                )?;

                Ok(convert_all_base_deltas(&deltas))
            } else {
                let total_active_balance = state.get_total_active_balance()?;

                let source_deltas = compute_altair_flag_deltas(
                    &state,
                    TIMELY_SOURCE_FLAG_INDEX,
                    total_active_balance,
                    spec,
                )?;
                let target_deltas = compute_altair_flag_deltas(
                    &state,
                    TIMELY_TARGET_FLAG_INDEX,
                    total_active_balance,
                    spec,
                )?;
                let head_deltas = compute_altair_flag_deltas(
                    &state,
                    TIMELY_HEAD_FLAG_INDEX,
                    total_active_balance,
                    spec,
                )?;
                let inactivity_penalty_deltas = compute_altair_inactivity_deltas(&state, spec)?;
                Ok(AllDeltas {
                    source_deltas,
                    target_deltas,
                    head_deltas,
                    inclusion_delay_deltas: None,
                    inactivity_penalty_deltas,
                })
            }
        })();

        compare_result_detailed(&deltas, &Some(self.deltas.clone()))?;

        Ok(())
    }
}

fn convert_all_base_deltas(ad: &[AttestationDelta]) -> AllDeltas {
    AllDeltas {
        source_deltas: convert_base_deltas(ad, |d| &d.source_delta),
        target_deltas: convert_base_deltas(ad, |d| &d.target_delta),
        head_deltas: convert_base_deltas(ad, |d| &d.head_delta),
        inclusion_delay_deltas: Some(convert_base_deltas(ad, |d| &d.inclusion_delay_delta)),
        inactivity_penalty_deltas: convert_base_deltas(ad, |d| &d.inactivity_penalty_delta),
    }
}

fn convert_base_deltas(attestation_deltas: &[AttestationDelta], accessor: Accessor) -> Deltas {
    let (rewards, penalties) = attestation_deltas
        .iter()
        .map(accessor)
        .map(|delta| (delta.rewards, delta.penalties))
        .unzip();
    Deltas { rewards, penalties }
}

fn compute_altair_flag_deltas<E: EthSpec>(
    state: &BeaconState<E>,
    flag_index: usize,
    total_active_balance: u64,
    spec: &ChainSpec,
) -> Result<Deltas, EpochProcessingError> {
    let mut deltas = vec![Delta::default(); state.validators().len()];
    get_flag_index_deltas(
        &mut deltas,
        state,
        flag_index,
        total_active_balance,
        &ParticipationCache::new(state, spec).unwrap(),
        spec,
    )?;
    Ok(convert_altair_deltas(deltas))
}

fn compute_altair_inactivity_deltas<E: EthSpec>(
    state: &BeaconState<E>,
    spec: &ChainSpec,
) -> Result<Deltas, EpochProcessingError> {
    let mut deltas = vec![Delta::default(); state.validators().len()];
    altair::rewards_and_penalties::get_inactivity_penalty_deltas(
        &mut deltas,
        state,
        &ParticipationCache::new(state, spec).unwrap(),
        spec,
    )?;
    Ok(convert_altair_deltas(deltas))
}

fn convert_altair_deltas(deltas: Vec<Delta>) -> Deltas {
    let (rewards, penalties) = deltas.into_iter().map(|d| (d.rewards, d.penalties)).unzip();
    Deltas { rewards, penalties }
}
