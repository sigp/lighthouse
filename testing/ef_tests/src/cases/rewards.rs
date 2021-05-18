use super::*;
use crate::case_result::compare_result_detailed;
use crate::decode::{ssz_decode_file, ssz_decode_state, yaml_decode_file};
use compare_fields_derive::CompareFields;
use serde_derive::Deserialize;
use ssz_derive::{Decode, Encode};
use state_processing::per_epoch_processing::validator_statuses::ValidatorStatuses;
use state_processing::{
    per_epoch_processing::base::{
        self,
        rewards_and_penalties::{AttestationDelta, Delta},
    },
    EpochProcessingError,
};
use std::path::{Path, PathBuf};
use types::{BeaconState, EthSpec, ForkName};

#[derive(Debug, Clone, PartialEq, Decode, Encode, CompareFields)]
pub struct Deltas {
    #[compare_fields(as_slice)]
    rewards: Vec<u64>,
    #[compare_fields(as_slice)]
    penalties: Vec<u64>,
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
    pub source_deltas: Deltas,
    pub target_deltas: Deltas,
    pub head_deltas: Deltas,
    pub inclusion_delay_deltas: Deltas,
    pub inactivity_penalty_deltas: Deltas,
}

/// Function that extracts a delta for a single component from an `AttestationDelta`.
type Accessor = fn(&AttestationDelta) -> &Delta;

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
            ssz_decode_file(&path.join("inclusion_delay_deltas.ssz_snappy"))?;
        let inactivity_penalty_deltas =
            ssz_decode_file(&path.join("inactivity_penalty_deltas.ssz_snappy"))?;

        Ok(Self {
            path: path.into(),
            metadata,
            pre,
            source_deltas,
            target_deltas,
            head_deltas,
            inclusion_delay_deltas,
            inactivity_penalty_deltas,
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

    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        match fork_name {
            ForkName::Base => true,
            // FIXME(sproul): work out Altair
            ForkName::Altair => false,
        }
    }

    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let mut state = self.pre.clone();
        let spec = &testing_spec::<E>(fork_name);

        let deltas = (|| {
            // Processing requires the committee caches.
            state.build_all_committee_caches(spec)?;

            let mut validator_statuses = ValidatorStatuses::new(&state, spec)?;
            validator_statuses.process_attestations(&state)?;

            let deltas = base::rewards_and_penalties::get_attestation_deltas(
                &state,
                &validator_statuses,
                spec,
            )?;
            Ok(deltas)
        })();

        let components: Vec<(Accessor, Deltas)> = vec![
            (|d| &d.source_delta, self.source_deltas.clone()),
            (|d| &d.target_delta, self.target_deltas.clone()),
            (|d| &d.head_delta, self.head_deltas.clone()),
            (
                |d| &d.inclusion_delay_delta,
                self.inclusion_delay_deltas.clone(),
            ),
            (
                |d| &d.inactivity_penalty_delta,
                self.inactivity_penalty_deltas.clone(),
            ),
        ];

        for (accessor, expected) in components {
            let component_deltas = convert_base_res(&deltas, accessor);
            compare_result_detailed(&component_deltas, &Some(expected))?;
        }

        Ok(())
    }
}

fn convert_base_res(
    attestation_deltas: &Result<Vec<AttestationDelta>, EpochProcessingError>,
    accessor: Accessor,
) -> Result<Deltas, &EpochProcessingError> {
    attestation_deltas
        .as_ref()
        .map(|ad| convert_base_deltas(ad, accessor))
}

fn convert_base_deltas(attestation_deltas: &[AttestationDelta], accessor: Accessor) -> Deltas {
    let (rewards, penalties) = attestation_deltas
        .iter()
        .map(accessor)
        .map(|delta| (delta.rewards, delta.penalties))
        .unzip();
    Deltas { rewards, penalties }
}
