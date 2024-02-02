use super::*;
use crate::case_result::compare_result_detailed;
use crate::decode::{ssz_decode_file, ssz_decode_state, yaml_decode_file};
use compare_fields_derive::CompareFields;
use serde::Deserialize;
use ssz::four_byte_option_impl;
use ssz_derive::{Decode, Encode};
use state_processing::{
    per_epoch_processing::{
        base::{self, rewards_and_penalties::AttestationDelta, ValidatorStatuses},
        Delta,
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

// Define "legacy" implementations of `Option<Epoch>`, `Option<NonZeroUsize>` which use four bytes
// for encoding the union selector.
four_byte_option_impl!(four_byte_option_deltas, Deltas);

#[derive(Debug, Clone, PartialEq, Decode, Encode, CompareFields)]
pub struct AllDeltas {
    source_deltas: Deltas,
    target_deltas: Deltas,
    head_deltas: Deltas,
    #[ssz(with = "four_byte_option_deltas")]
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
        self.metadata.description.clone().unwrap_or_default()
    }

    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let mut state = self.pre.clone();

        // NOTE: We cannot run these tests for forks other than phase0 because single-pass epoch
        // processing cannot expose these individual deltas. There is no point maintaining a
        // separate implementation of rewards processing that will not be used in prod.
        if fork_name != ForkName::Base {
            return Ok(());
        }

        let spec = &testing_spec::<E>(fork_name);

        let deltas: Result<AllDeltas, EpochProcessingError> = (|| {
            // Processing requires the committee caches.
            state.build_all_committee_caches(spec)?;

            let mut validator_statuses = ValidatorStatuses::new(&state, spec)?;
            validator_statuses.process_attestations(&state)?;

            let deltas = base::rewards_and_penalties::get_attestation_deltas_all(
                &state,
                &validator_statuses,
                spec,
            )?;

            Ok(convert_all_base_deltas(&deltas))
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
