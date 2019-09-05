use super::*;
use crate::bls_setting::BlsSetting;
use crate::case_result::compare_beacon_state_results_without_caches;
use crate::decode::{ssz_decode_file, yaml_decode_file};
use crate::type_name;
use crate::type_name::TypeName;
use serde_derive::Deserialize;
use state_processing::per_epoch_processing::{
    errors::EpochProcessingError, process_crosslinks, process_final_updates,
    process_justification_and_finalization, process_registry_updates, process_slashings,
    validator_statuses::ValidatorStatuses,
};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use types::{BeaconState, ChainSpec, EthSpec};

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
pub struct Crosslinks;
#[derive(Debug)]
pub struct RegistryUpdates;
#[derive(Debug)]
pub struct Slashings;
#[derive(Debug)]
pub struct FinalUpdates;

type_name!(
    JustificationAndFinalization,
    "justification_and_finalization"
);
type_name!(Crosslinks, "crosslinks");
type_name!(RegistryUpdates, "registry_updates");
type_name!(Slashings, "slashings");
type_name!(FinalUpdates, "final_updates");

impl<E: EthSpec> EpochTransition<E> for JustificationAndFinalization {
    fn run(state: &mut BeaconState<E>, spec: &ChainSpec) -> Result<(), EpochProcessingError> {
        let mut validator_statuses = ValidatorStatuses::new(state, spec)?;
        validator_statuses.process_attestations(state, spec)?;
        process_justification_and_finalization(state, &validator_statuses.total_balances)
    }
}

impl<E: EthSpec> EpochTransition<E> for Crosslinks {
    fn run(state: &mut BeaconState<E>, spec: &ChainSpec) -> Result<(), EpochProcessingError> {
        process_crosslinks(state, spec)?;
        Ok(())
    }
}

impl<E: EthSpec> EpochTransition<E> for RegistryUpdates {
    fn run(state: &mut BeaconState<E>, spec: &ChainSpec) -> Result<(), EpochProcessingError> {
        process_registry_updates(state, spec)
    }
}

impl<E: EthSpec> EpochTransition<E> for Slashings {
    fn run(state: &mut BeaconState<E>, spec: &ChainSpec) -> Result<(), EpochProcessingError> {
        let mut validator_statuses = ValidatorStatuses::new(&state, spec)?;
        validator_statuses.process_attestations(&state, spec)?;
        process_slashings(state, validator_statuses.total_balances.current_epoch, spec)?;
        Ok(())
    }
}

impl<E: EthSpec> EpochTransition<E> for FinalUpdates {
    fn run(state: &mut BeaconState<E>, spec: &ChainSpec) -> Result<(), EpochProcessingError> {
        process_final_updates(state, spec)
    }
}

impl<E: EthSpec, T: EpochTransition<E>> LoadCase for EpochProcessing<E, T> {
    fn load_from_dir(path: &Path) -> Result<Self, Error> {
        let metadata_path = path.join("meta.yaml");
        let metadata: Metadata = if metadata_path.is_file() {
            yaml_decode_file(&metadata_path)?
        } else {
            Metadata::default()
        };
        let pre = ssz_decode_file(&path.join("pre.ssz"))?;
        let post_file = path.join("post.ssz");
        let post = if post_file.is_file() {
            Some(ssz_decode_file(&post_file)?)
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

    fn result(&self, _case_index: usize) -> Result<(), Error> {
        let mut state = self.pre.clone();
        let mut expected = self.post.clone();

        let spec = &E::default_spec();

        let mut result = (|| {
            // Processing requires the epoch cache.
            state.build_all_caches(spec)?;

            T::run(&mut state, spec).map(|_| state)
        })();

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
