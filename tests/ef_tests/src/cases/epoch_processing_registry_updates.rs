use super::*;
use crate::case_result::compare_beacon_state_results_without_caches;
use serde_derive::Deserialize;
use state_processing::per_block_processing::per_block_processing;
use state_processing::per_epoch_processing::registry_updates::process_registry_updates;
use state_processing::per_slot_processing;
use types::{BeaconBlock, BeaconState, EthSpec};

#[derive(Debug, Clone, Deserialize)]
pub struct EpochProcessingRegistryUpdates<E: EthSpec> {
    pub description: String,
    #[serde(bound = "E: EthSpec")]
    pub pre: BeaconState<E>,
    pub trigger_block: BeaconBlock,
    #[serde(bound = "E: EthSpec")]
    pub post: Option<BeaconState<E>>,
}

impl<E: EthSpec> YamlDecode for EpochProcessingRegistryUpdates<E> {
    fn yaml_decode(yaml: &String) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(&yaml.as_str()).unwrap())
    }
}

impl<E: EthSpec> Case for EpochProcessingRegistryUpdates<E> {
    fn description(&self) -> String {
        self.description.clone()
    }

    fn result(&self, _case_index: usize) -> Result<(), Error> {
        let mut state = self.pre.clone();
        let mut expected = self.post.clone();
        let spec = &E::spec();

        // Processing requires the epoch cache.
        state.build_all_caches(spec).unwrap();

        // Apply the trigger block.
        // FIXME: trigger block gets applied to state after per-epoch processing (test bug)
        while state.slot < self.trigger_block.slot {
            per_slot_processing(&mut state, spec).expect("slot processing failed");
        }
        per_block_processing(&mut state, &self.trigger_block, spec).expect("process block");

        let mut result = process_registry_updates(&mut state, spec).map(|_| state);

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
