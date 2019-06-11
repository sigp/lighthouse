use super::*;
use crate::bls_setting::BlsSetting;
use crate::case_result::compare_beacon_state_results_without_caches;
use serde_derive::Deserialize;
use state_processing::{per_block_processing, per_slot_processing};
use types::{BeaconBlock, BeaconState, EthSpec};

#[derive(Debug, Clone, Deserialize)]
pub struct SanityBlocks<E: EthSpec> {
    pub description: String,
    pub bls_setting: Option<BlsSetting>,
    #[serde(bound = "E: EthSpec")]
    pub pre: BeaconState<E>,
    pub blocks: Vec<BeaconBlock>,
    #[serde(bound = "E: EthSpec")]
    pub post: Option<BeaconState<E>>,
}

impl<E: EthSpec> YamlDecode for SanityBlocks<E> {
    fn yaml_decode(yaml: &String) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(&yaml.as_str()).unwrap())
    }
}

impl<E: EthSpec> Case for SanityBlocks<E> {
    fn description(&self) -> String {
        self.description.clone()
    }

    fn result(&self, case_index: usize) -> Result<(), Error> {
        self.bls_setting.unwrap_or_default().check()?;

        let mut state = self.pre.clone();
        let mut expected = self.post.clone();
        let spec = &E::spec();

        // Processing requires the epoch cache.
        state.build_all_caches(&E::spec()).unwrap();

        let mut result = self
            .blocks
            .iter()
            .try_for_each(|block| {
                while state.slot < block.slot {
                    per_slot_processing(&mut state, spec).unwrap();
                }
                per_block_processing(&mut state, block, spec)
            })
            .map(|_| state);

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
