use super::*;
use crate::bls_setting::BlsSetting;
use crate::case_result::compare_beacon_state_results_without_caches;
use serde_derive::Deserialize;
use state_processing::{
    per_block_processing, per_slot_processing, BlockProcessingError, BlockSignatureStrategy,
};
use types::{BeaconBlock, BeaconState, EthSpec, RelativeEpoch};

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct SanityBlocks<E: EthSpec> {
    pub description: String,
    pub bls_setting: Option<BlsSetting>,
    pub pre: BeaconState<E>,
    pub blocks: Vec<BeaconBlock<E>>,
    pub post: Option<BeaconState<E>>,
}

impl<E: EthSpec> YamlDecode for SanityBlocks<E> {
    fn yaml_decode(yaml: &str) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(yaml).unwrap())
    }
}

impl<E: EthSpec> Case for SanityBlocks<E> {
    fn description(&self) -> String {
        self.description.clone()
    }

    fn result(&self, _case_index: usize) -> Result<(), Error> {
        self.bls_setting.unwrap_or_default().check()?;

        let mut state = self.pre.clone();
        let mut expected = self.post.clone();
        let spec = &E::default_spec();

        // Processing requires the epoch cache.
        state.build_all_caches(spec).unwrap();

        let mut result = self
            .blocks
            .iter()
            .try_for_each(|block| {
                while state.slot < block.slot {
                    per_slot_processing(&mut state, spec).unwrap();
                }

                state
                    .build_committee_cache(RelativeEpoch::Current, spec)
                    .unwrap();

                per_block_processing(
                    &mut state,
                    block,
                    None,
                    BlockSignatureStrategy::VerifyIndividual,
                    spec,
                )?;

                if block.state_root == state.canonical_root() {
                    Ok(())
                } else {
                    Err(BlockProcessingError::StateRootMismatch)
                }
            })
            .map(|_| state);

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
