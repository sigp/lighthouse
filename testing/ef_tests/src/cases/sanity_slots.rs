use super::*;
use crate::bls_setting::BlsSetting;
use crate::case_result::compare_beacon_state_results_without_caches;
use crate::decode::{ssz_decode_state, yaml_decode_file};
use serde::Deserialize;
use state_processing::per_slot_processing;
use types::BeaconState;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Metadata {
    pub description: Option<String>,
    pub bls_setting: Option<BlsSetting>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SanitySlots {
    pub metadata: Metadata,
    pub pre: BeaconState,
    pub slots: u64,
    pub post: Option<BeaconState>,
}

impl LoadCase for SanitySlots {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let spec = &testing_spec(fork_name);
        let metadata_path = path.join("meta.yaml");
        let metadata: Metadata = if metadata_path.is_file() {
            yaml_decode_file(&metadata_path)?
        } else {
            Metadata::default()
        };
        let pre = ssz_decode_state(&path.join("pre.ssz_snappy"), spec)?;
        let slots: u64 = yaml_decode_file(&path.join("slots.yaml"))?;
        let post_file = path.join("post.ssz_snappy");
        let post = if post_file.is_file() {
            Some(ssz_decode_state(&post_file, spec)?)
        } else {
            None
        };

        Ok(Self {
            metadata,
            pre,
            slots,
            post,
        })
    }
}

impl Case for SanitySlots {
    fn description(&self) -> String {
        self.metadata.description.clone().unwrap_or_default()
    }

    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        self.metadata.bls_setting.unwrap_or_default().check()?;

        let mut state = self.pre.clone();
        let mut expected = self.post.clone();
        let spec = &testing_spec(fork_name);

        // Processing requires the epoch cache.
        state.build_caches(spec).unwrap();

        let mut result = (0..self.slots)
            .try_for_each(|_| per_slot_processing(&mut state, None, spec).map(|_| ()))
            .map(|_| state);

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
