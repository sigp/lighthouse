use super::*;
use crate::bls_setting::BlsSetting;
use crate::case_result::compare_beacon_state_results_without_caches;
use crate::decode::{ssz_decode_file, yaml_decode_file};
use serde_derive::Deserialize;
use state_processing::per_slot_processing;
use types::{BeaconState, EthSpec};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Metadata {
    pub description: Option<String>,
    pub bls_setting: Option<BlsSetting>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct SanitySlots<E: EthSpec> {
    pub metadata: Metadata,
    pub pre: BeaconState<E>,
    pub slots: u64,
    pub post: Option<BeaconState<E>>,
}

impl<E: EthSpec> LoadCase for SanitySlots<E> {
    fn load_from_dir(path: &Path) -> Result<Self, Error> {
        let metadata_path = path.join("meta.yaml");
        let metadata: Metadata = if metadata_path.is_file() {
            yaml_decode_file(&metadata_path)?
        } else {
            Metadata::default()
        };
        let pre = ssz_decode_file(&path.join("pre.ssz"))?;
        let slots: u64 = yaml_decode_file(&path.join("slots.yaml"))?;
        let post_file = path.join("post.ssz");
        let post = if post_file.is_file() {
            Some(ssz_decode_file(&post_file)?)
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

impl<E: EthSpec> Case for SanitySlots<E> {
    fn description(&self) -> String {
        self.metadata
            .description
            .clone()
            .unwrap_or_else(String::new)
    }

    fn result(&self, _case_index: usize) -> Result<(), Error> {
        self.metadata.bls_setting.unwrap_or_default().check()?;

        let mut state = self.pre.clone();
        let mut expected = self.post.clone();
        let spec = &E::default_spec();

        // Processing requires the epoch cache.
        state.build_all_caches(spec).unwrap();

        let mut result = (0..self.slots)
            .try_for_each(|_| per_slot_processing(&mut state, None, spec))
            .map(|_| state);

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
