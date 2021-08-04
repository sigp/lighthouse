use super::*;
use crate::case_result::compare_beacon_state_results_without_caches;
use crate::cases::common::previous_fork;
use crate::decode::{ssz_decode_state, yaml_decode_file};
use serde_derive::Deserialize;
use state_processing::upgrade::upgrade_to_altair;
use types::{BeaconState, ForkName};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Metadata {
    pub fork: String,
}

impl Metadata {
    fn fork_name(&self) -> ForkName {
        self.fork.parse().unwrap()
    }
}

#[derive(Debug)]
pub struct ForkTest<E: EthSpec> {
    pub metadata: Metadata,
    pub pre: BeaconState<E>,
    pub post: BeaconState<E>,
}

impl<E: EthSpec> LoadCase for ForkTest<E> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let metadata: Metadata = yaml_decode_file(&path.join("meta.yaml"))?;
        assert_eq!(metadata.fork_name(), fork_name);

        // Decode pre-state with previous fork.
        let pre_spec = &previous_fork(fork_name).make_genesis_spec(E::default_spec());
        let pre = ssz_decode_state(&path.join("pre.ssz_snappy"), pre_spec)?;

        // Decode post-state with target fork.
        let post_spec = &fork_name.make_genesis_spec(E::default_spec());
        let post = ssz_decode_state(&path.join("post.ssz_snappy"), post_spec)?;

        Ok(Self {
            metadata,
            pre,
            post,
        })
    }
}

impl<E: EthSpec> Case for ForkTest<E> {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        // Upgrades exist targeting all forks except phase0/base.
        // Fork tests also need BLS.
        cfg!(not(feature = "fake_crypto")) && fork_name != ForkName::Base
    }

    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let mut result_state = self.pre.clone();
        let mut expected = Some(self.post.clone());
        let spec = &E::default_spec();

        let mut result = match fork_name {
            ForkName::Altair => upgrade_to_altair(&mut result_state, spec).map(|_| result_state),
            _ => panic!("unknown fork: {:?}", fork_name),
        };

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
