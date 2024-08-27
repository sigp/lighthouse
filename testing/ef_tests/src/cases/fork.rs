use super::*;
use crate::case_result::compare_beacon_state_results_without_caches;
use crate::decode::{ssz_decode_state, yaml_decode_file};
use serde::Deserialize;
use state_processing::upgrade::{
    upgrade_to_altair, upgrade_to_bellatrix, upgrade_to_capella, upgrade_to_deneb,
    upgrade_to_electra,
};
use types::BeaconState;

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
        let pre_spec = fork_name
            .previous_fork()
            .unwrap_or(ForkName::Base)
            .make_genesis_spec(E::default_spec());
        let pre = ssz_decode_state(&path.join("pre.ssz_snappy"), &pre_spec)?;

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
            ForkName::Base => panic!("phase0 not supported"),
            ForkName::Altair => upgrade_to_altair(&mut result_state, spec).map(|_| result_state),
            ForkName::Bellatrix => {
                upgrade_to_bellatrix(&mut result_state, spec).map(|_| result_state)
            }
            ForkName::Capella => upgrade_to_capella(&mut result_state, spec).map(|_| result_state),
            ForkName::Deneb => upgrade_to_deneb(&mut result_state, spec).map(|_| result_state),
            ForkName::Electra => upgrade_to_electra(&mut result_state, spec).map(|_| result_state),
            ForkName::EIP7732 => todo!("upgrade_to_eip7732 not yet implemented"),
        };

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
