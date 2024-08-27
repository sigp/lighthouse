use super::*;
use crate::case_result::compare_beacon_state_results_without_caches;
use crate::decode::{ssz_decode_file_with, ssz_decode_state, yaml_decode_file};
use serde::Deserialize;
use state_processing::{
    per_block_processing, state_advance::complete_state_advance, BlockSignatureStrategy,
    ConsensusContext, VerifyBlockRoot,
};
use std::str::FromStr;
use types::{BeaconState, Epoch, SignedBeaconBlock};

#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    pub post_fork: String,
    pub fork_epoch: Epoch,
    pub fork_block: Option<usize>,
    pub blocks_count: usize,
}

#[derive(Debug)]
pub struct TransitionTest<E: EthSpec> {
    pub metadata: Metadata,
    pub pre: BeaconState<E>,
    pub blocks: Vec<SignedBeaconBlock<E>>,
    pub post: BeaconState<E>,
    pub spec: ChainSpec,
}

impl<E: EthSpec> LoadCase for TransitionTest<E> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let metadata: Metadata = yaml_decode_file(&path.join("meta.yaml"))?;
        assert_eq!(ForkName::from_str(&metadata.post_fork).unwrap(), fork_name);

        // Make spec with appropriate fork block.
        let mut spec = E::default_spec();
        match fork_name {
            ForkName::Base => panic!("cannot fork to base/phase0"),
            ForkName::Altair => {
                spec.altair_fork_epoch = Some(metadata.fork_epoch);
            }
            ForkName::Bellatrix => {
                spec.altair_fork_epoch = Some(Epoch::new(0));
                spec.bellatrix_fork_epoch = Some(metadata.fork_epoch);
            }
            ForkName::Capella => {
                spec.altair_fork_epoch = Some(Epoch::new(0));
                spec.bellatrix_fork_epoch = Some(Epoch::new(0));
                spec.capella_fork_epoch = Some(metadata.fork_epoch);
            }
            ForkName::Deneb => {
                spec.altair_fork_epoch = Some(Epoch::new(0));
                spec.bellatrix_fork_epoch = Some(Epoch::new(0));
                spec.capella_fork_epoch = Some(Epoch::new(0));
                spec.deneb_fork_epoch = Some(metadata.fork_epoch);
            }
            ForkName::Electra => {
                spec.altair_fork_epoch = Some(Epoch::new(0));
                spec.bellatrix_fork_epoch = Some(Epoch::new(0));
                spec.capella_fork_epoch = Some(Epoch::new(0));
                spec.deneb_fork_epoch = Some(Epoch::new(0));
                spec.electra_fork_epoch = Some(metadata.fork_epoch);
            }
            ForkName::EIP7732 => {
                spec.altair_fork_epoch = Some(Epoch::new(0));
                spec.bellatrix_fork_epoch = Some(Epoch::new(0));
                spec.capella_fork_epoch = Some(Epoch::new(0));
                spec.deneb_fork_epoch = Some(Epoch::new(0));
                spec.electra_fork_epoch = Some(Epoch::new(0));
                spec.eip7732_fork_epoch = Some(metadata.fork_epoch);
            }
        }

        // Load blocks
        let blocks = (0..metadata.blocks_count)
            .map(|i| {
                let filename = format!("blocks_{}.ssz_snappy", i);
                ssz_decode_file_with(&path.join(filename), |bytes| {
                    SignedBeaconBlock::from_ssz_bytes(bytes, &spec)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Decode pre-state.
        let pre = ssz_decode_state(&path.join("pre.ssz_snappy"), &spec)?;

        // Decode post-state.
        let post = ssz_decode_state(&path.join("post.ssz_snappy"), &spec)?;

        Ok(Self {
            metadata,
            pre,
            blocks,
            post,
            spec,
        })
    }
}

impl<E: EthSpec> Case for TransitionTest<E> {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        // Upgrades exist targeting all forks except phase0/base.
        // Transition tests also need BLS.
        cfg!(not(feature = "fake_crypto")) && fork_name != ForkName::Base
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let mut state = self.pre.clone();
        let mut expected = Some(self.post.clone());
        let spec = &self.spec;

        let mut result: Result<_, String> = self
            .blocks
            .iter()
            .try_for_each(|block| {
                // Advance to block slot.
                complete_state_advance(&mut state, None, block.slot(), spec)
                    .map_err(|e| format!("Failed to advance: {:?}", e))?;

                // Apply block.
                let mut ctxt = ConsensusContext::new(state.slot());
                per_block_processing(
                    &mut state,
                    block,
                    BlockSignatureStrategy::VerifyBulk,
                    VerifyBlockRoot::True,
                    &mut ctxt,
                    spec,
                )
                .map_err(|e| format!("Block processing failed: {:?}", e))?;

                let state_root = state.update_tree_hash_cache().unwrap();
                if block.state_root() != state_root {
                    return Err(format!(
                        "Mismatched state root at slot {}, got: {:?}, expected: {:?}",
                        block.slot(),
                        state_root,
                        block.state_root()
                    ));
                }

                Ok(())
            })
            .map(move |()| state);

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
