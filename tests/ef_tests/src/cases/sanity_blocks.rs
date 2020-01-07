use super::*;
use crate::bls_setting::BlsSetting;
use crate::case_result::compare_beacon_state_results_without_caches;
use crate::decode::{ssz_decode_file, yaml_decode_file};
use serde_derive::Deserialize;
use state_processing::{
    per_block_processing, per_slot_processing, BlockProcessingError, BlockSignatureStrategy,
};
use types::{BeaconBlock, BeaconState, EthSpec, RelativeEpoch};

#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    pub description: Option<String>,
    pub bls_setting: Option<BlsSetting>,
    pub blocks_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct SanityBlocks<E: EthSpec> {
    pub metadata: Metadata,
    pub pre: BeaconState<E>,
    pub blocks: Vec<BeaconBlock<E>>,
    pub post: Option<BeaconState<E>>,
}

impl<E: EthSpec> LoadCase for SanityBlocks<E> {
    fn load_from_dir(path: &Path) -> Result<Self, Error> {
        let metadata: Metadata = yaml_decode_file(&path.join("meta.yaml"))?;
        let pre = ssz_decode_file(&path.join("pre.ssz"))?;
        let blocks: Vec<BeaconBlock<E>> = (0..metadata.blocks_count)
            .map(|i| {
                let filename = format!("blocks_{}.ssz", i);
                ssz_decode_file(&path.join(filename))
            })
            .collect::<Result<_, _>>()?;
        let post_file = path.join("post.ssz");
        let post = if post_file.is_file() {
            Some(ssz_decode_file(&post_file)?)
        } else {
            None
        };

        Ok(Self {
            metadata,
            pre,
            blocks,
            post,
        })
    }
}

impl<E: EthSpec> Case for SanityBlocks<E> {
    fn description(&self) -> String {
        self.metadata
            .description
            .clone()
            .unwrap_or_else(String::new)
    }

    fn result(&self, _case_index: usize) -> Result<(), Error> {
        self.metadata.bls_setting.unwrap_or_default().check()?;

        let mut bulk_state = self.pre.clone();
        let mut expected = self.post.clone();
        let spec = &E::default_spec();

        // Processing requires the epoch cache.
        bulk_state.build_all_caches(spec).unwrap();

        // Spawning a second state to call the VerifyIndiviual strategy to avoid bitrot.
        // See https://github.com/sigp/lighthouse/issues/742.
        let mut indiv_state = bulk_state.clone();

        let result = self
            .blocks
            .iter()
            .try_for_each(|block| {
                while bulk_state.slot < block.slot {
                    per_slot_processing(&mut bulk_state, None, spec).unwrap();
                    per_slot_processing(&mut indiv_state, None, spec).unwrap();
                }

                bulk_state
                    .build_committee_cache(RelativeEpoch::Current, spec)
                    .unwrap();

                indiv_state
                    .build_committee_cache(RelativeEpoch::Current, spec)
                    .unwrap();

                per_block_processing(
                    &mut indiv_state,
                    block,
                    None,
                    BlockSignatureStrategy::VerifyIndividual,
                    spec,
                )?;

                per_block_processing(
                    &mut bulk_state,
                    block,
                    None,
                    BlockSignatureStrategy::VerifyBulk,
                    spec,
                )?;

                if block.state_root == bulk_state.canonical_root()
                    && block.state_root == indiv_state.canonical_root()
                {
                    Ok(())
                } else {
                    Err(BlockProcessingError::StateRootMismatch)
                }
            })
            .map(|_| (bulk_state, indiv_state));

        let (mut bulk_result, mut indiv_result) = match result {
            Err(e) => (Err(e.clone()), Err(e)),
            Ok(res) => (Ok(res.0), Ok(res.1)),
        };
        compare_beacon_state_results_without_caches(&mut indiv_result, &mut expected)?;
        compare_beacon_state_results_without_caches(&mut bulk_result, &mut expected)
    }
}
