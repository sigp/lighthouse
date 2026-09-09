use super::*;
use crate::bls_setting::BlsSetting;
use crate::case_result::compare_beacon_state_results_without_caches;
use crate::decode::{ssz_decode_file_with, ssz_decode_state, yaml_decode_file};
use serde::Deserialize;
use state_processing::{
    BlockProcessingError, BlockSignatureStrategy, ConsensusContext, GloasVerificationContext,
    VerifyBlockRoot, per_block_processing, per_slot_processing,
};
use types::{BeaconState, RelativeEpoch, SignedBeaconBlock};

#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    pub description: Option<String>,
    pub bls_setting: Option<BlsSetting>,
    pub blocks_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct SanityBlocks<E: EthSpec> {
    pub case_name: String,
    pub metadata: Metadata,
    pub pre: BeaconState<E>,
    pub blocks: Vec<SignedBeaconBlock<E>>,
    pub post: Option<BeaconState<E>>,
}

impl<E: EthSpec> LoadCase for SanityBlocks<E> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let spec = &testing_spec::<E>(fork_name);
        let metadata: Metadata = yaml_decode_file(&path.join("meta.yaml"))?;
        let pre = ssz_decode_state(&path.join("pre.ssz_snappy"), spec)?;
        let blocks = (0..metadata.blocks_count)
            .map(|i| {
                let filename = format!("blocks_{}.ssz_snappy", i);
                ssz_decode_file_with(&path.join(filename), |bytes| {
                    SignedBeaconBlock::from_ssz_bytes(bytes, spec)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let post_file = path.join("post.ssz_snappy");
        let post = if post_file.is_file() {
            Some(ssz_decode_state(&post_file, spec)?)
        } else {
            None
        };
        let case_name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();

        Ok(Self {
            case_name,
            metadata,
            pre,
            blocks,
            post,
        })
    }
}

impl<E: EthSpec> Case for SanityBlocks<E> {
    fn description(&self) -> String {
        self.metadata.description.clone().unwrap_or_default()
    }

    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        // TODO(gloas): Remove once the EF test vectors include the fix from
        // https://github.com/ethereum/consensus-specs/pull/5594.
        const IGNORED_STALE_GLOAS_CASES: &[&str] = &[
            "epoch_boundary_full_parent_all_requests_gap_5_epochs",
            "epoch_boundary_full_parent_gap_1_epoch",
            "epoch_boundary_full_parent_gap_2_epochs",
            "epoch_boundary_full_parent_gap_5_epochs",
            "many_partial_withdrawals_in_epoch_transition",
            "missed_payload_recovery_resumes_with_remaining_withdrawals",
            "missed_payload_recovery_resumes_without_remaining_withdrawals",
            "partial_withdrawal_in_epoch_transition",
            "switch_to_compounding_across_epoch_boundary",
            "withdrawal_success_two_blocks",
        ];

        if fork_name == ForkName::Gloas
            && IGNORED_STALE_GLOAS_CASES.contains(&self.case_name.as_str())
        {
            return Err(Error::SkippedKnownFailure);
        }

        self.metadata.bls_setting.unwrap_or_default().check()?;

        let mut bulk_state = self.pre.clone();
        let mut expected = self.post.clone();
        let spec = &testing_spec::<E>(fork_name);

        // Processing requires the epoch cache.
        bulk_state.build_caches(spec).unwrap();

        // Spawning a second state to call the VerifyIndiviual strategy to avoid bitrot.
        // See https://github.com/sigp/lighthouse/issues/742.
        let mut indiv_state = bulk_state.clone();

        let result = self
            .blocks
            .iter()
            .try_for_each(|signed_block| {
                let block = signed_block.message();
                while bulk_state.slot() < block.slot() {
                    per_slot_processing(
                        &mut bulk_state,
                        None,
                        GloasVerificationContext::FullVerification,
                        spec,
                    )
                    .unwrap();
                    per_slot_processing(
                        &mut indiv_state,
                        None,
                        GloasVerificationContext::FullVerification,
                        spec,
                    )
                    .unwrap();
                }

                bulk_state
                    .build_committee_cache(RelativeEpoch::Current, spec)
                    .unwrap();

                indiv_state
                    .build_committee_cache(RelativeEpoch::Current, spec)
                    .unwrap();

                let mut ctxt = ConsensusContext::new(indiv_state.slot());
                per_block_processing(
                    &mut indiv_state,
                    signed_block,
                    BlockSignatureStrategy::VerifyIndividual,
                    VerifyBlockRoot::True,
                    &mut ctxt,
                    spec,
                )?;

                let mut ctxt = ConsensusContext::new(indiv_state.slot());
                per_block_processing(
                    &mut bulk_state,
                    signed_block,
                    BlockSignatureStrategy::VerifyBulk,
                    VerifyBlockRoot::True,
                    &mut ctxt,
                    spec,
                )?;

                if block.state_root() == bulk_state.update_tree_hash_cache().unwrap()
                    && block.state_root() == indiv_state.update_tree_hash_cache().unwrap()
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
