use super::*;
use crate::bls_setting::BlsSetting;
use crate::case_result::compare_beacon_state_results_without_caches;
use crate::decode::{ssz_decode_file, yaml_decode_file};
use crate::type_name::TypeName;
use serde_derive::Deserialize;
use ssz::Decode;
use state_processing::per_block_processing::{
    errors::BlockProcessingError, process_attestations, process_attester_slashings,
    process_block_header, process_deposits, process_exits, process_proposer_slashings,
    VerifySignatures,
};
use std::fmt::Debug;
use std::path::Path;
use types::{
    Attestation, AttesterSlashing, BeaconBlock, BeaconState, ChainSpec, Deposit, EthSpec,
    ProposerSlashing, SignedVoluntaryExit,
};

#[derive(Debug, Clone, Default, Deserialize)]
struct Metadata {
    description: Option<String>,
    bls_setting: Option<BlsSetting>,
}

#[derive(Debug, Clone)]
pub struct Operations<E: EthSpec, O: Operation<E>> {
    metadata: Metadata,
    pub pre: BeaconState<E>,
    pub operation: Option<O>,
    pub post: Option<BeaconState<E>>,
}

pub trait Operation<E: EthSpec>: Decode + TypeName + Debug + Sync {
    fn handler_name() -> String {
        Self::name().to_lowercase()
    }

    fn filename() -> String {
        format!("{}.ssz", Self::handler_name())
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError>;
}

impl<E: EthSpec> Operation<E> for Attestation<E> {
    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        process_attestations(state, &[self.clone()], VerifySignatures::True, spec)
    }
}

impl<E: EthSpec> Operation<E> for AttesterSlashing<E> {
    fn handler_name() -> String {
        "attester_slashing".into()
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        process_attester_slashings(state, &[self.clone()], VerifySignatures::True, spec)
    }
}

impl<E: EthSpec> Operation<E> for Deposit {
    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        process_deposits(state, &[self.clone()], spec)
    }
}

impl<E: EthSpec> Operation<E> for ProposerSlashing {
    fn handler_name() -> String {
        "proposer_slashing".into()
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        process_proposer_slashings(state, &[self.clone()], VerifySignatures::True, spec)
    }
}

impl<E: EthSpec> Operation<E> for SignedVoluntaryExit {
    fn handler_name() -> String {
        "voluntary_exit".into()
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        process_exits(state, &[self.clone()], VerifySignatures::True, spec)
    }
}

impl<E: EthSpec> Operation<E> for BeaconBlock<E> {
    fn handler_name() -> String {
        "block_header".into()
    }

    fn filename() -> String {
        "block.ssz".into()
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        Ok(process_block_header(state, self, spec)?)
    }
}

impl<E: EthSpec, O: Operation<E>> LoadCase for Operations<E, O> {
    fn load_from_dir(path: &Path) -> Result<Self, Error> {
        let metadata_path = path.join("meta.yaml");
        let metadata: Metadata = if metadata_path.is_file() {
            yaml_decode_file(&metadata_path)?
        } else {
            Metadata::default()
        };

        let pre = ssz_decode_file(&path.join("pre.ssz"))?;

        // Check BLS setting here before SSZ deserialization, as most types require signatures
        // to be valid.
        let (operation, bls_error) = if metadata.bls_setting.unwrap_or_default().check().is_ok() {
            match ssz_decode_file(&path.join(O::filename())) {
                Ok(op) => (Some(op), None),
                Err(Error::InvalidBLSInput(error)) => (None, Some(error)),
                Err(e) => return Err(e),
            }
        } else {
            (None, None)
        };
        let post_filename = path.join("post.ssz");
        let post = if post_filename.is_file() {
            if let Some(bls_error) = bls_error {
                panic!("input is unexpectedly invalid: {}", bls_error);
            }
            Some(ssz_decode_file(&post_filename)?)
        } else {
            None
        };

        Ok(Self {
            metadata,
            pre,
            operation,
            post,
        })
    }
}

impl<E: EthSpec, O: Operation<E>> Case for Operations<E, O> {
    fn description(&self) -> String {
        self.metadata
            .description
            .clone()
            .unwrap_or_else(String::new)
    }

    fn result(&self, _case_index: usize) -> Result<(), Error> {
        let spec = &E::default_spec();
        let mut state = self.pre.clone();
        let mut expected = self.post.clone();

        // Processing requires the committee caches.
        state
            .build_all_committee_caches(spec)
            .expect("committee caches OK");

        let mut result = self
            .operation
            .as_ref()
            .ok_or(Error::SkippedBls)?
            .apply_to(&mut state, spec)
            .map(|()| state);

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
