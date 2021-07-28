use super::*;
use crate::bls_setting::BlsSetting;
use crate::case_result::compare_beacon_state_results_without_caches;
use crate::decode::{ssz_decode_file, ssz_decode_file_with, ssz_decode_state, yaml_decode_file};
use crate::testing_spec;
use crate::type_name::TypeName;
use serde_derive::Deserialize;
use state_processing::per_block_processing::{
    errors::BlockProcessingError,
    process_block_header,
    process_operations::{
        altair, base, process_attester_slashings, process_deposits, process_exits,
        process_proposer_slashings,
    },
    process_sync_aggregate, VerifySignatures,
};
use std::fmt::Debug;
use std::path::Path;
use types::{
    Attestation, AttesterSlashing, BeaconBlock, BeaconState, ChainSpec, Deposit, EthSpec, ForkName,
    ProposerSlashing, SignedVoluntaryExit, SyncAggregate,
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

pub trait Operation<E: EthSpec>: TypeName + Debug + Sync + Sized {
    fn handler_name() -> String {
        Self::name().to_lowercase()
    }

    fn filename() -> String {
        format!("{}.ssz_snappy", Self::handler_name())
    }

    fn is_enabled_for_fork(_fork_name: ForkName) -> bool {
        true
    }

    fn decode(path: &Path, spec: &ChainSpec) -> Result<Self, Error>;

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError>;
}

impl<E: EthSpec> Operation<E> for Attestation<E> {
    fn decode(path: &Path, _spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file(path)
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        let proposer_index = state.get_beacon_proposer_index(state.slot(), spec)? as u64;
        match state {
            BeaconState::Base(_) => {
                base::process_attestations(state, &[self.clone()], VerifySignatures::True, spec)
            }
            BeaconState::Altair(_) => altair::process_attestation(
                state,
                self,
                0,
                proposer_index,
                VerifySignatures::True,
                spec,
            ),
        }
    }
}

impl<E: EthSpec> Operation<E> for AttesterSlashing<E> {
    fn handler_name() -> String {
        "attester_slashing".into()
    }

    fn decode(path: &Path, _spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file(path)
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
    fn decode(path: &Path, _spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file(path)
    }

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

    fn decode(path: &Path, _spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file(path)
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

    fn decode(path: &Path, _spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file(path)
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
        "block.ssz_snappy".into()
    }

    fn decode(path: &Path, spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file_with(path, |bytes| BeaconBlock::from_ssz_bytes(bytes, spec))
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        process_block_header(state, self.to_ref(), spec)?;
        Ok(())
    }
}

impl<E: EthSpec> Operation<E> for SyncAggregate<E> {
    fn handler_name() -> String {
        "sync_aggregate".into()
    }

    fn filename() -> String {
        "sync_aggregate.ssz_snappy".into()
    }

    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name != ForkName::Base
    }

    fn decode(path: &Path, _spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file(path)
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        let proposer_index = state.get_beacon_proposer_index(state.slot(), spec)? as u64;
        process_sync_aggregate(state, self, proposer_index, VerifySignatures::True, spec)
    }
}

impl<E: EthSpec, O: Operation<E>> LoadCase for Operations<E, O> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let spec = &testing_spec::<E>(fork_name);
        let metadata_path = path.join("meta.yaml");
        let metadata: Metadata = if metadata_path.is_file() {
            yaml_decode_file(&metadata_path)?
        } else {
            Metadata::default()
        };

        let pre = ssz_decode_state(&path.join("pre.ssz_snappy"), spec)?;

        // Check BLS setting here before SSZ deserialization, as most types require signatures
        // to be valid.
        let (operation, bls_error) = if metadata.bls_setting.unwrap_or_default().check().is_ok() {
            match O::decode(&path.join(O::filename()), spec) {
                Ok(op) => (Some(op), None),
                Err(Error::InvalidBLSInput(error)) => (None, Some(error)),
                Err(e) => return Err(e),
            }
        } else {
            (None, None)
        };
        let post_filename = path.join("post.ssz_snappy");
        let post = if post_filename.is_file() {
            if let Some(bls_error) = bls_error {
                panic!("input is unexpectedly invalid: {}", bls_error);
            }
            Some(ssz_decode_state(&post_filename, spec)?)
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

    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        O::is_enabled_for_fork(fork_name)
    }

    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let spec = &testing_spec::<E>(fork_name);
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
