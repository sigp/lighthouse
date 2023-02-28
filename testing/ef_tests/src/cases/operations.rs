use super::*;
use crate::bls_setting::BlsSetting;
use crate::case_result::compare_beacon_state_results_without_caches;
use crate::decode::{ssz_decode_file, ssz_decode_file_with, ssz_decode_state, yaml_decode_file};
use crate::testing_spec;
use serde_derive::Deserialize;
use state_processing::{
    per_block_processing::{
        errors::BlockProcessingError,
        process_block_header, process_execution_payload,
        process_operations::{
            altair, base, process_attester_slashings, process_bls_to_execution_changes,
            process_deposits, process_exits, process_proposer_slashings,
        },
        process_sync_aggregate, process_withdrawals, VerifyBlockRoot, VerifySignatures,
    },
    ConsensusContext,
};
use std::fmt::Debug;
use std::path::Path;
use types::{
    Attestation, AttesterSlashing, BeaconBlock, BeaconState, BlindedPayload, ChainSpec, Deposit,
    EthSpec, ExecutionPayload, ForkName, FullPayload, ProposerSlashing, SignedBlsToExecutionChange,
    SignedVoluntaryExit, SyncAggregate,
};

#[derive(Debug, Clone, Default, Deserialize)]
struct Metadata {
    description: Option<String>,
    bls_setting: Option<BlsSetting>,
}

#[derive(Debug, Clone, Deserialize)]
struct ExecutionMetadata {
    execution_valid: bool,
}

/// Newtype for testing withdrawals.
#[derive(Debug, Clone, Deserialize)]
pub struct WithdrawalsPayload<T: EthSpec> {
    payload: FullPayload<T>,
}

#[derive(Debug, Clone)]
pub struct Operations<E: EthSpec, O: Operation<E>> {
    metadata: Metadata,
    execution_metadata: Option<ExecutionMetadata>,
    pub pre: BeaconState<E>,
    pub operation: Option<O>,
    pub post: Option<BeaconState<E>>,
}

pub trait Operation<E: EthSpec>: Debug + Sync + Sized {
    fn handler_name() -> String;

    fn filename() -> String {
        format!("{}.ssz_snappy", Self::handler_name())
    }

    fn is_enabled_for_fork(_fork_name: ForkName) -> bool {
        true
    }

    fn decode(path: &Path, fork_name: ForkName, spec: &ChainSpec) -> Result<Self, Error>;

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
        _: &Operations<E, Self>,
    ) -> Result<(), BlockProcessingError>;
}

impl<E: EthSpec> Operation<E> for Attestation<E> {
    fn handler_name() -> String {
        "attestation".into()
    }

    fn decode(path: &Path, _fork_name: ForkName, _spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file(path)
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
        _: &Operations<E, Self>,
    ) -> Result<(), BlockProcessingError> {
        let mut ctxt = ConsensusContext::new(state.slot());
        match state {
            BeaconState::Base(_) => base::process_attestations(
                state,
                &[self.clone()],
                VerifySignatures::True,
                &mut ctxt,
                spec,
            ),
            BeaconState::Altair(_)
            | BeaconState::Merge(_)
            | BeaconState::Capella(_)
            | BeaconState::Eip4844(_) => {
                altair::process_attestation(state, self, 0, &mut ctxt, VerifySignatures::True, spec)
            }
        }
    }
}

impl<E: EthSpec> Operation<E> for AttesterSlashing<E> {
    fn handler_name() -> String {
        "attester_slashing".into()
    }

    fn decode(path: &Path, _fork_name: ForkName, _spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file(path)
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
        _: &Operations<E, Self>,
    ) -> Result<(), BlockProcessingError> {
        let mut ctxt = ConsensusContext::new(state.slot());
        process_attester_slashings(
            state,
            &[self.clone()],
            VerifySignatures::True,
            &mut ctxt,
            spec,
        )
    }
}

impl<E: EthSpec> Operation<E> for Deposit {
    fn handler_name() -> String {
        "deposit".into()
    }

    fn decode(path: &Path, _fork_name: ForkName, _spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file(path)
    }

    fn is_enabled_for_fork(_: ForkName) -> bool {
        // Some deposit tests require signature verification but are not marked as such.
        cfg!(not(feature = "fake_crypto"))
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
        _: &Operations<E, Self>,
    ) -> Result<(), BlockProcessingError> {
        process_deposits(state, &[self.clone()], spec)
    }
}

impl<E: EthSpec> Operation<E> for ProposerSlashing {
    fn handler_name() -> String {
        "proposer_slashing".into()
    }

    fn decode(path: &Path, _fork_name: ForkName, _spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file(path)
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
        _: &Operations<E, Self>,
    ) -> Result<(), BlockProcessingError> {
        let mut ctxt = ConsensusContext::new(state.slot());
        process_proposer_slashings(
            state,
            &[self.clone()],
            VerifySignatures::True,
            &mut ctxt,
            spec,
        )
    }
}

impl<E: EthSpec> Operation<E> for SignedVoluntaryExit {
    fn handler_name() -> String {
        "voluntary_exit".into()
    }

    fn decode(path: &Path, _fork_name: ForkName, _spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file(path)
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
        _: &Operations<E, Self>,
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

    fn decode(path: &Path, _fork_name: ForkName, spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file_with(path, |bytes| BeaconBlock::from_ssz_bytes(bytes, spec))
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
        _: &Operations<E, Self>,
    ) -> Result<(), BlockProcessingError> {
        let mut ctxt = ConsensusContext::new(state.slot());
        process_block_header(
            state,
            self.to_ref().temporary_block_header(),
            VerifyBlockRoot::True,
            &mut ctxt,
            spec,
        )?;
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

    fn decode(path: &Path, _fork_name: ForkName, _spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file(path)
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
        _: &Operations<E, Self>,
    ) -> Result<(), BlockProcessingError> {
        let proposer_index = state.get_beacon_proposer_index(state.slot(), spec)? as u64;
        process_sync_aggregate(state, self, proposer_index, VerifySignatures::True, spec)
    }
}

impl<E: EthSpec> Operation<E> for FullPayload<E> {
    fn handler_name() -> String {
        "execution_payload".into()
    }

    fn filename() -> String {
        "execution_payload.ssz_snappy".into()
    }

    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name != ForkName::Base && fork_name != ForkName::Altair
    }

    fn decode(path: &Path, fork_name: ForkName, _spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file_with(path, |bytes| {
            ExecutionPayload::from_ssz_bytes(bytes, fork_name)
        })
        .map(Into::into)
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
        extra: &Operations<E, Self>,
    ) -> Result<(), BlockProcessingError> {
        let valid = extra
            .execution_metadata
            .as_ref()
            .map_or(false, |e| e.execution_valid);
        if valid {
            process_execution_payload::<E, FullPayload<E>>(state, self.to_ref(), spec)
        } else {
            Err(BlockProcessingError::ExecutionInvalid)
        }
    }
}
impl<E: EthSpec> Operation<E> for BlindedPayload<E> {
    fn handler_name() -> String {
        "execution_payload".into()
    }

    fn filename() -> String {
        "execution_payload.ssz_snappy".into()
    }

    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name != ForkName::Base && fork_name != ForkName::Altair
    }

    fn decode(path: &Path, fork_name: ForkName, _spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file_with(path, |bytes| {
            ExecutionPayload::from_ssz_bytes(bytes, fork_name)
        })
        .map(Into::into)
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
        extra: &Operations<E, Self>,
    ) -> Result<(), BlockProcessingError> {
        let valid = extra
            .execution_metadata
            .as_ref()
            .map_or(false, |e| e.execution_valid);
        if valid {
            process_execution_payload::<E, BlindedPayload<E>>(state, self.to_ref(), spec)
        } else {
            Err(BlockProcessingError::ExecutionInvalid)
        }
    }
}

impl<E: EthSpec> Operation<E> for WithdrawalsPayload<E> {
    fn handler_name() -> String {
        "withdrawals".into()
    }

    fn filename() -> String {
        "execution_payload.ssz_snappy".into()
    }

    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name != ForkName::Base && fork_name != ForkName::Altair && fork_name != ForkName::Merge
    }

    fn decode(path: &Path, fork_name: ForkName, _spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file_with(path, |bytes| {
            ExecutionPayload::from_ssz_bytes(bytes, fork_name)
        })
        .map(|payload| WithdrawalsPayload {
            payload: payload.into(),
        })
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
        _: &Operations<E, Self>,
    ) -> Result<(), BlockProcessingError> {
        process_withdrawals::<_, FullPayload<_>>(state, self.payload.to_ref(), spec)
    }
}

impl<E: EthSpec> Operation<E> for SignedBlsToExecutionChange {
    fn handler_name() -> String {
        "bls_to_execution_change".into()
    }

    fn filename() -> String {
        "address_change.ssz_snappy".into()
    }

    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name != ForkName::Base && fork_name != ForkName::Altair && fork_name != ForkName::Merge
    }

    fn decode(path: &Path, _fork_name: ForkName, _spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file(path)
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
        _extra: &Operations<E, Self>,
    ) -> Result<(), BlockProcessingError> {
        process_bls_to_execution_changes(state, &[self.clone()], VerifySignatures::True, spec)
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

        // For execution payloads only.
        let execution_yaml_path = path.join("execution.yaml");
        let execution_metadata = if execution_yaml_path.is_file() {
            Some(yaml_decode_file(&execution_yaml_path)?)
        } else {
            None
        };

        let pre = ssz_decode_state(&path.join("pre.ssz_snappy"), spec)?;

        // Check BLS setting here before SSZ deserialization, as most types require signatures
        // to be valid.
        let (operation, bls_error) = if metadata.bls_setting.unwrap_or_default().check().is_ok() {
            match O::decode(&path.join(O::filename()), fork_name, spec) {
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
            execution_metadata,
            pre,
            operation,
            post,
        })
    }
}

impl<E: EthSpec, O: Operation<E>> Case for Operations<E, O> {
    fn description(&self) -> String {
        self.metadata.description.clone().unwrap_or_default()
    }

    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        O::is_enabled_for_fork(fork_name)
    }

    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let spec = &testing_spec::<E>(fork_name);
        let mut state = self.pre.clone();
        let mut expected = self.post.clone();

        // Processing requires the committee caches.
        // NOTE: some of the withdrawals tests have 0 active validators, do not try
        // to build the commitee cache in this case.
        if O::handler_name() != "withdrawals" {
            state.build_all_committee_caches(spec).unwrap();
        }

        let mut result = self
            .operation
            .as_ref()
            .ok_or(Error::SkippedBls)?
            .apply_to(&mut state, spec, self)
            .map(|()| state);

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
