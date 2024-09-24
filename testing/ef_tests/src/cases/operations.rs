use super::*;
use crate::bls_setting::BlsSetting;
use crate::case_result::compare_beacon_state_results_without_caches;
use crate::decode::{ssz_decode_file, ssz_decode_file_with, ssz_decode_state, yaml_decode_file};
use serde::Deserialize;
use ssz::Decode;
use state_processing::common::update_progressive_balances_cache::initialize_progressive_balances_cache;
use state_processing::epoch_cache::initialize_epoch_cache;
use state_processing::per_block_processing::process_operations::{
    process_consolidation_requests, process_deposit_requests, process_withdrawal_requests,
};
use state_processing::{
    per_block_processing::{
        errors::BlockProcessingError,
        process_block_header, process_execution_payload,
        process_operations::{
            altair_deneb, base, process_attester_slashings, process_bls_to_execution_changes,
            process_deposits, process_exits, process_proposer_slashings,
        },
        process_sync_aggregate, process_withdrawals, VerifyBlockRoot, VerifySignatures,
    },
    ConsensusContext,
};
use std::fmt::Debug;
use types::{
    Attestation, AttesterSlashing, BeaconBlock, BeaconBlockBody, BeaconBlockBodyBellatrix,
    BeaconBlockBodyCapella, BeaconBlockBodyDeneb, BeaconBlockBodyEIP7732, BeaconBlockBodyElectra,
    BeaconState, BlindedPayload, ConsolidationRequest, Deposit, DepositRequest, ExecutionPayload,
    FullPayload, ProposerSlashing, SignedBlsToExecutionChange, SignedVoluntaryExit, SyncAggregate,
    WithdrawalRequest,
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
pub struct WithdrawalsPayload<E: EthSpec> {
    payload: FullPayload<E>,
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

    fn decode(path: &Path, fork_name: ForkName, _spec: &ChainSpec) -> Result<Self, Error> {
        if fork_name < ForkName::Electra {
            Ok(Self::Base(ssz_decode_file(path)?))
        } else {
            Ok(Self::Electra(ssz_decode_file(path)?))
        }
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
        _: &Operations<E, Self>,
    ) -> Result<(), BlockProcessingError> {
        initialize_epoch_cache(state, spec)?;
        let mut ctxt = ConsensusContext::new(state.slot());
        match state {
            BeaconState::Base(_) => base::process_attestations(
                state,
                [self.clone().to_ref()].into_iter(),
                VerifySignatures::True,
                &mut ctxt,
                spec,
            ),
            BeaconState::Altair(_)
            | BeaconState::Bellatrix(_)
            | BeaconState::Capella(_)
            | BeaconState::Deneb(_)
            | BeaconState::Electra(_)
            | BeaconState::EIP7732(_) => {
                initialize_progressive_balances_cache(state, spec)?;
                altair_deneb::process_attestation(
                    state,
                    self.to_ref(),
                    0,
                    &mut ctxt,
                    VerifySignatures::True,
                    spec,
                )
            }
        }
    }
}

impl<E: EthSpec> Operation<E> for AttesterSlashing<E> {
    fn handler_name() -> String {
        "attester_slashing".into()
    }

    fn decode(path: &Path, fork_name: ForkName, _spec: &ChainSpec) -> Result<Self, Error> {
        Ok(match fork_name {
            ForkName::Base
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb => Self::Base(ssz_decode_file(path)?),
            ForkName::Electra | ForkName::EIP7732 => Self::Electra(ssz_decode_file(path)?),
        })
    }

    fn apply_to(
        &self,
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
        _: &Operations<E, Self>,
    ) -> Result<(), BlockProcessingError> {
        let mut ctxt = ConsensusContext::new(state.slot());
        initialize_progressive_balances_cache(state, spec)?;
        process_attester_slashings(
            state,
            [self.clone().to_ref()].into_iter(),
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
        initialize_progressive_balances_cache(state, spec)?;
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
        fork_name.altair_enabled()
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

impl<E: EthSpec> Operation<E> for BeaconBlockBody<E, FullPayload<E>> {
    fn handler_name() -> String {
        "execution_payload".into()
    }

    fn filename() -> String {
        "body.ssz_snappy".into()
    }

    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name.bellatrix_enabled()
    }

    fn decode(path: &Path, fork_name: ForkName, _spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file_with(path, |bytes| {
            Ok(match fork_name {
                ForkName::Bellatrix => BeaconBlockBody::Bellatrix(<_>::from_ssz_bytes(bytes)?),
                ForkName::Capella => BeaconBlockBody::Capella(<_>::from_ssz_bytes(bytes)?),
                ForkName::Deneb => BeaconBlockBody::Deneb(<_>::from_ssz_bytes(bytes)?),
                ForkName::Electra => BeaconBlockBody::Electra(<_>::from_ssz_bytes(bytes)?),
                ForkName::EIP7732 => BeaconBlockBody::EIP7732(<_>::from_ssz_bytes(bytes)?),
                _ => panic!(),
            })
        })
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
impl<E: EthSpec> Operation<E> for BeaconBlockBody<E, BlindedPayload<E>> {
    fn handler_name() -> String {
        "execution_payload".into()
    }

    fn filename() -> String {
        "body.ssz_snappy".into()
    }

    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name.bellatrix_enabled()
    }

    fn decode(path: &Path, fork_name: ForkName, _spec: &ChainSpec) -> Result<Self, Error> {
        ssz_decode_file_with(path, |bytes| {
            Ok(match fork_name {
                ForkName::Bellatrix => {
                    let inner =
                        <BeaconBlockBodyBellatrix<E, FullPayload<E>>>::from_ssz_bytes(bytes)?;
                    BeaconBlockBody::Bellatrix(inner.clone_as_blinded())
                }
                ForkName::Capella => {
                    let inner = <BeaconBlockBodyCapella<E, FullPayload<E>>>::from_ssz_bytes(bytes)?;
                    BeaconBlockBody::Capella(inner.clone_as_blinded())
                }
                ForkName::Deneb => {
                    let inner = <BeaconBlockBodyDeneb<E, FullPayload<E>>>::from_ssz_bytes(bytes)?;
                    BeaconBlockBody::Deneb(inner.clone_as_blinded())
                }
                ForkName::Electra => {
                    let inner = <BeaconBlockBodyElectra<E, FullPayload<E>>>::from_ssz_bytes(bytes)?;
                    BeaconBlockBody::Electra(inner.clone_as_blinded())
                }
                ForkName::EIP7732 => {
                    let inner = <BeaconBlockBodyEIP7732<E, FullPayload<E>>>::from_ssz_bytes(bytes)?;
                    BeaconBlockBody::EIP7732(inner.clone_as_blinded())
                }
                _ => panic!(),
            })
        })
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
        fork_name.capella_enabled()
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
        if state.fork_name_unchecked().eip7732_enabled() {
            process_withdrawals::eip7732::process_withdrawals(state, spec)
        } else {
            process_withdrawals::capella::process_withdrawals::<_, FullPayload<_>>(
                state,
                self.payload.to_ref(),
                spec,
            )
        }
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
        fork_name.capella_enabled()
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

impl<E: EthSpec> Operation<E> for WithdrawalRequest {
    fn handler_name() -> String {
        "withdrawal_request".into()
    }

    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name.electra_enabled()
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
        state.update_pubkey_cache()?;
        process_withdrawal_requests(state, &[self.clone()], spec)
    }
}

impl<E: EthSpec> Operation<E> for DepositRequest {
    fn handler_name() -> String {
        "deposit_request".into()
    }

    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name.electra_enabled()
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
        process_deposit_requests(state, &[self.clone()], spec)
    }
}

impl<E: EthSpec> Operation<E> for ConsolidationRequest {
    fn handler_name() -> String {
        "consolidation_request".into()
    }

    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name.electra_enabled()
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
        state.update_pubkey_cache()?;
        process_consolidation_requests(state, &[self.clone()], spec)
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

        let mut pre_state = self.pre.clone();
        // Processing requires the committee caches.
        // NOTE: some of the withdrawals tests have 0 active validators, do not try
        // to build the commitee cache in this case.
        if O::handler_name() != "withdrawals" {
            pre_state.build_all_committee_caches(spec).unwrap();
        }

        let mut state = pre_state.clone();
        let mut expected = self.post.clone();

        if O::handler_name() != "withdrawals" {
            if let Some(post_state) = expected.as_mut() {
                post_state.build_all_committee_caches(spec).unwrap();
            }
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
