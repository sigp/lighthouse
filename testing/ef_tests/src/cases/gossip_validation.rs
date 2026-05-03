use super::*;
use crate::decode::{
    snappy_decode_file, ssz_decode_file, ssz_decode_file_with, ssz_decode_state, yaml_decode_file,
};
use crate::type_name::TypeName;
use ::fork_choice::InvalidationOperation;
use beacon_chain::attestation_verification::Error as AttestationError;
use beacon_chain::block_verification_types::LookupBlock;
use beacon_chain::sync_committee_verification::Error as SyncCommitteeError;
use beacon_chain::{
    AvailabilityProcessingStatus, BeaconChainError, BlockError, ChainConfig, NotifyExecutionLayer,
    custody_context::NodeCustodyType,
    observed_operations::ObservationOutcome,
    test_utils::{BeaconChainHarness, EphemeralHarnessType},
};
use operation_pool::ReceivedPreCapella;
use serde::Deserialize;
use ssz::Decode;
use state_processing::common::update_progressive_balances_cache::initialize_progressive_balances_cache;
use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use types::{
    Attestation, AttestationBase, AttestationElectra, AttesterSlashing, BeaconState,
    BlockImportSource, Checkpoint, Epoch, EthSpec, ForkName, Hash256, ProposerSlashing,
    SignedAggregateAndProof, SignedBeaconBlock, SignedBlsToExecutionChange,
    SignedContributionAndProof, SignedVoluntaryExit, SingleAttestation, Slot, SubnetId,
    SyncCommitteeMessage, SyncSubnetId,
};

pub(crate) const RUNNER_NAME: &str = "networking";
pub(crate) const HANDLER_NAME: &str = "gossip_validation";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Meta {
    topic: Topic,
    #[serde(default)]
    blocks: Vec<BlockMeta>,
    finalized_checkpoint: Option<FinalizedCheckpointMeta>,
    current_time_ms: u64,
    messages: Vec<MessageMeta>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockMeta {
    block: String,
    #[serde(default)]
    failed: bool,
    payload_status: Option<PayloadStatus>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageMeta {
    offset_ms: u64,
    subnet_id: Option<u64>,
    message: String,
    expected: Expected,
    reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Expected {
    Valid,
    Ignore,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Topic {
    BeaconBlock,
    BeaconAttestation,
    BeaconAggregateAndProof,
    ProposerSlashing,
    AttesterSlashing,
    VoluntaryExit,
    SyncCommitteeContributionAndProof,
    SyncCommittee,
    BlsToExecutionChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum PayloadStatus {
    Valid,
    Invalidated,
    NotValidated,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalizedCheckpointMeta {
    epoch: u64,
    root: Option<Hash256>,
    block: Option<String>,
}

#[derive(Debug)]
pub struct GossipValidation<E: EthSpec> {
    description: String,
    path: PathBuf,
    meta: Meta,
    state: BeaconState<E>,
    blocks: Vec<PreloadedBlock<E>>,
    messages: Vec<Message<E>>,
}

#[derive(Debug)]
struct PreloadedBlock<E: EthSpec> {
    meta: BlockMeta,
    block: SignedBeaconBlock<E>,
}

#[derive(Debug)]
enum Message<E: EthSpec> {
    BeaconBlock(Arc<SignedBeaconBlock<E>>),
    BeaconAttestation(AttestationMessage<E>),
    BeaconAggregateAndProof(SignedAggregateAndProof<E>),
    ProposerSlashing(ProposerSlashing),
    AttesterSlashing(AttesterSlashing<E>),
    VoluntaryExit(SignedVoluntaryExit),
    SyncCommitteeContributionAndProof(SignedContributionAndProof<E>),
    SyncCommittee(SyncCommitteeMessage),
    BlsToExecutionChange(SignedBlsToExecutionChange),
}

#[derive(Debug)]
enum AttestationMessage<E: EthSpec> {
    Single(SingleAttestation),
    Attestation(Attestation<E>),
}

impl<E: EthSpec> LoadCase for GossipValidation<E> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let description = path
            .iter()
            .next_back()
            .expect("path must be non-empty")
            .to_str()
            .expect("path must be valid OsStr")
            .to_string();
        let spec = &testing_spec::<E>(fork_name);
        let meta: Meta = yaml_decode_file(&path.join("meta.yaml"))?;
        let state = ssz_decode_state(&path.join("state.ssz_snappy"), spec)?;

        let blocks = meta
            .blocks
            .iter()
            .map(|block_meta| {
                let block =
                    decode_block(&path.join(format!("{}.ssz_snappy", block_meta.block)), spec)?;
                Ok(PreloadedBlock {
                    meta: block_meta.clone(),
                    block,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let messages = meta
            .messages
            .iter()
            .map(|message_meta| decode_message(path, fork_name, &meta.topic, message_meta))
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(Self {
            description,
            path: path.to_path_buf(),
            meta,
            state,
            blocks,
            messages,
        })
    }
}

impl<E: EthSpec + TypeName> Case for GossipValidation<E> {
    fn description(&self) -> String {
        self.description.clone()
    }

    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        gossip_validation_handler_path::<E>(fork_name).exists()
    }

    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let tester = GossipValidationTester::new(self, testing_spec::<E>(fork_name))?;

        for (message_meta, message) in self.meta.messages.iter().zip(&self.messages) {
            tester.set_time_ms(
                self.meta
                    .current_time_ms
                    .checked_add(message_meta.offset_ms)
                    .ok_or_else(|| Error::FailedToParseTest("message time overflows u64".into()))?,
            )?;

            let actual = tester.validate_message(message, message_meta.subnet_id, fork_name)?;
            if actual != message_meta.expected {
                return Err(Error::NotEqual(format!(
                    "{}: expected {:?}, got {:?}{}",
                    self.path.display(),
                    message_meta.expected,
                    actual,
                    message_meta
                        .reason
                        .as_ref()
                        .map(|reason| format!(" ({reason})"))
                        .unwrap_or_default()
                )));
            }
        }

        Ok(())
    }
}

fn gossip_validation_handler_path<E: EthSpec + TypeName>(fork_name: ForkName) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("consensus-spec-tests")
        .join("tests")
        .join(E::name())
        .join(fork_name.to_string())
        .join(RUNNER_NAME)
        .join(HANDLER_NAME)
}

fn decode_block<E: EthSpec>(
    path: &Path,
    spec: &types::ChainSpec,
) -> Result<SignedBeaconBlock<E>, Error> {
    ssz_decode_file_with(path, |bytes| SignedBeaconBlock::from_ssz_bytes(bytes, spec))
}

fn decode_message<E: EthSpec>(
    path: &Path,
    fork_name: ForkName,
    topic: &Topic,
    message_meta: &MessageMeta,
) -> Result<Message<E>, Error> {
    let path = path.join(format!("{}.ssz_snappy", message_meta.message));
    match topic {
        Topic::BeaconBlock => decode_block(&path, &testing_spec::<E>(fork_name))
            .map(Arc::new)
            .map(Message::BeaconBlock),
        Topic::BeaconAttestation => {
            decode_attestation_message(&path, fork_name).map(Message::BeaconAttestation)
        }
        Topic::BeaconAggregateAndProof => decode_signed_aggregate_and_proof(&path, fork_name)
            .map(Message::BeaconAggregateAndProof),
        Topic::ProposerSlashing => ssz_decode_file(&path).map(Message::ProposerSlashing),
        Topic::AttesterSlashing => {
            decode_attester_slashing(&path, fork_name).map(Message::AttesterSlashing)
        }
        Topic::VoluntaryExit => ssz_decode_file(&path).map(Message::VoluntaryExit),
        Topic::SyncCommitteeContributionAndProof => {
            ssz_decode_file(&path).map(Message::SyncCommitteeContributionAndProof)
        }
        Topic::SyncCommittee => ssz_decode_file(&path).map(Message::SyncCommittee),
        Topic::BlsToExecutionChange => ssz_decode_file(&path).map(Message::BlsToExecutionChange),
    }
}

fn decode_attestation_message<E: EthSpec>(
    path: &Path,
    fork_name: ForkName,
) -> Result<AttestationMessage<E>, Error> {
    let bytes = snappy_decode_file(path)?;
    if fork_name.electra_enabled()
        && let Ok(single_attestation) = SingleAttestation::from_ssz_bytes(&bytes)
    {
        return Ok(AttestationMessage::Single(single_attestation));
    }

    if fork_name.electra_enabled() {
        AttestationElectra::from_ssz_bytes(&bytes)
            .map(|attestation| AttestationMessage::Attestation(Attestation::Electra(attestation)))
            .map_err(|e| {
                Error::FailedToParseTest(format!(
                    "Unable to parse SSZ at {}: {:?}",
                    path.display(),
                    e
                ))
            })
    } else {
        AttestationBase::from_ssz_bytes(&bytes)
            .map(|attestation| AttestationMessage::Attestation(Attestation::Base(attestation)))
            .map_err(|e| {
                Error::FailedToParseTest(format!(
                    "Unable to parse SSZ at {}: {:?}",
                    path.display(),
                    e
                ))
            })
    }
}

fn decode_signed_aggregate_and_proof<E: EthSpec>(
    path: &Path,
    fork_name: ForkName,
) -> Result<SignedAggregateAndProof<E>, Error> {
    if fork_name.electra_enabled() {
        ssz_decode_file(path).map(SignedAggregateAndProof::Electra)
    } else {
        ssz_decode_file(path).map(SignedAggregateAndProof::Base)
    }
}

fn decode_attester_slashing<E: EthSpec>(
    path: &Path,
    fork_name: ForkName,
) -> Result<AttesterSlashing<E>, Error> {
    if fork_name.electra_enabled() {
        ssz_decode_file(path).map(AttesterSlashing::Electra)
    } else {
        ssz_decode_file(path).map(AttesterSlashing::Base)
    }
}

struct GossipValidationTester<E: EthSpec> {
    harness: BeaconChainHarness<EphemeralHarnessType<E>>,
    genesis_time: u64,
    failed_block_roots: Mutex<HashSet<Hash256>>,
}

impl<E: EthSpec> GossipValidationTester<E> {
    fn new(case: &GossipValidation<E>, spec: types::ChainSpec) -> Result<Self, Error> {
        let genesis_time = case.state.genesis_time();
        let mut state = case.state.clone();

        if state.slot() != spec.genesis_slot {
            return Err(Error::FailedToParseTest(format!(
                "gossip_validation currently supports genesis states only, got state slot {}",
                state.slot()
            )));
        }

        initialize_progressive_balances_cache(&mut state, &spec).map_err(|e| {
            Error::FailedToParseTest(format!("failed to update progressive balances: {e:?}"))
        })?;

        let mut chain_config = ChainConfig {
            archive: true,
            ..ChainConfig::default()
        };
        chain_config.invalid_block_roots.extend(
            case.blocks
                .iter()
                .filter(|block| block.meta.failed)
                .map(|block| block.block.canonical_root()),
        );

        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .spec(Arc::new(spec.clone()))
            .keypairs(vec![])
            .chain_config(chain_config)
            .genesis_state_ephemeral_store(state)
            .mock_execution_layer()
            .recalculate_fork_times_with_genesis(genesis_time)
            .node_custody_type(NodeCustodyType::Supernode)
            .mock_execution_layer_all_payloads_valid()
            .build();

        harness
            .mock_execution_layer
            .as_ref()
            .expect("mock execution layer exists")
            .server
            .drop_all_blocks();

        let tester = Self {
            harness,
            genesis_time,
            failed_block_roots: Mutex::new(
                case.blocks
                    .iter()
                    .filter(|block| block.meta.failed)
                    .map(|block| block.block.canonical_root())
                    .collect(),
            ),
        };

        for preloaded_block in &case.blocks {
            tester.process_preloaded_block(preloaded_block)?;
        }
        tester.mock_execution_layer().server.all_payloads_valid();

        if let Some(meta) = case.meta.finalized_checkpoint.as_ref() {
            tester.apply_finalized_checkpoint_override(case, meta)?;
        }

        Ok(tester)
    }

    fn block_on_dangerous<F: Future>(&self, future: F) -> Result<F::Output, Error> {
        self.harness
            .chain
            .task_executor
            .clone()
            .block_on_dangerous(future, "ef_tests_gossip_validation")
            .ok_or_else(|| Error::InternalError("runtime shutdown".into()))
    }

    fn set_time_ms(&self, current_time_ms: u64) -> Result<(), Error> {
        let current_time = Duration::from_secs(self.genesis_time)
            .checked_add(Duration::from_millis(current_time_ms))
            .ok_or_else(|| Error::FailedToParseTest("current time overflows Duration".into()))?;
        self.harness.chain.slot_clock.set_current_time(current_time);

        let slot = self
            .harness
            .chain
            .slot()
            .map_err(|e| Error::InternalError(format!("unable to read slot: {e:?}")))?;
        self.harness
            .chain
            .canonical_head
            .fork_choice_write_lock()
            .update_time(slot)
            .map(|_| ())
            .map_err(|e| Error::InternalError(format!("unable to update fork choice time: {e:?}")))
    }

    fn validate_message(
        &self,
        message: &Message<E>,
        subnet_id: Option<u64>,
        fork_name: ForkName,
    ) -> Result<Expected, Error> {
        match message {
            Message::BeaconBlock(block) => self.validate_block(block.clone()),
            Message::BeaconAttestation(attestation) => {
                self.validate_attestation(attestation, subnet_id, fork_name)
            }
            Message::BeaconAggregateAndProof(aggregate) => self.validate_aggregate(aggregate),
            Message::ProposerSlashing(slashing) => {
                self.validate_proposer_slashing(slashing.clone())
            }
            Message::AttesterSlashing(slashing) => {
                self.validate_attester_slashing(slashing.clone())
            }
            Message::VoluntaryExit(exit) => self.validate_voluntary_exit(exit.clone()),
            Message::SyncCommitteeContributionAndProof(contribution) => {
                self.validate_sync_contribution(contribution.clone())
            }
            Message::SyncCommittee(message) => self.validate_sync_committee_message(
                message.clone(),
                subnet_id.ok_or_else(|| {
                    Error::FailedToParseTest("sync_committee message requires subnet_id".into())
                })?,
            ),
            Message::BlsToExecutionChange(change) => {
                self.validate_bls_to_execution_change(change.clone())
            }
        }
    }

    fn validate_block(&self, block: Arc<SignedBeaconBlock<E>>) -> Result<Expected, Error> {
        if self.is_failed_parent(&block) {
            self.record_failed_block(block.canonical_root());
            return Ok(Expected::Reject);
        }

        let block_root = block.canonical_root();
        let result =
            self.block_on_dangerous(self.harness.chain.clone().verify_block_for_gossip(block))?;
        match result {
            Ok(verified_block) => {
                self.import_verified_block(verified_block)?;
                Ok(Expected::Valid)
            }
            Err(error) => {
                let result = classify_block_error(&error);
                if result == Expected::Reject {
                    self.record_failed_block(block_root);
                }
                Ok(result)
            }
        }
    }

    fn validate_attestation(
        &self,
        attestation: &AttestationMessage<E>,
        subnet_id: Option<u64>,
        fork_name: ForkName,
    ) -> Result<Expected, Error> {
        let single_attestation = match attestation {
            AttestationMessage::Single(single_attestation) => single_attestation.clone(),
            AttestationMessage::Attestation(attestation) => {
                self.attestation_to_single(attestation, fork_name)?
            }
        };
        let subnet_id = subnet_id.map(SubnetId::new);
        match self
            .harness
            .chain
            .verify_unaggregated_attestation_for_gossip(&single_attestation, subnet_id)
        {
            Ok(verified_attestation) => {
                let _ = self
                    .harness
                    .chain
                    .apply_attestation_to_fork_choice(&verified_attestation);
                let _ = self
                    .harness
                    .chain
                    .add_to_naive_aggregation_pool(&verified_attestation);
                Ok(Expected::Valid)
            }
            Err(error) => Ok(classify_attestation_error(&error)),
        }
    }

    fn validate_aggregate(
        &self,
        aggregate: &SignedAggregateAndProof<E>,
    ) -> Result<Expected, Error> {
        match self
            .harness
            .chain
            .verify_aggregated_attestation_for_gossip(aggregate)
        {
            Ok(verified_aggregate) => {
                let _ = self
                    .harness
                    .chain
                    .apply_attestation_to_fork_choice(&verified_aggregate);
                let _ = self
                    .harness
                    .chain
                    .add_to_block_inclusion_pool(verified_aggregate);
                Ok(Expected::Valid)
            }
            Err(error) => Ok(classify_attestation_error(&error)),
        }
    }

    fn validate_sync_committee_message(
        &self,
        message: SyncCommitteeMessage,
        subnet_id: u64,
    ) -> Result<Expected, Error> {
        match self
            .harness
            .chain
            .verify_sync_committee_message_for_gossip(message, SyncSubnetId::new(subnet_id))
        {
            Ok(verified_message) => {
                let _ = self
                    .harness
                    .chain
                    .add_to_naive_sync_aggregation_pool(verified_message);
                Ok(Expected::Valid)
            }
            Err(error) => Ok(classify_sync_committee_error(&error)),
        }
    }

    fn validate_sync_contribution(
        &self,
        contribution: SignedContributionAndProof<E>,
    ) -> Result<Expected, Error> {
        match self
            .harness
            .chain
            .verify_sync_contribution_for_gossip(contribution)
        {
            Ok(verified_contribution) => {
                let _ = self
                    .harness
                    .chain
                    .add_contribution_to_block_inclusion_pool(verified_contribution);
                Ok(Expected::Valid)
            }
            Err(error) => Ok(classify_sync_committee_error(&error)),
        }
    }

    fn validate_voluntary_exit(&self, exit: SignedVoluntaryExit) -> Result<Expected, Error> {
        match self.harness.chain.verify_voluntary_exit_for_gossip(exit) {
            Ok(ObservationOutcome::New(exit)) => {
                self.harness.chain.import_voluntary_exit(exit);
                Ok(Expected::Valid)
            }
            Ok(ObservationOutcome::AlreadyKnown) | Err(_) => Ok(Expected::Ignore),
        }
    }

    fn validate_proposer_slashing(&self, slashing: ProposerSlashing) -> Result<Expected, Error> {
        match self
            .harness
            .chain
            .verify_proposer_slashing_for_gossip(slashing)
        {
            Ok(ObservationOutcome::New(slashing)) => {
                self.harness.chain.import_proposer_slashing(slashing);
                Ok(Expected::Valid)
            }
            Ok(ObservationOutcome::AlreadyKnown) | Err(_) => Ok(Expected::Ignore),
        }
    }

    fn validate_attester_slashing(&self, slashing: AttesterSlashing<E>) -> Result<Expected, Error> {
        match self
            .harness
            .chain
            .verify_attester_slashing_for_gossip(slashing)
        {
            Ok(ObservationOutcome::New(slashing)) => {
                self.harness.chain.import_attester_slashing(slashing);
                Ok(Expected::Valid)
            }
            Ok(ObservationOutcome::AlreadyKnown) | Err(_) => Ok(Expected::Ignore),
        }
    }

    fn validate_bls_to_execution_change(
        &self,
        change: SignedBlsToExecutionChange,
    ) -> Result<Expected, Error> {
        match self
            .harness
            .chain
            .verify_bls_to_execution_change_for_gossip(change)
        {
            Ok(ObservationOutcome::New(change)) => {
                self.harness
                    .chain
                    .import_bls_to_execution_change(change, ReceivedPreCapella::No);
                Ok(Expected::Valid)
            }
            Ok(ObservationOutcome::AlreadyKnown) => Ok(Expected::Ignore),
            Err(BeaconChainError::BlsToExecutionPriorToCapella) => Ok(Expected::Ignore),
            Err(_) => Ok(Expected::Reject),
        }
    }

    fn attestation_to_single(
        &self,
        attestation: &Attestation<E>,
        fork_name: ForkName,
    ) -> Result<SingleAttestation, Error> {
        let aggregation_bits = attestation.get_aggregation_bits();
        if aggregation_bits.len() != 1 {
            return Err(Error::FailedToParseTest(format!(
                "beacon_attestation must be unaggregated, got {} aggregation bits",
                aggregation_bits.len()
            )));
        }

        let committee_index = attestation
            .committee_index()
            .ok_or_else(|| Error::FailedToParseTest("attestation has no committee index".into()))?;
        let aggregation_bit = aggregation_bits[0] as usize;
        let committee = self
            .harness
            .chain
            .with_committee_cache(
                attestation.data().target.root,
                attestation.data().target.epoch,
                |committee_cache, _| {
                    committee_cache
                        .get_beacon_committee(attestation.data().slot, committee_index)
                        .map(|committee| committee.committee.to_vec())
                        .ok_or_else(|| BeaconChainError::NoStateForAttestation {
                            beacon_block_root: attestation.data().beacon_block_root,
                        })
                },
            )
            .map_err(|e| {
                Error::InternalError(format!("unable to load attestation committee: {e:?}"))
            })?;
        let attester_index = committee.get(aggregation_bit).copied().ok_or_else(|| {
            Error::FailedToParseTest(format!(
                "aggregation bit {aggregation_bit} is outside committee length {}",
                committee.len()
            ))
        })?;

        let single_attestation = attestation
            .to_single_attestation_with_attester_index(attester_index as u64)
            .map_err(|e| {
                Error::FailedToParseTest(format!(
                    "unable to convert {fork_name:?} attestation to SingleAttestation: {e:?}"
                ))
            })?;
        Ok(single_attestation)
    }

    fn import_block(
        &self,
        block: SignedBeaconBlock<E>,
        source: BlockImportSource,
    ) -> Result<(), Error> {
        let block = Arc::new(block);
        let block_root = block.canonical_root();
        let result = self.block_on_dangerous(self.harness.chain.process_block(
            block_root,
            LookupBlock::new(block),
            NotifyExecutionLayer::Yes,
            source,
            || Ok(()),
        ))?;
        expect_block_imported(block_root, result)
    }

    fn import_verified_block(
        &self,
        block: beacon_chain::GossipVerifiedBlock<EphemeralHarnessType<E>>,
    ) -> Result<(), Error> {
        let block_root = block.block_root();
        let result = self.block_on_dangerous(self.harness.chain.process_block(
            block_root,
            block,
            NotifyExecutionLayer::Yes,
            BlockImportSource::Gossip,
            || Ok(()),
        ))?;
        expect_block_imported(block_root, result)
    }

    fn process_preloaded_block(&self, preloaded_block: &PreloadedBlock<E>) -> Result<(), Error> {
        let block_root = preloaded_block.block.canonical_root();
        if preloaded_block.meta.failed || self.is_failed_parent(&preloaded_block.block) {
            self.record_failed_block(block_root);
            return Ok(());
        }

        match preloaded_block.meta.payload_status {
            Some(PayloadStatus::NotValidated) => self
                .mock_execution_layer()
                .server
                .all_payloads_syncing(true),
            Some(PayloadStatus::Invalidated) => self
                .mock_execution_layer()
                .server
                .all_payloads_syncing(true),
            Some(PayloadStatus::Valid) | None => {
                self.mock_execution_layer().server.all_payloads_valid()
            }
        }

        self.import_block(preloaded_block.block.clone(), BlockImportSource::Lookup)?;

        if preloaded_block.meta.payload_status == Some(PayloadStatus::Invalidated) {
            self.block_on_dangerous(
                self.harness
                    .chain
                    .clone()
                    .process_invalid_execution_payload(&InvalidationOperation::InvalidateOne {
                        block_root,
                    }),
            )?
            .map_err(|e| {
                Error::InternalError(format!(
                    "failed to invalidate preloaded block {block_root:?}: {e:?}"
                ))
            })?;
        }

        Ok(())
    }

    fn mock_execution_layer(&self) -> &execution_layer::test_utils::MockExecutionLayer<E> {
        self.harness
            .mock_execution_layer
            .as_ref()
            .expect("mock execution layer exists")
    }

    fn is_failed_parent(&self, block: &SignedBeaconBlock<E>) -> bool {
        self.failed_block_roots
            .lock()
            .expect("failed block roots lock poisoned")
            .contains(&block.parent_root())
    }

    fn record_failed_block(&self, block_root: Hash256) {
        self.failed_block_roots
            .lock()
            .expect("failed block roots lock poisoned")
            .insert(block_root);
    }

    /// Constrained `meta.finalized_checkpoint` support.
    ///
    /// Resolves the override checkpoint (`root` xor `block`) and applies it to
    /// fork choice when its root is genesis or one of the preloaded blocks.
    /// Non-genesis anchor states and unknown override roots are explicitly
    /// unsupported. See https://github.com/sigp/lighthouse/issues/9232.
    ///
    /// EF semantics initialise `finalized_checkpoint` *before* importing
    /// preloaded blocks; this handler imports first and then overrides, so we
    /// also have to reconcile any finality that the imports advanced through
    /// the normal `on_block` path:
    ///
    /// * `current == requested` – no-op.
    /// * `current.epoch > requested.epoch` – tolerated only when the current
    ///   finalized root is a strict descendant of the requested root (same
    ///   end-state); otherwise this is a hard conflict.
    /// * `current.epoch == requested.epoch && current.root != requested.root`
    ///   – conflict, not supported.
    /// * `current.epoch < requested.epoch` – apply the override forward, but
    ///   only when the requested root descends from the current finalized
    ///   root. Forward jumps that would silently switch finality across
    ///   branches (e.g. preloaded imports finalised branch A while the
    ///   override points at a higher-epoch root on branch B) are rejected as
    ///   conflicts.
    fn apply_finalized_checkpoint_override(
        &self,
        case: &GossipValidation<E>,
        meta: &FinalizedCheckpointMeta,
    ) -> Result<(), Error> {
        let checkpoint = resolve_finalized_checkpoint(case, meta)?;

        {
            let fork_choice = self.harness.chain.canonical_head.fork_choice_read_lock();
            let current = fork_choice.finalized_checkpoint();

            if current == checkpoint {
                return Ok(());
            }

            if current.epoch > checkpoint.epoch {
                if fork_choice.is_descendant(checkpoint.root, current.root) {
                    return Ok(());
                }
                return Err(Error::FailedToParseTest(format!(
                    "preloaded-block imports advanced finality to {current:?}, which conflicts \
                     with meta.finalized_checkpoint override {checkpoint:?} (current is not a \
                     descendant of the override root)"
                )));
            }

            if current.epoch == checkpoint.epoch && current.root != checkpoint.root {
                return Err(Error::FailedToParseTest(format!(
                    "fork-choice finality {current:?} conflicts with meta.finalized_checkpoint \
                     override {checkpoint:?} (same epoch, different root)"
                )));
            }

            // current.epoch < checkpoint.epoch — moving finality forward.
            // Refuse to silently jump across branches: the override root must
            // be a descendant of the currently finalized root.
            if !fork_choice.is_descendant(current.root, checkpoint.root) {
                return Err(Error::FailedToParseTest(format!(
                    "meta.finalized_checkpoint override {checkpoint:?} is not a descendant of \
                     the current fork-choice finality {current:?}; refusing to switch finality \
                     across branches"
                )));
            }
        }

        let (justified_state_root, block_slot) =
            self.lookup_state_root_and_slot_for_root(case, checkpoint.root)?;

        let boundary_slot = checkpoint.epoch.start_slot(E::slots_per_epoch());
        if block_slot != boundary_slot {
            return Err(Error::FailedToParseTest(format!(
                "finalized_checkpoint {checkpoint:?} references a block at slot {block_slot}, \
                 which is not the epoch-boundary slot {boundary_slot}; skipped-boundary \
                 checkpoints are unsupported (the boundary state root would differ from the \
                 referenced block's state root)"
            )));
        }

        self.harness
            .chain
            .canonical_head
            .fork_choice_write_lock()
            .override_finalized_checkpoint_for_testing(checkpoint, justified_state_root)
            .map_err(|e| match e {
                ::fork_choice::Error::MissingProtoArrayBlock(root) => Error::FailedToParseTest(
                    format!("finalized_checkpoint root {root:?} is not in fork choice"),
                ),
                other => Error::InternalError(format!(
                    "failed to apply finalized_checkpoint override: {other:?}"
                )),
            })
    }

    fn lookup_state_root_and_slot_for_root(
        &self,
        case: &GossipValidation<E>,
        root: Hash256,
    ) -> Result<(Hash256, Slot), Error> {
        if root == self.harness.chain.genesis_block_root {
            return Ok((self.harness.chain.genesis_state_root, Slot::new(0)));
        }

        case.blocks
            .iter()
            .find(|preloaded| preloaded.block.canonical_root() == root)
            .map(|preloaded| (preloaded.block.state_root(), preloaded.block.slot()))
            .ok_or_else(|| {
                Error::FailedToParseTest(format!(
                    "finalized_checkpoint root {root:?} is neither genesis nor a preloaded block"
                ))
            })
    }
}

fn resolve_finalized_checkpoint<E: EthSpec>(
    case: &GossipValidation<E>,
    meta: &FinalizedCheckpointMeta,
) -> Result<Checkpoint, Error> {
    let root = match (meta.root, meta.block.as_deref()) {
        (Some(root), None) => root,
        (None, Some(block_name)) => case
            .blocks
            .iter()
            .find(|preloaded| preloaded.meta.block == block_name)
            .map(|preloaded| preloaded.block.canonical_root())
            .ok_or_else(|| {
                Error::FailedToParseTest(format!(
                    "finalized_checkpoint.block {block_name:?} not found in preloaded blocks"
                ))
            })?,
        (Some(_), Some(_)) => {
            return Err(Error::FailedToParseTest(
                "finalized_checkpoint must set exactly one of `root` or `block`".into(),
            ));
        }
        (None, None) => {
            return Err(Error::FailedToParseTest(
                "finalized_checkpoint must set exactly one of `root` or `block`".into(),
            ));
        }
    };

    Ok(Checkpoint {
        epoch: Epoch::new(meta.epoch),
        root,
    })
}

fn expect_block_imported(
    block_root: Hash256,
    result: Result<AvailabilityProcessingStatus, BlockError>,
) -> Result<(), Error> {
    match result {
        Ok(AvailabilityProcessingStatus::Imported(_)) => Ok(()),
        Ok(status) => Err(Error::InternalError(format!(
            "block {block_root:?} was not imported: {status:?}"
        ))),
        Err(error) => Err(Error::InternalError(format!(
            "failed to import block {block_root:?}: {error:?}"
        ))),
    }
}

fn classify_block_error(error: &BlockError) -> Expected {
    match error {
        BlockError::DuplicateFullyImported(_)
        | BlockError::DuplicateImportStatusUnknown(_)
        | BlockError::ParentUnknown { .. }
        | BlockError::BeaconChainError(_)
        | BlockError::FutureSlot { .. }
        | BlockError::WouldRevertFinalizedSlot { .. }
        | BlockError::NotFinalizedDescendant { .. } => Expected::Ignore,
        BlockError::ExecutionPayloadError(error) if !error.penalize_peer() => Expected::Ignore,
        BlockError::AvailabilityCheck(_)
        | BlockError::InternalError(_)
        | BlockError::BlobNotRequired(_) => Expected::Ignore,
        BlockError::Slashable => Expected::Ignore,
        _ => Expected::Reject,
    }
}

fn classify_attestation_error(error: &AttestationError) -> Expected {
    match error {
        AttestationError::FutureSlot { .. }
        | AttestationError::PastSlot { .. }
        | AttestationError::AttestationSupersetKnown(_)
        | AttestationError::AggregatorAlreadyKnown(_)
        | AttestationError::PriorAttestationKnown { .. }
        | AttestationError::UnknownHeadBlock { .. }
        | AttestationError::BeaconChainError(_) => Expected::Ignore,
        _ => Expected::Reject,
    }
}

fn classify_sync_committee_error(error: &SyncCommitteeError) -> Expected {
    match error {
        SyncCommitteeError::FutureSlot { .. }
        | SyncCommitteeError::PastSlot { .. }
        | SyncCommitteeError::SyncContributionSupersetKnown(_)
        | SyncCommitteeError::AggregatorAlreadyKnown(_)
        | SyncCommitteeError::PriorSyncCommitteeMessageKnown { .. }
        | SyncCommitteeError::PriorSyncContributionMessageKnown { .. }
        | SyncCommitteeError::BeaconChainError(_)
        | SyncCommitteeError::BeaconStateError(_)
        | SyncCommitteeError::ContributionError(_)
        | SyncCommitteeError::SyncCommitteeError(_)
        | SyncCommitteeError::ArithError(_) => Expected::Ignore,
        _ => Expected::Reject,
    }
}
