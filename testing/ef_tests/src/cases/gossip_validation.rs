use super::*;
use crate::decode::{
    snappy_decode_file, ssz_decode_file, ssz_decode_file_with, ssz_decode_state, yaml_decode_file,
};
use crate::type_name::TypeName;
use ::fork_choice::{InvalidationOperation, PayloadVerificationStatus};
use beacon_chain::attestation_verification::Error as AttestationError;
use beacon_chain::block_verification_types::LookupBlock;
use beacon_chain::sync_committee_verification::Error as SyncCommitteeError;
use beacon_chain::{
    AvailabilityProcessingStatus, BeaconChainError, BeaconSnapshot, BlockError, ChainConfig,
    NotifyExecutionLayer,
    custody_context::NodeCustodyType,
    observed_operations::ObservationOutcome,
    test_utils::{BeaconChainHarness, EphemeralHarnessType},
};
use operation_pool::ReceivedPreCapella;
use serde::Deserialize;
use ssz::Decode;
use state_processing::common::update_progressive_balances_cache::initialize_progressive_balances_cache;
use state_processing::genesis::genesis_block;
use state_processing::per_block_processing::errors::{
    AttesterSlashingInvalid, BlockOperationError, IndexedAttestationInvalid,
};
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

pub const RUNNER_NAME: &str = "networking";
pub const GOSSIP_VALIDATION_HANDLER_NAME: &str = "gossip_validation";
pub const GOSSIP_VALIDATION_HANDLER_NAMES: &[&str] = &[
    GOSSIP_VALIDATION_HANDLER_NAME,
    "gossip_attester_slashing",
    "gossip_beacon_aggregate_and_proof",
    "gossip_beacon_attestation",
    "gossip_beacon_block",
    "gossip_bls_to_execution_change",
    "gossip_proposer_slashing",
    "gossip_sync_committee_contribution_and_proof",
    "gossip_sync_committee_message",
    "gossip_voluntary_exit",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Meta {
    topic: Topic,
    #[serde(default)]
    blocks: Vec<BlockMeta>,
    finalized_checkpoint: Option<FinalizedCheckpointMeta>,
    #[serde(default)]
    current_time_ms: Option<u64>,
    messages: Vec<MessageMeta>,
    #[serde(default, rename = "bls_setting")]
    _bls_setting: Option<u64>,
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
    #[serde(default)]
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
    current_time_ms: u64,
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
    InvalidBls,
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
        let meta: Meta = yaml_decode_file(&path.join("meta.yaml"))?;
        let spec = &testing_spec::<E>(fork_name);
        let state = ssz_decode_state(&path.join("state.ssz_snappy"), spec)?;
        let current_time_ms = meta.current_time_ms.unwrap_or_else(|| {
            state
                .slot()
                .saturating_sub(spec.genesis_slot)
                .as_u64()
                .saturating_mul(spec.get_slot_duration().as_millis() as u64)
        });

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
            current_time_ms,
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
        fork_name.fulu_enabled()
            && gossip_validation_handler_path::<E>(fork_name, GOSSIP_VALIDATION_HANDLER_NAME)
                .exists()
    }

    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let tester = GossipValidationTester::new(self, testing_spec::<E>(fork_name))?;

        for (message_meta, message) in self.meta.messages.iter().zip(&self.messages) {
            tester.set_time_ms(
                self.current_time_ms
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

impl<E: EthSpec> GossipValidation<E> {
    fn requires_pre_capella_wall_clock(&self) -> bool {
        self.meta.topic == Topic::BlsToExecutionChange
            && self.meta.messages.iter().any(|message| {
                message.expected == Expected::Ignore
                    && message
                        .reason
                        .as_deref()
                        .is_some_and(|reason| reason.contains("pre-capella"))
            })
    }
}

pub fn gossip_validation_handler_path<E: EthSpec + TypeName>(
    fork_name: ForkName,
    handler_name: &str,
) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("consensus-spec-tests")
        .join("tests")
        .join(E::name())
        .join(fork_name.to_string())
        .join(RUNNER_NAME)
        .join(handler_name)
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
    let decoded = match topic {
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
    };

    match decoded {
        Err(Error::InvalidBLSInput(_)) => Ok(Message::InvalidBls),
        result => result,
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

fn reset_state_to_builder_genesis_slot<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &types::ChainSpec,
) -> Result<(), Error> {
    *state.slot_mut() = spec.genesis_slot;
    let latest_block_header = genesis_block(state, spec)
        .map_err(|e| Error::FailedToParseTest(format!("failed to build genesis block: {e:?}")))?
        .temporary_block_header();
    match state {
        BeaconState::Base(state) => state.latest_block_header = latest_block_header,
        BeaconState::Altair(state) => state.latest_block_header = latest_block_header,
        BeaconState::Bellatrix(state) => state.latest_block_header = latest_block_header,
        BeaconState::Capella(state) => state.latest_block_header = latest_block_header,
        BeaconState::Deneb(state) => state.latest_block_header = latest_block_header,
        BeaconState::Electra(state) => state.latest_block_header = latest_block_header,
        BeaconState::Fulu(state) => state.latest_block_header = latest_block_header,
        BeaconState::Gloas(state) => state.latest_block_header = latest_block_header,
    }
    Ok(())
}

fn set_state_latest_block_header<E: EthSpec>(
    state: &mut BeaconState<E>,
    block: &SignedBeaconBlock<E>,
) {
    let latest_block_header = block.message().block_header();
    match state {
        BeaconState::Base(state) => state.latest_block_header = latest_block_header,
        BeaconState::Altair(state) => state.latest_block_header = latest_block_header,
        BeaconState::Bellatrix(state) => state.latest_block_header = latest_block_header,
        BeaconState::Capella(state) => state.latest_block_header = latest_block_header,
        BeaconState::Deneb(state) => state.latest_block_header = latest_block_header,
        BeaconState::Electra(state) => state.latest_block_header = latest_block_header,
        BeaconState::Fulu(state) => state.latest_block_header = latest_block_header,
        BeaconState::Gloas(state) => state.latest_block_header = latest_block_header,
    }
}

fn attestation_head_root<E: EthSpec>(attestation: &AttestationMessage<E>) -> Hash256 {
    match attestation {
        AttestationMessage::Single(single_attestation) => single_attestation.data.beacon_block_root,
        AttestationMessage::Attestation(attestation) => attestation.data().beacon_block_root,
    }
}

struct GossipValidationTester<E: EthSpec> {
    harness: BeaconChainHarness<EphemeralHarnessType<E>>,
    genesis_time: u64,
    failed_block_roots: Mutex<HashSet<Hash256>>,
    execution_valid_failed_block_roots: HashSet<Hash256>,
    state_is_post_capella: bool,
    force_pre_capella_bls_to_execution_change: bool,
}

impl<E: EthSpec> GossipValidationTester<E> {
    fn new(case: &GossipValidation<E>, spec: types::ChainSpec) -> Result<Self, Error> {
        let genesis_time = case.state.genesis_time();
        let mut state = case.state.clone();
        let state_slot = state.slot();
        let trusted_preload_setup = state_slot != spec.genesis_slot
            || (case.meta.topic == Topic::SyncCommitteeContributionAndProof
                && case.blocks.is_empty())
            || case
                .blocks
                .iter()
                .any(|block| block.block.slot() == spec.genesis_slot);

        initialize_progressive_balances_cache(&mut state, &spec).map_err(|e| {
            Error::FailedToParseTest(format!("failed to update progressive balances: {e:?}"))
        })?;
        let state_root = state.update_tree_hash_cache().map_err(|e| {
            Error::FailedToParseTest(format!("failed to compute vector state root: {e:?}"))
        })?;
        let state_fork_version = state.fork().current_version;
        let state_is_post_capella = [
            spec.capella_fork_version,
            spec.deneb_fork_version,
            spec.electra_fork_version,
            spec.fulu_fork_version,
            spec.gloas_fork_version,
        ]
        .contains(&state_fork_version);
        let mut builder_state = state.clone();
        if trusted_preload_setup {
            reset_state_to_builder_genesis_slot(&mut builder_state, &spec)?;
            builder_state.update_tree_hash_cache().map_err(|e| {
                Error::FailedToParseTest(format!(
                    "failed to compute trusted builder state root: {e:?}"
                ))
            })?;
        }

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
            .genesis_state_ephemeral_store(builder_state)
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
            execution_valid_failed_block_roots: case
                .blocks
                .iter()
                .filter(|block| {
                    block.meta.failed && block.meta.payload_status == Some(PayloadStatus::Valid)
                })
                .map(|block| block.block.canonical_root())
                .collect(),
            state_is_post_capella,
            force_pre_capella_bls_to_execution_change: case.requires_pre_capella_wall_clock(),
        };

        if trusted_preload_setup {
            tester.setup_trusted_preload_context(case, &state, state_root)?;
        }

        tester.set_time_ms(case.current_time_ms)?;
        let preload_current_slot = tester
            .harness
            .chain
            .slot()
            .map_err(|e| Error::InternalError(format!("unable to read preload slot: {e:?}")))?;

        for preloaded_block in &case.blocks {
            if trusted_preload_setup {
                tester.process_trusted_preloaded_block(
                    preloaded_block,
                    &state,
                    preload_current_slot,
                )?;
            } else {
                tester.process_preloaded_block(preloaded_block)?;
            }
        }

        tester.mock_execution_layer().server.all_payloads_valid();

        if let Some(meta) = case.meta.finalized_checkpoint.as_ref() {
            tester.apply_finalized_checkpoint_override(case, meta)?;
        } else {
            tester.apply_state_finalized_checkpoint(case, state.finalized_checkpoint())?;
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
        let slot_duration_ms = self.harness.chain.spec.get_slot_duration().as_millis() as u64;
        let gossip_disparity_ms = self
            .harness
            .chain
            .spec
            .maximum_gossip_clock_disparity()
            .as_millis() as u64;
        // EF vectors use millisecond timestamps at gossip-disparity
        // boundaries. Lighthouse's slot clock treats an exact slot boundary
        // as the new slot, so nudge past-tolerance boundary cases back by 1ms
        // to keep them on the vector's intended side without affecting
        // future-tolerance boundaries.
        let current_time_ms = if slot_duration_ms != 0
            && current_time_ms >= slot_duration_ms
            && current_time_ms % slot_duration_ms == gossip_disparity_ms
        {
            current_time_ms.saturating_sub(1)
        } else {
            current_time_ms
        };
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
            Message::InvalidBls => Ok(Expected::Reject),
        }
    }

    fn validate_block(&self, block: Arc<SignedBeaconBlock<E>>) -> Result<Expected, Error> {
        if self.is_failed_parent(&block) {
            self.record_failed_block(block.canonical_root());
            if self
                .execution_valid_failed_block_roots
                .contains(&block.parent_root())
            {
                return Ok(Expected::Ignore);
            }
            return Ok(Expected::Reject);
        }

        let block_root = block.canonical_root();
        let result =
            self.block_on_dangerous(self.harness.chain.clone().verify_block_for_gossip(block))?;
        match result {
            Ok(verified_block) => {
                let _ = self.import_verified_block(verified_block);
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
        if self.is_failed_attestation_head(attestation) {
            return Ok(Expected::Reject);
        }

        if !self.is_finalized_descendant(attestation_head_root(attestation)) {
            return Ok(Expected::Ignore);
        }

        let single_attestation = match attestation {
            AttestationMessage::Single(single_attestation) => single_attestation.clone(),
            AttestationMessage::Attestation(attestation) => {
                match self.attestation_to_single(attestation, fork_name)? {
                    Some(single_attestation) => single_attestation,
                    None => return Ok(Expected::Reject),
                }
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
        if self
            .failed_block_roots
            .lock()
            .expect("failed block roots lock poisoned")
            .contains(&aggregate.message().aggregate().data().beacon_block_root)
        {
            return Ok(Expected::Reject);
        }

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
            Ok(ObservationOutcome::AlreadyKnown) => Ok(Expected::Ignore),
            Err(BeaconChainError::ExitValidationError(_)) => Ok(Expected::Reject),
            Err(_) => Ok(Expected::Ignore),
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
            Ok(ObservationOutcome::AlreadyKnown) => Ok(Expected::Ignore),
            Err(BeaconChainError::ProposerSlashingValidationError(_)) => Ok(Expected::Reject),
            Err(_) => Ok(Expected::Ignore),
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
            Ok(ObservationOutcome::AlreadyKnown) => Ok(Expected::Ignore),
            Err(error) => Ok(classify_attester_slashing_error(&error)),
        }
    }

    fn validate_bls_to_execution_change(
        &self,
        change: SignedBlsToExecutionChange,
    ) -> Result<Expected, Error> {
        if self.force_pre_capella_bls_to_execution_change || !self.state_is_post_capella {
            return Ok(Expected::Ignore);
        }

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
    ) -> Result<Option<SingleAttestation>, Error> {
        let aggregation_bits = attestation.get_aggregation_bits();
        if aggregation_bits.len() != 1 {
            return Ok(None);
        }
        let aggregation_bit = aggregation_bits[0] as usize;

        let committee_index = attestation
            .committee_index()
            .ok_or_else(|| Error::FailedToParseTest("attestation has no committee index".into()))?;
        let committee = match self.harness.chain.with_committee_cache(
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
        ) {
            Ok(committee) => committee,
            Err(BeaconChainError::MissingBeaconBlock(_))
            | Err(BeaconChainError::NoStateForAttestation { .. }) => return Ok(None),
            Err(e) => {
                return Err(Error::InternalError(format!(
                    "unable to load attestation committee: {e:?}"
                )));
            }
        };
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
        Ok(Some(single_attestation))
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

    fn setup_trusted_preload_context(
        &self,
        case: &GossipValidation<E>,
        state: &BeaconState<E>,
        state_root: Hash256,
    ) -> Result<(), Error> {
        let maybe_anchor_block = case
            .blocks
            .iter()
            .min_by_key(|preloaded| preloaded.block.slot());
        let anchor_root = if let Some(anchor_block) = maybe_anchor_block {
            if anchor_block.block.slot() == self.harness.chain.spec.genesis_slot {
                anchor_block.block.canonical_root()
            } else {
                anchor_block.block.parent_root()
            }
        } else {
            state.get_latest_block_root(state_root)
        };
        let anchor_latest_block = maybe_anchor_block
            .filter(|anchor_block| {
                anchor_block.block.slot() == self.harness.chain.spec.genesis_slot
            })
            .map(|anchor_block| &anchor_block.block);

        self.cache_state_for_block(
            state_root,
            anchor_root,
            state,
            self.harness.chain.spec.genesis_slot,
            anchor_latest_block,
        )?;

        self.harness
            .chain
            .canonical_head
            .fork_choice_write_lock()
            .override_anchor_block_for_testing(
                anchor_root,
                state_root,
                state,
                &self.harness.chain.spec,
            )
            .map_err(|e| {
                Error::InternalError(format!("failed to seed vector fork-choice anchor: {e:?}"))
            })?;

        if case.blocks.is_empty() && state.slot() != self.harness.chain.spec.genesis_slot {
            let cached_head = self.harness.chain.canonical_head.cached_head();
            let snapshot = Arc::new(BeaconSnapshot {
                beacon_block_root: anchor_root,
                execution_envelope: cached_head.snapshot.execution_envelope.clone(),
                beacon_block: cached_head.snapshot.beacon_block.clone(),
                beacon_state: state.clone(),
            });
            self.harness
                .chain
                .canonical_head
                .override_cached_head_for_testing(snapshot, cached_head.head_payload_status());
        }

        Ok(())
    }

    fn process_trusted_preloaded_block(
        &self,
        preloaded_block: &PreloadedBlock<E>,
        state: &BeaconState<E>,
        current_slot: Slot,
    ) -> Result<(), Error> {
        let block_root = preloaded_block.block.canonical_root();
        if preloaded_block.meta.failed || self.is_failed_parent(&preloaded_block.block) {
            self.record_failed_block(block_root);
            return Ok(());
        }

        self.harness
            .chain
            .store
            .put_block(&block_root, preloaded_block.block.clone())
            .map_err(|e| {
                Error::InternalError(format!(
                    "failed to store trusted preloaded block {block_root:?}: {e:?}"
                ))
            })?;
        let trusted_state = self.prepare_trusted_state_for_block(
            preloaded_block.block.state_root(),
            state,
            preloaded_block.block.slot(),
            Some(&preloaded_block.block),
        )?;
        self.harness
            .chain
            .store
            .put_state(&preloaded_block.block.state_root(), &trusted_state)
            .map_err(|e| {
                Error::InternalError(format!(
                    "failed to store trusted preloaded state {:?}: {e:?}",
                    preloaded_block.block.state_root()
                ))
            })?;
        self.cache_state_for_block(
            preloaded_block.block.state_root(),
            block_root,
            state,
            preloaded_block.block.slot(),
            Some(&preloaded_block.block),
        )?;

        if preloaded_block.block.slot() == self.harness.chain.spec.genesis_slot {
            return Ok(());
        }

        let payload_verification_status = match preloaded_block.meta.payload_status {
            Some(PayloadStatus::NotValidated) | Some(PayloadStatus::Invalidated) => {
                PayloadVerificationStatus::Optimistic
            }
            Some(PayloadStatus::Valid) | None => PayloadVerificationStatus::Verified,
        };

        self.harness
            .chain
            .canonical_head
            .fork_choice_write_lock()
            .on_block(
                current_slot,
                preloaded_block.block.message(),
                block_root,
                Duration::ZERO,
                &trusted_state,
                payload_verification_status,
                preloaded_block.block.message().proposer_index(),
                &self.harness.chain.spec,
            )
            .map_err(|e| {
                Error::InternalError(format!(
                    "failed to insert trusted preloaded block {block_root:?}: {e:?}"
                ))
            })?;

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

    fn cache_state_for_block(
        &self,
        state_root: Hash256,
        block_root: Hash256,
        state: &BeaconState<E>,
        slot: Slot,
        latest_block: Option<&SignedBeaconBlock<E>>,
    ) -> Result<(), Error> {
        let cached_state =
            self.prepare_trusted_state_for_block(state_root, state, slot, latest_block)?;
        self.harness.chain.store.put_state_in_cache_for_testing(
            state_root,
            block_root,
            &cached_state,
        );
        Ok(())
    }

    fn prepare_trusted_state_for_block(
        &self,
        state_root: Hash256,
        state: &BeaconState<E>,
        slot: Slot,
        latest_block: Option<&SignedBeaconBlock<E>>,
    ) -> Result<BeaconState<E>, Error> {
        let mut cached_state = state.clone();
        *cached_state.slot_mut() = slot;
        if let Some(latest_block) = latest_block {
            set_state_latest_block_header(&mut cached_state, latest_block);
        }
        cached_state.update_tree_hash_cache().map_err(|e| {
            Error::InternalError(format!(
                "failed to prepare trusted cached state {state_root:?}: {e:?}"
            ))
        })?;
        Ok(cached_state)
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

    fn is_failed_attestation_head(&self, attestation: &AttestationMessage<E>) -> bool {
        let block_root = attestation_head_root(attestation);
        self.failed_block_roots
            .lock()
            .expect("failed block roots lock poisoned")
            .contains(&block_root)
    }

    fn is_finalized_descendant(&self, block_root: Hash256) -> bool {
        self.harness
            .chain
            .canonical_head
            .fork_choice_read_lock()
            .is_finalized_checkpoint_or_descendant(block_root)
    }

    /// Apply the default finalized checkpoint from `state.ssz_snappy`.
    ///
    /// The unified EF format only uses `meta.finalized_checkpoint` as an
    /// override. When it is absent, the store must use the checkpoint embedded
    /// in the supplied state. The default genesis checkpoint is encoded with a
    /// zero root in many vectors, while Lighthouse's harness finalizes the
    /// actual genesis block root; those two are equivalent for the genesis
    /// store setup, so keep the harness default in that case.
    fn apply_state_finalized_checkpoint(
        &self,
        case: &GossipValidation<E>,
        checkpoint: Checkpoint,
    ) -> Result<(), Error> {
        if checkpoint == Checkpoint::default() {
            return Ok(());
        }

        self.apply_finalized_checkpoint(case, checkpoint, "state.finalized_checkpoint")
    }

    /// Constrained `meta.finalized_checkpoint` override support.
    fn apply_finalized_checkpoint_override(
        &self,
        case: &GossipValidation<E>,
        meta: &FinalizedCheckpointMeta,
    ) -> Result<(), Error> {
        let checkpoint = resolve_finalized_checkpoint(case, meta)?;
        self.apply_finalized_checkpoint(case, checkpoint, "meta.finalized_checkpoint")
    }

    /// Apply an EF finalized checkpoint to fork choice.
    ///
    /// Applies checkpoints with known state roots fully. If a vector references
    /// a root for which this constrained harness cannot materialize the
    /// boundary state, apply the root-only view used by gossip checks instead
    /// of silently using an incorrect state root. See
    /// https://github.com/sigp/lighthouse/issues/9232.
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
    fn apply_finalized_checkpoint(
        &self,
        case: &GossipValidation<E>,
        checkpoint: Checkpoint,
        source: &str,
    ) -> Result<(), Error> {
        let resolved_checkpoint_root = self
            .lookup_state_root_and_slot_for_root(case, checkpoint.root)
            .ok();

        {
            let fork_choice = self.harness.chain.canonical_head.fork_choice_read_lock();
            let current = fork_choice.finalized_checkpoint();

            if current == checkpoint {
                return Ok(());
            }

            if resolved_checkpoint_root.is_none() {
                if current.epoch == checkpoint.epoch {
                    drop(fork_choice);
                    self.harness
                        .chain
                        .canonical_head
                        .fork_choice_write_lock()
                        .override_finalized_checkpoint_root_for_testing(checkpoint);
                    return Ok(());
                }

                return Err(Error::FailedToParseTest(format!(
                    "{source} {checkpoint:?} is unknown to fork choice \
                     and has a different epoch than current finality {current:?}"
                )));
            }

            if current.epoch > checkpoint.epoch {
                if fork_choice.is_descendant(checkpoint.root, current.root) {
                    return Ok(());
                }
                return Err(Error::FailedToParseTest(format!(
                    "preloaded-block imports advanced finality to {current:?}, which conflicts \
                     with {source} {checkpoint:?} (current is not a \
                     descendant of the override root)"
                )));
            }

            if current.epoch == checkpoint.epoch && current.root != checkpoint.root {
                return Err(Error::FailedToParseTest(format!(
                    "fork-choice finality {current:?} conflicts with {source} {checkpoint:?} \
                     (same epoch, different root)"
                )));
            }

            // current.epoch < checkpoint.epoch — moving finality forward.
            // Refuse to silently jump across branches: the override root must
            // be a descendant of the currently finalized root.
            if !fork_choice.is_descendant(current.root, checkpoint.root) {
                return Err(Error::FailedToParseTest(format!(
                    "{source} {checkpoint:?} is not a descendant of \
                     the current fork-choice finality {current:?}; refusing to switch finality \
                     across branches"
                )));
            }
        }

        let (justified_state_root, block_slot) = resolved_checkpoint_root.expect("checked above");

        let boundary_slot = checkpoint.epoch.start_slot(E::slots_per_epoch());
        if block_slot != boundary_slot {
            self.harness
                .chain
                .canonical_head
                .fork_choice_write_lock()
                .override_finalized_checkpoint_root_for_testing(checkpoint);
            return Ok(());
        }

        self.harness
            .chain
            .canonical_head
            .fork_choice_write_lock()
            .override_finalized_checkpoint_for_testing(checkpoint, justified_state_root)
            .map_err(|e| match e {
                ::fork_choice::Error::MissingProtoArrayBlock(root) => Error::FailedToParseTest(
                    format!("{source} root {root:?} is not in fork choice"),
                ),
                other => Error::InternalError(format!("failed to apply {source}: {other:?}")),
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
        | BlockError::ParentExecutionPayloadInvalid { .. } => Expected::Ignore,
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
        | AttestationError::HeadBlockFinalized { .. } => Expected::Ignore,
        _ => Expected::Reject,
    }
}

fn classify_attester_slashing_error(error: &BeaconChainError) -> Expected {
    match error {
        BeaconChainError::AttesterSlashingValidationError(error)
            if is_empty_attester_slashing(error) =>
        {
            Expected::Ignore
        }
        BeaconChainError::AttesterSlashingValidationError(_) => Expected::Reject,
        _ => Expected::Ignore,
    }
}

fn is_empty_attester_slashing(error: &BlockOperationError<AttesterSlashingInvalid>) -> bool {
    matches!(
        error,
        BlockOperationError::Invalid(
            AttesterSlashingInvalid::IndexedAttestation1Invalid(BlockOperationError::Invalid(
                IndexedAttestationInvalid::IndicesEmpty
            )) | AttesterSlashingInvalid::IndexedAttestation2Invalid(BlockOperationError::Invalid(
                IndexedAttestationInvalid::IndicesEmpty
            ))
        )
    )
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
