use super::*;
use crate::bls_setting::BlsSetting;
use crate::decode::{ssz_decode_file, ssz_decode_file_with, ssz_decode_state, yaml_decode_file};
use crate::type_name::TypeName;
use ::fork_choice::InvalidationOperation;
use beacon_chain::block_verification_types::LookupBlock;
use beacon_chain::slot_clock::{SlotClock, TestingSlotClock};
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use beacon_chain::{BlockError, NotifyExecutionLayer};
use bls::Signature;
use execution_layer::{PayloadStatusV1, PayloadStatusV1Status};
use lighthouse_network::{Client, MessageAcceptance, MessageId, PeerId};
use network::{NetworkBeaconProcessor, NetworkMessage, ReprocessAllowance};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use types::{
    AttesterSlashing, BeaconBlock, BeaconState, BlobSchedule, BlockImportSource, ChainSpec,
    Checkpoint, EthSpec, ExecPayload, ForkName, Hash256, ProposerSlashing, SignedAggregateAndProof,
    SignedAggregateAndProofElectra, SignedBeaconBlock, SignedBlsToExecutionChange,
    SignedContributionAndProof, SignedVoluntaryExit, SingleAttestation, Slot, SubnetId,
    SyncCommitteeMessage, SyncSubnetId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExpectedOutcome {
    Valid,
    Ignore,
    Reject,
}

impl PartialEq<MessageAcceptance> for ExpectedOutcome {
    fn eq(&self, other: &MessageAcceptance) -> bool {
        matches!(
            (self, other),
            (Self::Valid, MessageAcceptance::Accept)
                | (Self::Ignore, MessageAcceptance::Ignore)
                | (Self::Reject, MessageAcceptance::Reject)
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Meta {
    topic: Topic,
    #[serde(default)]
    blocks: Vec<SetupBlock>,
    #[serde(default)]
    finalized_checkpoint: Option<FinalizedCheckpoint>,
    #[serde(default)]
    current_time_ms: Option<u64>,
    #[serde(default)]
    messages: Vec<MessageMeta>,
    #[serde(default)]
    bls_setting: Option<BlsSetting>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
struct CaseConfig {
    #[serde(default)]
    blob_schedule: Option<BlobSchedule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupBlock {
    block: String,
    #[serde(default)]
    failed: bool,
    #[serde(default)]
    payload_status: Option<PayloadStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum PayloadStatus {
    Valid,
    NotValidated,
    Invalidated,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum FinalizedCheckpoint {
    Root { epoch: u64, root: Hash256 },
    Block { epoch: u64, block: String },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageMeta {
    message: String,
    expected: ExpectedOutcome,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    subnet_id: Option<u64>,
    #[serde(default)]
    offset_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Topic {
    ProposerSlashing,
    AttesterSlashing,
    BeaconBlock,
    VoluntaryExit,
    BeaconAttestation,
    BeaconAggregateAndProof,
    BlsToExecutionChange,
    SyncCommittee,
    SyncCommitteeContributionAndProof,
}

#[derive(Debug)]
pub struct GossipValidation<E: EthSpec> {
    path: PathBuf,
    meta: Meta,
    state: BeaconState<E>,
}

impl<E: EthSpec> LoadCase for GossipValidation<E> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let meta: Meta = yaml_decode_file(&path.join("meta.yaml"))?;
        let spec = &Self::testing_spec(path, fork_name)?;
        let state = ssz_decode_state(&path.join("state.ssz_snappy"), spec)?;

        Ok(Self {
            path: path.to_path_buf(),
            meta,
            state,
        })
    }
}

impl<E: EthSpec + TypeName> Case for GossipValidation<E> {
    fn description(&self) -> String {
        self.path
            .iter()
            .next_back()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        if self.has_known_harness_limitation() {
            return Err(Error::SkippedKnownFailure);
        }

        if let Some(bls_setting) = self.meta.bls_setting {
            bls_setting.check()?;
        }

        let spec = Self::testing_spec(&self.path, fork_name)?;
        let tester = GossipTester::new(self, spec)?;

        for message_meta in &self.meta.messages {
            let actual =
                tester.validate_message(&self.path, &self.meta.topic, message_meta, fork_name)?;

            if message_meta.expected != actual {
                return Err(Error::NotEqual(format!(
                    "{}: expected {:?}, got {:?}{}",
                    self.path.display(),
                    message_meta.expected,
                    actual,
                    message_meta
                        .reason
                        .as_ref()
                        .map(|r| format!(" ({r})"))
                        .unwrap_or_default()
                )));
            }
        }

        Ok(())
    }
}

struct GossipTester<E: EthSpec> {
    harness: BeaconChainHarness<EphemeralHarnessType<E>>,
    network_beacon_processor: Arc<NetworkBeaconProcessor<EphemeralHarnessType<E>>>,
    network_rx: Mutex<tokio::sync::mpsc::UnboundedReceiver<NetworkMessage<E>>>,
    spec: ChainSpec,
    genesis_time: u64,
    current_time_ms: u64,
}

impl<E: EthSpec> GossipTester<E> {
    fn new(case: &GossipValidation<E>, spec: ChainSpec) -> Result<Self, Error> {
        let genesis_time = case.state.genesis_time();
        let blocks = case.load_beacon_blocks(&spec)?;
        let current_time_ms = case.current_time_ms(&spec)?;
        let spec = Arc::new(spec);

        let (harness, initial_block_index) =
            Self::build_harness(case, spec.clone(), &blocks, genesis_time, current_time_ms)?;
        let (network_beacon_processor, network_rx) =
            NetworkBeaconProcessor::null_from_harness_with_network_receiver(&harness);

        let tester = Self {
            harness,
            network_beacon_processor: Arc::new(network_beacon_processor),
            network_rx: Mutex::new(network_rx),
            spec: spec.as_ref().clone(),
            genesis_time,
            current_time_ms,
        };

        tester.set_time_ms(current_time_ms)?;
        tester.import_setup_blocks(case, &blocks, initial_block_index)?;
        tester.set_finalized_checkpoint(case.finalized_checkpoint(&blocks)?);

        Ok(tester)
    }

    fn build_harness(
        case: &GossipValidation<E>,
        spec: Arc<ChainSpec>,
        blocks: &HashMap<String, SignedBeaconBlock<E>>,
        genesis_time: u64,
        current_time_ms: u64,
    ) -> Result<(BeaconChainHarness<EphemeralHarnessType<E>>, Option<usize>), Error> {
        // Timing-ignore fixtures advance the supplied state beyond their setup block. Anchor the
        // advanced state, then import the historical block through the normal path below.
        let initial_block_index =
            (!case.meta.blocks.is_empty() && !case.is_advanced_timing_ignore()).then_some(0);

        let harness_builder = || {
            BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
                .spec(spec.clone())
                .keypairs(vec![])
                .mock_execution_layer()
                .recalculate_fork_times_with_genesis(genesis_time)
                // Default to valid EL responses. Setup blocks with `payload_status` override this
                // during import.
                .mock_execution_layer_all_payloads_valid()
        };

        let harness = if let Some(initial_block_index) = initial_block_index {
            let initial_setup_block = &case.meta.blocks[initial_block_index];
            // The first setup block's post-state is `state.ssz_snappy`. Other setup blocks are
            // imported below through Lighthouse's normal block import path.
            let initial_block = blocks
                .get(&initial_setup_block.block)
                .ok_or_else(|| Error::FailedToParseTest("missing initial setup block".into()))?
                .clone();
            let finalized_checkpoint = case
                .finalized_checkpoint(blocks)?
                .filter(|checkpoint| checkpoint.root == initial_block.canonical_root());
            harness_builder()
                .initial_state_ephemeral_store(
                    case.state.clone(),
                    initial_block,
                    finalized_checkpoint,
                )
                .build()
        } else if case.meta.topic.requires_synthetic_anchor() {
            let (state, block) = synthetic_anchor(case.state.clone(), &spec)?;
            let slot_clock = TestingSlotClock::new(
                spec.genesis_slot,
                Duration::from_secs(genesis_time),
                spec.get_slot_duration(),
            );
            let state_time_ms = slot_time_ms(state.slot(), &spec)?;
            let build_time = Duration::from_secs(genesis_time)
                .checked_add(Duration::from_millis(current_time_ms.max(state_time_ms)))
                .ok_or_else(|| Error::FailedToParseTest("build time overflow".into()))?;
            slot_clock.set_current_time(build_time);
            harness_builder()
                .testing_slot_clock(slot_clock)
                .initial_state_ephemeral_store(state, block, None)
                .build()
        } else {
            harness_builder()
                .genesis_state_ephemeral_store(case.state.clone())
                .build()
        };

        Ok((harness, initial_block_index))
    }

    fn set_finalized_checkpoint(&self, checkpoint: Option<Checkpoint>) {
        let Some(checkpoint) = checkpoint else {
            return;
        };
        let mut fork_choice = self.harness.chain.canonical_head.fork_choice_write_lock();
        if fork_choice.finalized_checkpoint() != checkpoint {
            fork_choice.testing_set_finalized_checkpoint(checkpoint);
        }
    }

    fn import_setup_blocks(
        &self,
        case: &GossipValidation<E>,
        blocks: &HashMap<String, SignedBeaconBlock<E>>,
        initial_block_index: Option<usize>,
    ) -> Result<(), Error> {
        for (index, setup_block) in case.meta.blocks.iter().enumerate() {
            if setup_block.failed {
                continue;
            }
            if initial_block_index == Some(index) {
                continue;
            }
            let block = blocks.get(&setup_block.block).ok_or_else(|| {
                Error::FailedToParseTest(format!("unknown block file {}", setup_block.block))
            })?;
            self.import_setup_block(block.clone(), setup_block.payload_status)?;
        }

        Ok(())
    }

    fn validate_message(
        &self,
        path: &Path,
        topic: &Topic,
        message_meta: &MessageMeta,
        fork_name: ForkName,
    ) -> Result<MessageAcceptance, Error> {
        let message_id = MessageId::new(message_meta.message.as_bytes());
        let peer_id = PeerId::random();

        match topic {
            Topic::ProposerSlashing => {
                self.process_proposer_slashing(path, message_meta, message_id.clone(), peer_id)?
            }
            Topic::AttesterSlashing => self.process_attester_slashing(
                path,
                message_meta,
                fork_name,
                message_id.clone(),
                peer_id,
            )?,
            Topic::BeaconBlock => {
                self.process_beacon_block(path, message_meta, message_id.clone(), peer_id)?
            }
            Topic::VoluntaryExit => {
                self.process_voluntary_exit(path, message_meta, message_id.clone(), peer_id)?
            }
            Topic::BeaconAttestation => {
                self.process_beacon_attestation(path, message_meta, message_id.clone(), peer_id)?
            }
            Topic::BeaconAggregateAndProof => self.process_beacon_aggregate_and_proof(
                path,
                message_meta,
                message_id.clone(),
                peer_id,
            )?,
            Topic::BlsToExecutionChange => {
                if let Err(error) = self.process_bls_to_execution_change(
                    path,
                    message_meta,
                    message_id.clone(),
                    peer_id,
                ) {
                    return match error {
                        // The network service rejects SSZ decode failures before gossip processing.
                        Error::InvalidBLSInput(_) => Ok(MessageAcceptance::Reject),
                        error => Err(error),
                    };
                }
            }
            Topic::SyncCommittee => self.process_sync_committee_message(
                path,
                message_meta,
                message_id.clone(),
                peer_id,
            )?,
            Topic::SyncCommitteeContributionAndProof => self
                .process_sync_committee_contribution_and_proof(
                    path,
                    message_meta,
                    message_id.clone(),
                    peer_id,
                )?,
        }

        self.validation_result(&message_id, &peer_id)
    }

    fn process_proposer_slashing(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
        message_id: MessageId,
        peer_id: PeerId,
    ) -> Result<(), Error> {
        let slashing: ProposerSlashing =
            ssz_decode_file(&path.join(format!("{}.ssz_snappy", message_meta.message)))?;

        self.network_beacon_processor
            .process_gossip_proposer_slashing(message_id, peer_id, slashing);
        Ok(())
    }

    fn process_attester_slashing(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
        fork_name: ForkName,
        message_id: MessageId,
        peer_id: PeerId,
    ) -> Result<(), Error> {
        let ssz_path = path.join(format!("{}.ssz_snappy", message_meta.message));
        let slashing: AttesterSlashing<E> = if fork_name.gloas_enabled() {
            ssz_decode_file(&ssz_path).map(AttesterSlashing::Gloas)?
        } else if fork_name.electra_enabled() {
            ssz_decode_file(&ssz_path).map(AttesterSlashing::Electra)?
        } else {
            ssz_decode_file(&ssz_path).map(AttesterSlashing::Base)?
        };

        self.network_beacon_processor
            .process_gossip_attester_slashing(message_id, peer_id, slashing);
        Ok(())
    }

    fn process_beacon_block(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
        message_id: MessageId,
        peer_id: PeerId,
    ) -> Result<(), Error> {
        let block = Arc::new(load_beacon_block(path, &message_meta.message, &self.spec)?);
        let time_ms = self
            .current_time_ms
            .checked_add(message_meta.offset_ms.unwrap_or_default())
            .ok_or_else(|| Error::FailedToParseTest("message time overflow".into()))?;
        let seen_duration = self.set_time_ms(time_ms)?;

        let process_fn = Box::pin(self.network_beacon_processor.clone().process_gossip_block(
            message_id,
            peer_id,
            Client::default(),
            block,
            self.network_beacon_processor.duplicate_cache.clone(),
            self.network_beacon_processor.invalid_block_storage.clone(),
            seen_duration,
        ));

        self.block_on_dangerous(process_fn)?;
        Ok(())
    }

    fn process_voluntary_exit(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
        message_id: MessageId,
        peer_id: PeerId,
    ) -> Result<(), Error> {
        let voluntary_exit: SignedVoluntaryExit =
            ssz_decode_file(&path.join(format!("{}.ssz_snappy", message_meta.message)))?;
        self.set_message_time(message_meta)?;

        self.network_beacon_processor.process_gossip_voluntary_exit(
            message_id,
            peer_id,
            voluntary_exit,
        );
        Ok(())
    }

    fn process_beacon_attestation(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
        message_id: MessageId,
        peer_id: PeerId,
    ) -> Result<(), Error> {
        let attestation: SingleAttestation =
            ssz_decode_file(&path.join(format!("{}.ssz_snappy", message_meta.message)))?;
        let subnet_id = SubnetId::new(message_meta.subnet_id.ok_or_else(|| {
            Error::FailedToParseTest("missing beacon_attestation subnet_id".into())
        })?);
        let seen_timestamp = self.set_message_time(message_meta)?;

        self.network_beacon_processor
            .clone()
            .process_gossip_attestation(
                message_id,
                peer_id,
                Box::new(attestation),
                subnet_id,
                true,
                ReprocessAllowance::None,
                seen_timestamp,
            );
        Ok(())
    }

    fn process_beacon_aggregate_and_proof(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
        message_id: MessageId,
        peer_id: PeerId,
    ) -> Result<(), Error> {
        let aggregate = ssz_decode_file::<SignedAggregateAndProofElectra<E>>(
            &path.join(format!("{}.ssz_snappy", message_meta.message)),
        )
        .map(SignedAggregateAndProof::Electra)?;
        let seen_timestamp = self.set_message_time(message_meta)?;

        self.network_beacon_processor
            .clone()
            .process_gossip_aggregate(
                message_id,
                peer_id,
                Box::new(aggregate),
                ReprocessAllowance::None,
                seen_timestamp,
            );
        Ok(())
    }

    fn process_bls_to_execution_change(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
        message_id: MessageId,
        peer_id: PeerId,
    ) -> Result<(), Error> {
        let bls_to_execution_change: SignedBlsToExecutionChange =
            ssz_decode_file(&path.join(format!("{}.ssz_snappy", message_meta.message)))?;
        self.set_message_time(message_meta)?;

        self.network_beacon_processor
            .process_gossip_bls_to_execution_change(message_id, peer_id, bls_to_execution_change);
        Ok(())
    }

    fn process_sync_committee_message(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
        message_id: MessageId,
        peer_id: PeerId,
    ) -> Result<(), Error> {
        let sync_message: SyncCommitteeMessage =
            ssz_decode_file(&path.join(format!("{}.ssz_snappy", message_meta.message)))?;
        let subnet_id =
            SyncSubnetId::new(message_meta.subnet_id.ok_or_else(|| {
                Error::FailedToParseTest("missing sync_committee subnet_id".into())
            })?);
        let seen_timestamp = self.set_message_time(message_meta)?;

        self.network_beacon_processor
            .process_gossip_sync_committee_signature(
                message_id,
                peer_id,
                sync_message,
                subnet_id,
                seen_timestamp,
            );
        Ok(())
    }

    fn process_sync_committee_contribution_and_proof(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
        message_id: MessageId,
        peer_id: PeerId,
    ) -> Result<(), Error> {
        let contribution: SignedContributionAndProof<E> =
            ssz_decode_file(&path.join(format!("{}.ssz_snappy", message_meta.message)))?;
        let seen_timestamp = self.set_message_time(message_meta)?;

        self.network_beacon_processor
            .process_sync_committee_contribution(message_id, peer_id, contribution, seen_timestamp);
        Ok(())
    }

    fn set_message_time(&self, message_meta: &MessageMeta) -> Result<Duration, Error> {
        let time_ms = self
            .current_time_ms
            .checked_add(message_meta.offset_ms.unwrap_or_default())
            .ok_or_else(|| Error::FailedToParseTest("message time overflow".into()))?;
        self.set_time_ms(time_ms)
    }

    fn validation_result(
        &self,
        message_id: &MessageId,
        peer_id: &PeerId,
    ) -> Result<MessageAcceptance, Error> {
        let mut network_rx = self
            .network_rx
            .lock()
            .map_err(|_| Error::InternalError("network receiver lock poisoned".into()))?;
        while let Ok(network_message) = network_rx.try_recv() {
            if let NetworkMessage::ValidationResult {
                propagation_source,
                message_id: received_message_id,
                validation_result,
            } = network_message
                && &received_message_id == message_id
                && &propagation_source == peer_id
            {
                return Ok(validation_result);
            }
        }

        Err(Error::InternalError(
            "gossip processing did not emit a validation result".into(),
        ))
    }

    fn import_setup_block(
        &self,
        block: SignedBeaconBlock<E>,
        payload_status: Option<PayloadStatus>,
    ) -> Result<(), Error> {
        let block_root = block.canonical_root();
        // Configure the mock EL for this setup block only, then restore the default before
        // validating gossip messages.
        self.configure_payload_status(&block, payload_status);
        let result = self.block_on_dangerous(self.network_beacon_processor.chain.process_block(
            block_root,
            LookupBlock::new(Arc::new(block.clone())),
            NotifyExecutionLayer::Yes,
            BlockImportSource::Lookup,
            || Ok(()),
        ))?;
        self.configure_payload_status_for_default();

        match result {
            Ok(_) => {
                if payload_status == Some(PayloadStatus::Invalidated) {
                    // The block has been imported optimistically. Mark it invalid in fork choice so
                    // descendants observe an invalid execution parent.
                    self.block_on_dangerous(self.harness.chain.process_invalid_execution_payload(
                        &InvalidationOperation::InvalidateOne { block_root },
                    ))?
                    .map_err(|e| {
                        Error::InternalError(format!(
                            "setup block {block_root:?} invalidation failed: {e:?}"
                        ))
                    })?;
                }
                Ok(())
            }
            Err(BlockError::DuplicateFullyImported(_))
            | Err(BlockError::DuplicateImportStatusUnknown(_))
            | Err(BlockError::GenesisBlock) => Ok(()),
            Err(e) => Err(Error::InternalError(format!(
                "setup block {block_root:?} import failed: {e:?}"
            ))),
        }
    }

    fn configure_payload_status(
        &self,
        block: &SignedBeaconBlock<E>,
        status: Option<PayloadStatus>,
    ) {
        let Some(mock_execution_layer) = self.harness.mock_execution_layer.as_ref() else {
            return;
        };
        match status {
            Some(PayloadStatus::NotValidated) | Some(PayloadStatus::Invalidated) => {
                mock_execution_layer.server.all_payloads_syncing(true);
            }
            Some(PayloadStatus::Valid) | None => {
                mock_execution_layer.server.all_payloads_valid();
            }
        }

        if status == Some(PayloadStatus::Valid)
            && let Ok(payload) = block.message().execution_payload()
        {
            let block_hash = payload.block_hash();
            mock_execution_layer.server.set_payload_statuses(
                block_hash,
                PayloadStatusV1 {
                    status: PayloadStatusV1Status::Valid,
                    latest_valid_hash: Some(block_hash),
                    validation_error: None,
                },
            );
        }
    }

    fn configure_payload_status_for_default(&self) {
        if let Some(mock_execution_layer) = self.harness.mock_execution_layer.as_ref() {
            mock_execution_layer.server.all_payloads_valid();
        }
    }

    fn set_time_ms(&self, time_ms: u64) -> Result<Duration, Error> {
        let current_time = Duration::from_secs(self.genesis_time)
            .checked_add(Duration::from_millis(time_ms))
            .ok_or_else(|| Error::FailedToParseTest("message time overflow".into()))?;
        self.harness.chain.slot_clock.set_current_time(current_time);
        let slot = self
            .harness
            .chain
            .slot()
            .map_err(|e| Error::InternalError(format!("unable to read slot clock: {e:?}")))?;
        self.harness
            .chain
            .canonical_head
            .fork_choice_write_lock()
            .update_time(slot)
            .map_err(|e| {
                Error::InternalError(format!("unable to update fork choice time: {e:?}"))
            })?;
        Ok(current_time)
    }

    fn block_on_dangerous<F: Future>(&self, future: F) -> Result<F::Output, Error> {
        self.harness
            .chain
            .task_executor
            .clone()
            .block_on_dangerous(future, "gossip_validation")
            .ok_or_else(|| Error::InternalError("runtime shutdown".into()))
    }
}

impl Topic {
    fn requires_synthetic_anchor(self) -> bool {
        matches!(
            self,
            Self::VoluntaryExit
                | Self::BeaconAttestation
                | Self::BeaconAggregateAndProof
                | Self::BlsToExecutionChange
                | Self::SyncCommittee
                | Self::SyncCommitteeContributionAndProof
        )
    }
}

impl<E: EthSpec> GossipValidation<E> {
    fn testing_spec(path: &Path, fork_name: ForkName) -> Result<ChainSpec, Error> {
        let mut spec = testing_spec::<E>(fork_name);
        let config_path = path.join("config.yaml");
        if !config_path.exists() {
            return Ok(spec);
        }

        let case_config: CaseConfig = yaml_decode_file(&config_path)?;
        let Some(blob_schedule) = case_config.blob_schedule else {
            return Ok(spec);
        };

        spec.blob_schedule = blob_schedule;
        Ok(spec)
    }

    fn has_known_harness_limitation(&self) -> bool {
        const IGNORED_BEACON_BLOCK_CASES: &[&str] = &[
            // These vectors record a consensus-failed setup block so descendants can be classified
            // using the known-invalid parent. Lighthouse does not insert consensus-invalid blocks
            // into fork choice, so these preconditions cannot be constructed through the
            // production import path.
            "gossip_beacon_block__ignore_parent_consensus_failed_execution_known",
            "gossip_beacon_block__reject_parent_consensus_failed_execution_not_verified",
            "gossip_beacon_block__reject_parent_failed_validation",
        ];
        const UNSUPPORTED_TIMING_BOUNDARY_CASES: &[&str] = &[
            "accepts_at_slot_start",
            "accepts_first_slot_when_epoch_window_closes",
            "accepts_first_slot_when_epoch_window_opens",
            "accepts_last_slot_at_slot_start",
            "accepts_last_slot_one_millisecond_before_slot_start",
            "accepts_last_slot_when_epoch_window_closes",
            "accepts_one_millisecond_before_slot_start",
        ];
        let Some(case_name) = self.path.file_name().and_then(|name| name.to_str()) else {
            return false;
        };

        match self.meta.topic {
            Topic::BeaconBlock => IGNORED_BEACON_BLOCK_CASES.contains(&case_name),
            Topic::BeaconAttestation | Topic::BeaconAggregateAndProof => {
                // These vectors require fixture history that the production-backed harness cannot
                // construct: a retained consensus-invalid block, an unknown finalized root, or a
                // known but unfinalized slot-zero block.
                self.meta.blocks.iter().any(|block| block.failed)
                    || matches!(
                        self.meta.finalized_checkpoint,
                        Some(FinalizedCheckpoint::Root { .. })
                    )
                    || UNSUPPORTED_TIMING_BOUNDARY_CASES
                        .iter()
                        .any(|suffix| case_name.ends_with(suffix))
            }
            _ => false,
        }
    }

    fn is_advanced_timing_ignore(&self) -> bool {
        let Some(case_name) = self.path.file_name().and_then(|name| name.to_str()) else {
            return false;
        };
        matches!(
            self.meta.topic,
            Topic::BeaconAttestation | Topic::BeaconAggregateAndProof
        ) && [
            "ignores_first_slot_after_epoch_window_closes",
            "ignores_first_slot_before_epoch_window_opens",
            "ignores_last_slot_after_epoch_window_closes",
        ]
        .iter()
        .any(|suffix| case_name.ends_with(suffix))
    }

    fn current_time_ms(&self, spec: &ChainSpec) -> Result<u64, Error> {
        if let Some(current_time_ms) = self.meta.current_time_ms {
            return Ok(current_time_ms);
        }

        slot_time_ms(self.state.slot(), spec)
    }

    fn finalized_checkpoint(
        &self,
        blocks: &HashMap<String, SignedBeaconBlock<E>>,
    ) -> Result<Option<Checkpoint>, Error> {
        if let Some(checkpoint) = &self.meta.finalized_checkpoint {
            return checkpoint.checkpoint(blocks).map(Some);
        }

        let checkpoint = self.state.finalized_checkpoint();
        // The initial state uses a zero-root finalized checkpoint. Lighthouse production fork
        // choice represents that genesis anchor by the real genesis block root, so let the anchor
        // helper use its production default for this placeholder case.
        Ok((checkpoint.epoch.as_u64() != 0 || !checkpoint.root.is_zero()).then_some(checkpoint))
    }

    fn load_beacon_blocks(
        &self,
        spec: &ChainSpec,
    ) -> Result<HashMap<String, SignedBeaconBlock<E>>, Error> {
        let mut block_names = HashSet::new();
        block_names.extend(self.meta.blocks.iter().map(|block| block.block.clone()));
        block_names.extend(
            self.meta
                .messages
                .iter()
                .filter(|_| self.meta.topic == Topic::BeaconBlock)
                .map(|message| message.message.clone()),
        );
        if let Some(FinalizedCheckpoint::Block { block, .. }) = &self.meta.finalized_checkpoint {
            block_names.insert(block.clone());
        }

        block_names
            .into_iter()
            .map(|name| {
                let block = load_beacon_block(&self.path, &name, spec)?;
                Ok((name, block))
            })
            .collect()
    }
}

fn slot_time_ms(slot: Slot, spec: &ChainSpec) -> Result<u64, Error> {
    let slots_since_genesis = slot
        .as_u64()
        .checked_sub(spec.genesis_slot.as_u64())
        .ok_or_else(|| Error::FailedToParseTest("state is before genesis slot".into()))?;
    let slot_duration_ms = u64::try_from(spec.get_slot_duration().as_millis()).map_err(|_| {
        Error::FailedToParseTest("slot duration does not fit in milliseconds".into())
    })?;
    slots_since_genesis
        .checked_mul(slot_duration_ms)
        .ok_or_else(|| Error::FailedToParseTest("current time overflow".into()))
}

impl FinalizedCheckpoint {
    fn checkpoint<E: EthSpec>(
        &self,
        blocks: &HashMap<String, SignedBeaconBlock<E>>,
    ) -> Result<Checkpoint, Error> {
        match self {
            FinalizedCheckpoint::Root { epoch, root } => Ok(Checkpoint {
                epoch: (*epoch).into(),
                root: *root,
            }),
            FinalizedCheckpoint::Block { epoch, block } => {
                let block = blocks.get(block).ok_or_else(|| {
                    Error::FailedToParseTest(format!("unknown finalized checkpoint block {block}"))
                })?;
                Ok(Checkpoint {
                    epoch: (*epoch).into(),
                    root: block.canonical_root(),
                })
            }
        }
    }
}

fn load_beacon_block<E: EthSpec>(
    path: &Path,
    name: &str,
    spec: &ChainSpec,
) -> Result<SignedBeaconBlock<E>, Error> {
    ssz_decode_file_with(&path.join(format!("{name}.ssz_snappy")), |bytes| {
        SignedBeaconBlock::from_ssz_bytes(bytes, spec)
    })
}

fn synthetic_anchor<E: EthSpec>(
    mut state: BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(BeaconState<E>, SignedBeaconBlock<E>), Error> {
    let mut block = BeaconBlock::empty(spec);
    *block.slot_mut() = state.slot();
    *block.proposer_index_mut() = state.latest_block_header().proposer_index;

    let header = state.latest_block_header_mut();
    header.slot = block.slot();
    header.proposer_index = block.proposer_index();
    header.parent_root = block.parent_root();
    header.state_root = Hash256::ZERO;
    header.body_root = block.body_root();

    *block.state_root_mut() = state
        .update_tree_hash_cache()
        .map_err(|error| Error::InternalError(format!("unable to hash anchor state: {error:?}")))?;

    Ok((
        state,
        SignedBeaconBlock::from_block(block, Signature::empty()),
    ))
}
