use super::*;
use crate::bls_setting::BlsSetting;
use crate::decode::{ssz_decode_file, ssz_decode_file_with, ssz_decode_state, yaml_decode_file};
use crate::type_name::TypeName;
use ::fork_choice::InvalidationOperation;
use beacon_chain::block_verification_types::LookupBlock;
use beacon_chain::slot_clock::{SlotClock, TestingSlotClock};
use beacon_chain::store::{HotColdDB, config::StoreConfig};
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use beacon_chain::{BlockError, NotifyExecutionLayer};
use execution_layer::{PayloadStatusV1, PayloadStatusV1Status};
use lighthouse_network::{Client, MessageAcceptance, MessageId, PeerId};
use network::NetworkBeaconProcessor;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use types::{
    AttesterSlashing, BeaconState, BlockImportSource, ChainSpec, Checkpoint, EthSpec, ExecPayload,
    ForkName, Hash256, ProposerSlashing, SignedAggregateAndProof, SignedAggregateAndProofBase,
    SignedAggregateAndProofElectra, SignedBeaconBlock, SignedBlsToExecutionChange,
    SignedContributionAndProof, SignedVoluntaryExit, SingleAttestation, SubnetId,
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
    #[allow(dead_code)]
    subnet_id: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
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
        let spec = &testing_spec::<E>(fork_name);
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
        if self.is_known_failure_case() {
            return Err(Error::SkippedKnownFailure);
        }

        if let Some(bls_setting) = self.meta.bls_setting {
            bls_setting.check()?;
        }

        let spec = testing_spec::<E>(fork_name);
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
    spec: ChainSpec,
    current_time_ms: u64,
}

struct InitialTestState<E: EthSpec> {
    state: BeaconState<E>,
    block: SignedBeaconBlock<E>,
    finalized_checkpoint: Option<Checkpoint>,
    setup_block_index: Option<usize>,
}

impl<E: EthSpec> GossipTester<E> {
    fn new(case: &GossipValidation<E>, spec: ChainSpec) -> Result<Self, Error> {
        let genesis_time = case.state.genesis_time();
        let blocks = case.load_beacon_blocks(&spec)?;
        let spec = Arc::new(spec);

        let anchor = case.initial_anchor(&blocks)?;
        let harness = Self::build_harness(case, spec.clone(), genesis_time, anchor.as_ref())?;
        let network_beacon_processor =
            Arc::new(NetworkBeaconProcessor::null_from_harness(&harness));

        let tester = Self {
            harness,
            network_beacon_processor,
            spec: spec.as_ref().clone(),
            current_time_ms: case.current_time_ms(&spec, genesis_time),
        };

        tester.set_time_ms(tester.current_time_ms)?;
        tester.import_setup_blocks(case, &blocks, anchor.as_ref())?;

        Ok(tester)
    }

    fn build_harness(
        case: &GossipValidation<E>,
        spec: Arc<ChainSpec>,
        genesis_time: u64,
        anchor: Option<&InitialTestState<E>>,
    ) -> Result<BeaconChainHarness<EphemeralHarnessType<E>>, Error> {
        let state_slot = case.state.slot();
        let current_time_ms = case.current_time_ms(&spec, genesis_time);
        let initial_time = Duration::from_millis(current_time_ms);

        let harness_builder = || {
            let slot_clock = TestingSlotClock::new(
                spec.genesis_slot,
                Duration::from_secs(genesis_time),
                spec.get_slot_duration(),
            );
            slot_clock.set_current_time(initial_time);
            if slot_clock.now().is_none_or(|slot| slot < state_slot) {
                slot_clock.set_slot(state_slot.as_u64());
            }
            BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
                .spec(spec.clone())
                .keypairs(vec![])
                .testing_slot_clock(slot_clock)
                .mock_execution_layer()
                .recalculate_fork_times_with_genesis(genesis_time)
                // Default to valid EL responses. Setup blocks with `payload_status` override this
                // during import.
                .mock_execution_layer_all_payloads_valid()
        };

        let harness = if let Some(anchor) = anchor {
            let store =
                Arc::new(HotColdDB::open_ephemeral(StoreConfig::default(), spec.clone()).unwrap());
            let initial_state = anchor.state.clone();
            let initial_block = anchor.block.clone();
            let finalized_checkpoint = anchor.finalized_checkpoint;
            let genesis_slot = spec.genesis_slot;
            harness_builder()
                .resumed_ephemeral_store(store)
                .override_store_mutator(Box::new(move |builder| {
                    if finalized_checkpoint.is_some() || initial_block.slot() == genesis_slot {
                        builder
                            .testing_initial_state(
                                initial_state,
                                initial_block,
                                finalized_checkpoint,
                            )
                            .expect("should build test initial state")
                    } else {
                        builder
                            .testing_initial_state_with_unfinalized_block(
                                initial_state,
                                initial_block,
                            )
                            .expect("should build test initial state")
                    }
                }))
                .build()
        } else {
            harness_builder()
                .testing_state_ephemeral_store(case.state.clone())
                .build()
        };

        Ok(harness)
    }

    fn import_setup_blocks(
        &self,
        case: &GossipValidation<E>,
        blocks: &HashMap<String, SignedBeaconBlock<E>>,
        anchor: Option<&InitialTestState<E>>,
    ) -> Result<(), Error> {
        for (index, setup_block) in case.meta.blocks.iter().enumerate() {
            if setup_block.failed {
                continue;
            }
            if anchor.is_some_and(|anchor| anchor.setup_block_index == Some(index)) {
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
        match topic {
            Topic::ProposerSlashing => self.validate_proposer_slashing(path, message_meta),
            Topic::AttesterSlashing => {
                self.validate_attester_slashing(path, message_meta, fork_name)
            }
            Topic::BeaconBlock => self.validate_beacon_block(path, message_meta),
            Topic::VoluntaryExit => self.validate_voluntary_exit(path, message_meta),
            Topic::BeaconAttestation => {
                self.validate_beacon_attestation(path, message_meta, fork_name)
            }
            Topic::BeaconAggregateAndProof => {
                self.validate_beacon_aggregate_and_proof(path, message_meta, fork_name)
            }
            Topic::BlsToExecutionChange => {
                self.validate_bls_to_execution_change(path, message_meta)
            }
            Topic::SyncCommittee => self.validate_sync_committee_message(path, message_meta),
            Topic::SyncCommitteeContributionAndProof => {
                self.validate_sync_committee_contribution_and_proof(path, message_meta)
            }
        }
    }

    fn validate_proposer_slashing(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
    ) -> Result<MessageAcceptance, Error> {
        let slashing: ProposerSlashing =
            ssz_decode_file(&path.join(format!("{}.ssz_snappy", message_meta.message)))?;

        let message_id = MessageId::new(&[]);
        let peer_id = PeerId::random();
        Ok(self
            .network_beacon_processor
            .process_gossip_proposer_slashing(message_id, peer_id, slashing))
    }

    fn validate_attester_slashing(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
        fork_name: ForkName,
    ) -> Result<MessageAcceptance, Error> {
        let ssz_path = path.join(format!("{}.ssz_snappy", message_meta.message));
        let slashing: AttesterSlashing<E> = if fork_name.electra_enabled() {
            ssz_decode_file(&ssz_path).map(AttesterSlashing::Electra)?
        } else {
            ssz_decode_file(&ssz_path).map(AttesterSlashing::Base)?
        };

        let message_id = MessageId::new(&[]);
        let peer_id = PeerId::random();
        Ok(self
            .network_beacon_processor
            .process_gossip_attester_slashing(message_id, peer_id, slashing))
    }

    fn validate_beacon_block(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
    ) -> Result<MessageAcceptance, Error> {
        let block = Arc::new(load_beacon_block(path, &message_meta.message, &self.spec)?);
        let time_ms = self
            .current_time_ms
            .checked_add(message_meta.offset_ms.unwrap_or_default())
            .ok_or_else(|| Error::FailedToParseTest("message time overflow".into()))?;
        let seen_duration = self.set_time_ms(time_ms)?;

        let process_fn = Box::pin(self.network_beacon_processor.clone().process_gossip_block(
            MessageId::new(&[]),
            PeerId::random(),
            Client::default(),
            block,
            self.network_beacon_processor.duplicate_cache.clone(),
            self.network_beacon_processor.invalid_block_storage.clone(),
            seen_duration,
        ));

        self.block_on_dangerous(process_fn)
    }

    fn validate_voluntary_exit(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
    ) -> Result<MessageAcceptance, Error> {
        let voluntary_exit: SignedVoluntaryExit =
            ssz_decode_file(&path.join(format!("{}.ssz_snappy", message_meta.message)))?;
        self.message_seen_duration(message_meta)?;

        let message_id = MessageId::new(&[]);
        let peer_id = PeerId::random();
        Ok(self.network_beacon_processor.process_gossip_voluntary_exit(
            message_id,
            peer_id,
            voluntary_exit,
        ))
    }

    fn validate_beacon_attestation(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
        _fork_name: ForkName,
    ) -> Result<MessageAcceptance, Error> {
        let ssz_path = path.join(format!("{}.ssz_snappy", message_meta.message));
        let attestation: SingleAttestation = ssz_decode_file(&ssz_path)?;
        let subnet_id = SubnetId::new(message_meta.subnet_id.ok_or_else(|| {
            Error::FailedToParseTest("missing beacon_attestation subnet_id".into())
        })?);
        let seen_duration = self.message_seen_duration(message_meta)?;

        self.network_beacon_processor
            .clone()
            .process_gossip_attestation(
                MessageId::new(&[]),
                PeerId::random(),
                Box::new(attestation),
                subnet_id,
                true,
                false,
                seen_duration,
            )
            .ok_or_else(|| Error::InternalError("attestation validation deferred".into()))
    }

    fn validate_beacon_aggregate_and_proof(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
        fork_name: ForkName,
    ) -> Result<MessageAcceptance, Error> {
        let ssz_path = path.join(format!("{}.ssz_snappy", message_meta.message));
        let aggregate: SignedAggregateAndProof<E> = if fork_name.electra_enabled() {
            ssz_decode_file::<SignedAggregateAndProofElectra<E>>(&ssz_path)
                .map(SignedAggregateAndProof::Electra)?
        } else {
            ssz_decode_file::<SignedAggregateAndProofBase<E>>(&ssz_path)
                .map(SignedAggregateAndProof::Base)?
        };
        let seen_duration = self.message_seen_duration(message_meta)?;

        self.network_beacon_processor
            .clone()
            .process_gossip_aggregate(
                MessageId::new(&[]),
                PeerId::random(),
                Box::new(aggregate),
                false,
                seen_duration,
            )
            .ok_or_else(|| Error::InternalError("aggregate validation deferred".into()))
    }

    fn validate_bls_to_execution_change(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
    ) -> Result<MessageAcceptance, Error> {
        let bls_to_execution_change: SignedBlsToExecutionChange =
            match ssz_decode_file(&path.join(format!("{}.ssz_snappy", message_meta.message))) {
                Ok(message) => message,
                Err(Error::InvalidBLSInput(_)) => return Ok(MessageAcceptance::Reject),
                Err(e) => return Err(e),
            };
        self.message_seen_duration(message_meta)?;

        Ok(self
            .network_beacon_processor
            .process_gossip_bls_to_execution_change(
                MessageId::new(&[]),
                PeerId::random(),
                bls_to_execution_change,
            ))
    }

    fn validate_sync_committee_message(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
    ) -> Result<MessageAcceptance, Error> {
        let sync_message: SyncCommitteeMessage =
            ssz_decode_file(&path.join(format!("{}.ssz_snappy", message_meta.message)))?;
        let subnet_id = SyncSubnetId::new(message_meta.subnet_id.ok_or_else(|| {
            Error::FailedToParseTest("missing sync_committee_message subnet_id".into())
        })?);
        let seen_duration = self.message_seen_duration(message_meta)?;

        Ok(self
            .network_beacon_processor
            .process_gossip_sync_committee_signature(
                MessageId::new(&[]),
                PeerId::random(),
                sync_message,
                subnet_id,
                seen_duration,
            ))
    }

    fn validate_sync_committee_contribution_and_proof(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
    ) -> Result<MessageAcceptance, Error> {
        let sync_contribution: SignedContributionAndProof<E> =
            ssz_decode_file(&path.join(format!("{}.ssz_snappy", message_meta.message)))?;
        let seen_duration = self.message_seen_duration(message_meta)?;

        Ok(self
            .network_beacon_processor
            .process_sync_committee_contribution(
                MessageId::new(&[]),
                PeerId::random(),
                sync_contribution,
                seen_duration,
            ))
    }

    fn message_seen_duration(&self, message_meta: &MessageMeta) -> Result<Duration, Error> {
        let time_ms = self
            .current_time_ms
            .checked_add(message_meta.offset_ms.unwrap_or_default())
            .ok_or_else(|| Error::FailedToParseTest("message time overflow".into()))?;
        self.set_time_ms(time_ms)
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
        let current_time = Duration::from_millis(time_ms);
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

impl<E: EthSpec> GossipValidation<E> {
    fn is_known_failure_case(&self) -> bool {
        let Some(case_name) = self.path.file_name().and_then(|name| name.to_str()) else {
            return false;
        };

        match self.meta.topic {
            Topic::BeaconBlock => matches!(
                case_name,
                // Lighthouse fork choice requires finalized roots to be stored blocks.
                "gossip_beacon_block__reject_finalized_checkpoint_not_ancestor"
                    // Lighthouse does not retain consensus-failed parents as seen blocks.
                    | "gossip_beacon_block__ignore_parent_consensus_failed_execution_known"
                    | "gossip_beacon_block__reject_parent_consensus_failed_execution_not_verified"
                    | "gossip_beacon_block__reject_parent_failed_validation"
            ),
            Topic::BeaconAttestation | Topic::BeaconAggregateAndProof => {
                self.has_failed_setup_block()
                    || self.has_unstored_finalized_checkpoint()
                    || self.needs_unfinalized_slot_zero_block(case_name)
            }
            Topic::BlsToExecutionChange => matches!(
                case_name,
                // Historical pre-Capella fixture. Mainnet is already post-Capella, so keep this
                // out of scope instead of adding config-driven fork scheduling to the harness.
                "gossip_bls_to_execution_change__ignore_pre_capella"
            ),
            _ => false,
        }
    }

    fn has_failed_setup_block(&self) -> bool {
        // Lighthouse does not retain consensus-failed blocks as known blocks.
        self.meta.blocks.iter().any(|block| block.failed)
    }

    fn has_unstored_finalized_checkpoint(&self) -> bool {
        // Lighthouse fork choice requires finalized roots to be stored blocks.
        matches!(
            self.meta.finalized_checkpoint,
            Some(FinalizedCheckpoint::Root { .. })
        )
    }

    fn needs_unfinalized_slot_zero_block(&self, case_name: &str) -> bool {
        // These fixtures need a slot-zero block known but not finalized.
        case_name.contains("__accepts_")
    }

    fn initial_anchor(
        &self,
        blocks: &HashMap<String, SignedBeaconBlock<E>>,
    ) -> Result<Option<InitialTestState<E>>, Error> {
        if let Some((index, block)) = self.first_setup_block_matching_state(blocks)? {
            return Ok(Some(InitialTestState {
                state: self.state.clone(),
                block,
                finalized_checkpoint: self.finalized_checkpoint(blocks)?,
                setup_block_index: Some(index),
            }));
        }

        Ok(None)
    }

    fn first_setup_block_matching_state(
        &self,
        blocks: &HashMap<String, SignedBeaconBlock<E>>,
    ) -> Result<Option<(usize, SignedBeaconBlock<E>)>, Error> {
        let Some(setup_block) = self.meta.blocks.first() else {
            return Ok(None);
        };
        let Some(block) = blocks.get(&setup_block.block) else {
            return Ok(None);
        };

        Ok((block.state_root() == self.state_root()?).then_some((0, block.clone())))
    }

    fn finalized_checkpoint(
        &self,
        blocks: &HashMap<String, SignedBeaconBlock<E>>,
    ) -> Result<Option<Checkpoint>, Error> {
        if let Some(checkpoint) = &self.meta.finalized_checkpoint {
            return checkpoint.checkpoint(blocks).map(Some);
        }

        Ok(None)
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

    fn state_root(&self) -> Result<Hash256, Error> {
        let mut state = self.state.clone();
        state.update_tree_hash_cache().map_err(|e| {
            Error::InternalError(format!("unable to compute initial state root: {e:?}"))
        })
    }

    fn current_time_ms(&self, spec: &ChainSpec, genesis_time: u64) -> u64 {
        self.meta.current_time_ms.unwrap_or_else(|| {
            let state_time_ms = self
                .state
                .slot()
                .saturating_sub(spec.genesis_slot)
                .as_u64()
                .saturating_mul(spec.get_slot_duration().as_millis() as u64);
            genesis_time
                .saturating_mul(1_000)
                .saturating_add(state_time_ms)
        })
    }
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
