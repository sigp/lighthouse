use super::*;
use crate::bls_setting::BlsSetting;
use crate::decode::{
    snappy_decode_file, ssz_decode_file, ssz_decode_file_with, ssz_decode_state, yaml_decode_file,
};
use crate::type_name::TypeName;
use ::fork_choice::InvalidationOperation;
use beacon_chain::block_verification_types::LookupBlock;
use beacon_chain::custody_context::NodeCustodyType;
use beacon_chain::partial_data_column_assembler::AssemblyColumn;
use beacon_chain::payload_envelope_verification::EnvelopeSource;
use beacon_chain::proposer_preferences_verification::gossip_verified_proposer_preferences::GossipVerifiedProposerPreferences;
use beacon_chain::slot_clock::{SlotClock, TestingSlotClock};
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use beacon_chain::{BlockError, ChainConfig, NotifyExecutionLayer, PayloadVerificationStatus};
use bls::Signature;
use execution_layer::{PayloadStatusV1, PayloadStatusV1Status};
use lighthouse_network::types::{GossipEncoding, GossipKind};
use lighthouse_network::{Client, GossipTopic, MessageAcceptance, MessageId, PeerId};
use network::{NetworkBeaconProcessor, NetworkMessage, ReprocessAllowance};
use serde::Deserialize;
use ssz::Decode;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use types::{
    AttesterSlashing, BeaconBlock, BeaconState, BlobSchedule, BlockImportSource, ChainSpec,
    Checkpoint, DataColumnSidecar, DataColumnSubnetId, EthSpec, ExecPayload, ForkName,
    ForkVersionDecode, Hash256, PartialDataColumn, PartialDataColumnFulu, PartialDataColumnGloas,
    PartialDataColumnGroupId, PartialDataColumnHeader, PartialDataColumnSidecarFulu,
    PartialDataColumnSidecarGloas, PayloadAttestationMessage, ProposerSlashing,
    SignedAggregateAndProof, SignedAggregateAndProofElectra, SignedAggregateAndProofGloas,
    SignedBeaconBlock, SignedBlsToExecutionChange, SignedContributionAndProof,
    SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope, SignedProposerPreferences,
    SignedVoluntaryExit, SingleAttestation, Slot, SubnetId, SyncCommitteeMessage, SyncSubnetId,
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
#[serde(deny_unknown_fields)]
struct Meta {
    topic: Topic,
    #[serde(default)]
    blocks: Vec<SetupBlock>,
    #[serde(default)]
    finalized_checkpoint: Option<FinalizedCheckpoint>,
    #[serde(default)]
    messages: Vec<MessageMeta>,
    #[serde(default)]
    bls_setting: Option<BlsSetting>,
    /// Fulu partial data column headers the node has already validated before the messages.
    #[serde(default)]
    seen_partial_data_column_headers: Vec<SeenPartialDataColumnHeader>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SeenPartialDataColumnHeader {
    block_root: Hash256,
    header: String,
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
    payload: Option<String>,
    #[serde(default, rename = "pending")]
    pending: bool,
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
    current_time_ms: Option<u64>,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    column_index: Option<u64>,
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
    DataColumnSidecar,
    ExecutionPayloadBid,
    ExecutionPayload,
    PartialDataColumnSidecar,
    PayloadAttestationMessage,
    ProposerPreferences,
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

        let bls_setting = self.meta.bls_setting.unwrap_or_else(|| {
            if self.meta.messages.iter().any(|message| {
                message.expected == ExpectedOutcome::Reject
                    && message.reason.as_ref().is_some_and(|reason| {
                        let reason = reason.to_ascii_lowercase();
                        reason.contains("invalid") && reason.contains("signature")
                    })
            }) {
                // Some Gloas gossip vectors omit `bls_setting: required` even though their
                // expected rejection depends on real signature verification.
                BlsSetting::Required
            } else {
                BlsSetting::Flexible
            }
        });
        bls_setting.check()?;

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
        let current_time_ms = case.current_time_ms(&blocks, &spec)?;
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
        tester.seed_partial_data_column_headers(case)?;
        let finalized_checkpoint = case.finalized_checkpoint(&blocks)?;
        tester.set_finalized_checkpoint(finalized_checkpoint);
        if matches!(
            case.meta.topic,
            Topic::ExecutionPayloadBid | Topic::ProposerPreferences | Topic::ExecutionPayload
        ) {
            tester.block_on_dangerous(tester.harness.chain.recompute_head_at_current_slot())?;
            // Bid fixtures override finalization after producing their block and state files, so
            // replaying the blocks yields a head state whose finalized checkpoint (used by
            // `is_active_builder`) differs from the one the fixture was generated with.
            if case.meta.topic == Topic::ExecutionPayloadBid
                && let Some(checkpoint) = finalized_checkpoint
            {
                tester
                    .harness
                    .chain
                    .canonical_head
                    .testing_set_cached_head_state_finalized_checkpoint(checkpoint);
            }
        }

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
        let spec_synthetic_anchor = match initial_block_index {
            Some(index) => case.has_spec_synthetic_anchor(index, blocks)?,
            None => false,
        };

        let harness_builder = || {
            BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
                .spec(spec.clone())
                .keypairs(vec![])
                .mock_execution_layer()
                .recalculate_fork_times_with_genesis(genesis_time)
                // Default to valid EL responses. Setup blocks with `payload_status` override this
                // during import.
                .mock_execution_layer_all_payloads_valid()
                // Partial data column gossip is only processed when partial columns are enabled.
                .chain_config(ChainConfig {
                    enable_partial_columns: true,
                    ..ChainConfig::default()
                })
                // Partial cells are only stored for custodied columns. Custody every column so
                // accepted fixture cells are observable regardless of their column index.
                .node_custody_type(if case.meta.topic == Topic::PartialDataColumnSidecar {
                    NodeCustodyType::Supernode
                } else {
                    NodeCustodyType::Fullnode
                })
        };

        let harness = if let Some(initial_block_index) = initial_block_index
            && !spec_synthetic_anchor
        {
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
        } else if spec_synthetic_anchor || case.meta.topic.requires_synthetic_anchor() {
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

    fn seed_partial_data_column_headers(&self, case: &GossipValidation<E>) -> Result<(), Error> {
        if case.meta.seen_partial_data_column_headers.is_empty() {
            return Ok(());
        }
        let assembler = self
            .harness
            .chain
            .data_availability_checker
            .partial_assembler()
            .ok_or_else(|| Error::InternalError("partial columns are disabled".into()))?;
        for seen in &case.meta.seen_partial_data_column_headers {
            let header: PartialDataColumnHeader<E> =
                ssz_decode_file(&case.path.join(format!("{}.ssz_snappy", seen.header)))?;
            assembler.init(seen.block_root, Arc::new(header));
        }
        Ok(())
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
            if setup_block.failed || setup_block.pending {
                continue;
            }
            let block = blocks.get(&setup_block.block).ok_or_else(|| {
                Error::FailedToParseTest(format!("unknown block file {}", setup_block.block))
            })?;
            // For Gloas setup blocks with a payload, `payload_status` describes the payload
            // envelope's execution status rather than the block's.
            let block_payload_status = if setup_block.payload.is_some() {
                None
            } else {
                setup_block.payload_status
            };
            if initial_block_index != Some(index) {
                let block_time_ms = slot_time_ms(block.slot(), &self.spec)?;
                if block_time_ms > self.current_time_ms {
                    self.set_time_ms(block_time_ms)?;
                }
                self.import_setup_block(block.clone(), block_payload_status)?;
            }
            if let Some(payload) = setup_block.payload.as_deref() {
                if case.meta.topic == Topic::ExecutionPayloadBid {
                    self.import_setup_payload_for_bid(&case.path, block, payload)?;
                } else {
                    self.import_setup_payload(
                        &case.path,
                        block,
                        payload,
                        setup_block.payload_status,
                    )?;
                }
            }
        }

        self.set_time_ms(self.current_time_ms)?;

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
                return self.process_beacon_block(path, message_meta, message_id, peer_id);
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
                fork_name,
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
            Topic::DataColumnSidecar => self.process_data_column_sidecar(
                path,
                message_meta,
                fork_name,
                message_id.clone(),
                peer_id,
            )?,
            Topic::PartialDataColumnSidecar => {
                return self.process_partial_data_column_sidecar(
                    path,
                    message_meta,
                    fork_name,
                    peer_id,
                );
            }
            Topic::PayloadAttestationMessage => self.process_payload_attestation_message(
                path,
                message_meta,
                message_id.clone(),
                peer_id,
            )?,
            Topic::ExecutionPayload => {
                return self.process_execution_payload_envelope(
                    path,
                    message_meta,
                    message_id,
                    peer_id,
                );
            }
            Topic::ExecutionPayloadBid => {
                if let Some(acceptance) = self.process_execution_payload_bid_message(
                    path,
                    message_meta,
                    fork_name,
                    message_id.clone(),
                    peer_id,
                )? {
                    return Ok(acceptance);
                }
            }
            Topic::ProposerPreferences => {
                self.process_proposer_preferences(path, message_meta, message_id.clone(), peer_id)?
            }
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
    ) -> Result<MessageAcceptance, Error> {
        let bytes = snappy_decode_file(&path.join(format!("{}.ssz_snappy", message_meta.message)))?;
        // The network rejects malformed SSZ, including oversized lists, before gossip processing.
        let Ok(block) = SignedBeaconBlock::from_ssz_bytes(&bytes, &self.spec) else {
            return Ok(MessageAcceptance::Reject);
        };
        let time_ms = self.message_time_ms(message_meta);
        let seen_duration = self.set_time_ms(time_ms)?;

        let process_fn = Box::pin(self.network_beacon_processor.clone().process_gossip_block(
            message_id.clone(),
            peer_id,
            Client::default(),
            Arc::new(block),
            self.network_beacon_processor.duplicate_cache.clone(),
            self.network_beacon_processor.invalid_block_storage.clone(),
            seen_duration,
        ));

        self.block_on_dangerous(process_fn)?;
        self.validation_result(&message_id, &peer_id)
    }

    fn process_execution_payload_envelope(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
        message_id: MessageId,
        peer_id: PeerId,
    ) -> Result<MessageAcceptance, Error> {
        let bytes = snappy_decode_file(&path.join(format!("{}.ssz_snappy", message_meta.message)))?;
        // The network rejects malformed SSZ, including oversized lists, before gossip processing.
        let Ok(envelope) = SignedExecutionPayloadEnvelope::<E>::from_ssz_bytes(&bytes) else {
            return Ok(MessageAcceptance::Reject);
        };
        let seen_duration = self.set_message_time(message_meta)?;

        self.block_on_dangerous(
            self.network_beacon_processor
                .clone()
                .process_gossip_execution_payload_envelope(
                    message_id.clone(),
                    peer_id,
                    Arc::new(envelope),
                    seen_duration,
                ),
        )?;
        self.validation_result(&message_id, &peer_id)
    }

    fn process_data_column_sidecar(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
        fork_name: ForkName,
        message_id: MessageId,
        peer_id: PeerId,
    ) -> Result<(), Error> {
        let column_sidecar = ssz_decode_file_with(
            &path.join(format!("{}.ssz_snappy", message_meta.message)),
            |bytes| DataColumnSidecar::<E>::from_ssz_bytes_for_fork(bytes, fork_name),
        )?;
        let subnet_id = DataColumnSubnetId::new(message_meta.subnet_id.ok_or_else(|| {
            Error::FailedToParseTest("missing data_column_sidecar subnet_id".into())
        })?);
        let seen_duration = self.set_message_time(message_meta)?;

        self.block_on_dangerous(
            self.network_beacon_processor
                .clone()
                .process_gossip_data_column_sidecar(
                    message_id,
                    peer_id,
                    subnet_id,
                    Arc::new(column_sidecar),
                    seen_duration,
                    false,
                ),
        )?;
        Ok(())
    }

    fn process_partial_data_column_sidecar(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
        fork_name: ForkName,
        peer_id: PeerId,
    ) -> Result<MessageAcceptance, Error> {
        let group_id_file = message_meta.group_id.as_deref().ok_or_else(|| {
            Error::FailedToParseTest("missing partial_data_column_sidecar group_id".into())
        })?;
        let column_index = message_meta.column_index.ok_or_else(|| {
            Error::FailedToParseTest("missing partial_data_column_sidecar column_index".into())
        })?;
        let group_id_path = path.join(format!("{group_id_file}.ssz_snappy"));
        let bytes = snappy_decode_file(&path.join(format!("{}.ssz_snappy", message_meta.message)))?;
        // The network rejects malformed SSZ, including oversized lists, before gossip processing.
        let column = if fork_name.gloas_enabled() {
            let group_id: PartialDataColumnGroupId = ssz_decode_file(&group_id_path)?;
            let Ok(sidecar) = PartialDataColumnSidecarGloas::<E>::from_ssz_bytes(&bytes) else {
                return Ok(MessageAcceptance::Reject);
            };
            PartialDataColumn::from(PartialDataColumnGloas {
                block_root: group_id.beacon_block_root,
                slot: group_id.slot,
                index: column_index,
                sidecar,
            })
        } else {
            // The Fulu group id is a container holding only the block root.
            let block_root: Hash256 = ssz_decode_file(&group_id_path)?;
            let Ok(sidecar) = PartialDataColumnSidecarFulu::<E>::from_ssz_bytes(&bytes) else {
                return Ok(MessageAcceptance::Reject);
            };
            PartialDataColumn::from(PartialDataColumnFulu {
                block_root,
                index: column_index,
                sidecar,
            })
        };
        let seen_duration = self.set_message_time(message_meta)?;
        // Partial messages are spec'd with one column per subnet, so the subnet is the index.
        let topic = GossipTopic::new(
            GossipKind::DataColumnSidecar(DataColumnSubnetId::new(column_index)),
            GossipEncoding::default(),
            [0; 4],
        );

        self.block_on_dangerous(
            self.network_beacon_processor
                .process_gossip_partial_data_column_sidecar(
                    peer_id,
                    Box::new(column.clone()),
                    seen_duration,
                    topic,
                ),
        )?;

        // Partial messages have no message id or validation result. A rejection is reported to
        // gossipsub as a partial validation failure; otherwise the message was accepted if its
        // contents were stored, and ignored if not.
        let mut network_rx = self
            .network_rx
            .lock()
            .map_err(|_| Error::InternalError("network receiver lock poisoned".into()))?;
        while let Ok(network_message) = network_rx.try_recv() {
            if let NetworkMessage::PartialValidationFailure {
                propagation_source, ..
            } = network_message
                && propagation_source == peer_id
            {
                return Ok(MessageAcceptance::Reject);
            }
        }
        let accepted = match &column {
            PartialDataColumn::Gloas(_) => self.partial_cells_cached_gloas(&column),
            PartialDataColumn::Fulu(fulu) => self.partial_stored_fulu(fulu),
        };
        Ok(if accepted {
            MessageAcceptance::Accept
        } else {
            MessageAcceptance::Ignore
        })
    }

    /// Whether every cell of a non-empty Gloas partial is now in the pending payload cache.
    fn partial_cells_cached_gloas(&self, column: &PartialDataColumn<E>) -> bool {
        column.sidecar().cells_present_bitmap().num_set_bits() > 0
            && matches!(
                self.harness
                    .chain
                    .pending_payload_cache
                    .missing_cells_for_partial_column_sidecar(column.to_ref()),
                Ok(None)
            )
    }

    /// Whether the Fulu partial carries a header or cells, and the partial assembler now holds its
    /// header (if any) and all of its cells (if any).
    fn partial_stored_fulu(&self, column: &PartialDataColumnFulu<E>) -> bool {
        if column.sidecar.header.as_ref().is_none()
            && column.sidecar.cells_present_bitmap.num_set_bits() == 0
        {
            return false;
        }
        let Some(assembler) = self
            .harness
            .chain
            .data_availability_checker
            .partial_assembler()
        else {
            return false;
        };
        let header_stored = column.sidecar.header.as_ref().is_none_or(|header| {
            assembler
                .get_header(&column.block_root)
                .is_some_and(|stored| *stored == *header)
        });
        let present = &column.sidecar.cells_present_bitmap;
        let cells_stored = present.num_set_bits() == 0
            || match assembler.get_partial(&column.block_root, column.index) {
                Some(AssemblyColumn::Complete(_)) => true,
                Some(AssemblyColumn::Incomplete(stored)) => {
                    let stored_bitmap = stored.sidecar().cells_present_bitmap();
                    (0..present.len()).all(|i| {
                        !present.get(i).unwrap_or(false) || stored_bitmap.get(i).unwrap_or(false)
                    })
                }
                None => false,
            };
        header_stored && cells_stored
    }

    fn process_execution_payload_bid_message(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
        fork_name: ForkName,
        message_id: MessageId,
        peer_id: PeerId,
    ) -> Result<Option<MessageAcceptance>, Error> {
        // Bid fixtures replay proposer preferences and the parent's payload envelope as setup
        // messages. These are seeded directly into the caches the bid verifier reads and reported
        // as accepted without gossip validation: the parent payload has already been imported
        // during setup, so the production envelope path would ignore it as already known. Their
        // own validation is covered by the `gossip_proposer_preferences` and
        // `gossip_execution_payload_envelope` suites.
        if message_meta.message.starts_with("proposer_preferences_") {
            let preferences: SignedProposerPreferences =
                ssz_decode_file(&path.join(format!("{}.ssz_snappy", message_meta.message)))?;
            self.set_message_time(message_meta)?;
            let verified_preferences = GossipVerifiedProposerPreferences {
                signed_preferences: Arc::new(preferences),
            };
            self.harness
                .chain
                .gossip_verified_proposer_preferences_cache
                .insert_seen_validator(&verified_preferences);
            self.harness
                .chain
                .gossip_verified_proposer_preferences_cache
                .insert_preferences(verified_preferences);
            return Ok(Some(MessageAcceptance::Accept));
        }
        if message_meta
            .message
            .starts_with("execution_payload_envelope_")
        {
            let envelope: SignedExecutionPayloadEnvelope<E> =
                ssz_decode_file(&path.join(format!("{}.ssz_snappy", message_meta.message)))?;
            self.set_message_time(message_meta)?;
            let payload = &envelope.message.payload;
            self.harness
                .chain
                .observed_execution_payloads
                .insert_for_testing(payload.block_hash, payload.gas_limit);
            return Ok(Some(MessageAcceptance::Accept));
        }
        if !message_meta.message.starts_with("execution_payload_bid_") {
            return Err(Error::FailedToParseTest(format!(
                "unsupported execution payload bid fixture message {}",
                message_meta.message
            )));
        }

        let bid = ssz_decode_file_with(
            &path.join(format!("{}.ssz_snappy", message_meta.message)),
            |bytes| SignedExecutionPayloadBid::<E>::from_ssz_bytes_by_fork(bytes, fork_name),
        )?;
        self.set_message_time(message_meta)?;
        self.network_beacon_processor
            .process_gossip_execution_payload_bid(message_id, peer_id, Arc::new(bid));
        Ok(None)
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
        fork_name: ForkName,
        message_id: MessageId,
        peer_id: PeerId,
    ) -> Result<(), Error> {
        let ssz_path = path.join(format!("{}.ssz_snappy", message_meta.message));
        let aggregate = if fork_name.gloas_enabled() {
            ssz_decode_file::<SignedAggregateAndProofGloas<E>>(&ssz_path)
                .map(SignedAggregateAndProof::Gloas)?
        } else {
            ssz_decode_file::<SignedAggregateAndProofElectra<E>>(&ssz_path)
                .map(SignedAggregateAndProof::Electra)?
        };
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

    fn process_proposer_preferences(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
        message_id: MessageId,
        peer_id: PeerId,
    ) -> Result<(), Error> {
        let proposer_preferences: SignedProposerPreferences =
            ssz_decode_file(&path.join(format!("{}.ssz_snappy", message_meta.message)))?;
        self.set_message_time(message_meta)?;

        self.network_beacon_processor
            .clone()
            .process_gossip_proposer_preferences(
                message_id,
                peer_id,
                Arc::new(proposer_preferences),
            );
        Ok(())
    }

    fn process_payload_attestation_message(
        &self,
        path: &Path,
        message_meta: &MessageMeta,
        message_id: MessageId,
        peer_id: PeerId,
    ) -> Result<(), Error> {
        let payload_attestation_message: PayloadAttestationMessage =
            ssz_decode_file(&path.join(format!("{}.ssz_snappy", message_meta.message)))?;
        self.set_message_time(message_meta)?;

        self.network_beacon_processor
            .clone()
            .process_gossip_payload_attestation(
                message_id,
                peer_id,
                Box::new(payload_attestation_message),
                ReprocessAllowance::None,
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
        let time_ms = self.message_time_ms(message_meta);
        self.set_time_ms(time_ms)
    }

    fn message_time_ms(&self, message_meta: &MessageMeta) -> u64 {
        message_meta.current_time_ms.unwrap_or(self.current_time_ms)
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
            LookupBlock::new(block_root, Arc::new(block.clone())),
            NotifyExecutionLayer::Yes,
            BlockImportSource::Lookup,
            || Ok(()),
        ))?;
        self.configure_payload_status_for_default();

        match result {
            Ok(_) => {
                if payload_status == Some(PayloadStatus::Invalidated) {
                    // The block has been imported optimistically. Mark its payload invalid in fork
                    // choice so descendants observe an invalid execution parent.
                    let head_hash = block
                        .message()
                        .execution_payload()
                        .map_err(|e| {
                            Error::InternalError(format!(
                                "setup block {block_root:?} has no execution payload: {e:?}"
                            ))
                        })?
                        .block_hash();
                    self.block_on_dangerous(self.harness.chain.process_invalid_execution_payload(
                        &InvalidationOperation::InvalidateOne { head_hash },
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

    fn import_setup_payload_for_bid(
        &self,
        path: &Path,
        block: &SignedBeaconBlock<E>,
        payload: &str,
    ) -> Result<(), Error> {
        let envelope: SignedExecutionPayloadEnvelope<E> =
            ssz_decode_file(&path.join(format!("{payload}.ssz_snappy")))?;
        let block_root = envelope.beacon_block_root();
        if block.canonical_root() != block_root {
            return Err(Error::FailedToParseTest(format!(
                "setup payload references block {block_root:?}, expected {:?}",
                block.canonical_root()
            )));
        }

        let execution_payload = &envelope.message.payload;
        // Only replayed envelope messages populate the observed payload cache, which lets
        // `ignore_parent_block_hash_unknown` import a parent payload whose hash is not yet known.
        self.harness
            .chain
            .store
            .put_payload_envelope(&block_root, &envelope)
            .map_err(|e| {
                Error::InternalError(format!(
                    "failed to store setup payload for block {block_root:?}: {e:?}"
                ))
            })?;
        self.harness
            .chain
            .canonical_head
            .fork_choice_write_lock()
            .on_payload_envelope_received(
                block_root,
                PayloadVerificationStatus::Verified,
                execution_payload.block_hash,
            )
            .map_err(|e| {
                Error::InternalError(format!(
                    "failed to mark setup payload for block {block_root:?} as received: {e:?}"
                ))
            })?;
        // Setup payloads are treated as valid without executing them in the mock EL.
        if let Some(mock_execution_layer) = self.harness.mock_execution_layer.as_ref() {
            let block_hash = execution_payload.block_hash;
            mock_execution_layer.server.set_fcu_payload_status(
                block_hash,
                PayloadStatusV1 {
                    status: PayloadStatusV1Status::Valid,
                    latest_valid_hash: Some(block_hash),
                    validation_error: None,
                    inclusion_list_satisfied: None,
                },
            );
        }
        Ok(())
    }

    fn import_setup_payload(
        &self,
        path: &Path,
        block: &SignedBeaconBlock<E>,
        payload: &str,
        payload_status: Option<PayloadStatus>,
    ) -> Result<(), Error> {
        let envelope: SignedExecutionPayloadEnvelope<E> =
            ssz_decode_file(&path.join(format!("{payload}.ssz_snappy")))?;
        let block_root = envelope.beacon_block_root();
        if block.canonical_root() != block_root {
            return Err(Error::FailedToParseTest(format!(
                "setup payload references block {block_root:?}, expected {:?}",
                block.canonical_root()
            )));
        }
        let payload_block_hash = envelope.message.payload.block_hash;

        let verified_envelope = self
            .block_on_dangerous(
                self.harness
                    .chain
                    .clone()
                    .verify_envelope_for_gossip(Arc::new(envelope), EnvelopeSource::Gossip),
            )?
            .map_err(|e| {
                Error::InternalError(format!(
                    "setup payload for block {block_root:?} failed gossip verification: {e:?}"
                ))
            })?;

        // Configure the mock EL for this setup payload only, then restore the default before
        // validating gossip messages.
        if let Some(mock_execution_layer) = self.harness.mock_execution_layer.as_ref()
            && matches!(
                payload_status,
                Some(PayloadStatus::NotValidated) | Some(PayloadStatus::Invalidated)
            )
        {
            mock_execution_layer.server.all_payloads_syncing(true);
        }
        let result =
            self.block_on_dangerous(self.harness.chain.process_execution_payload_envelope(
                block_root,
                verified_envelope,
                NotifyExecutionLayer::Yes,
                BlockImportSource::Lookup,
                || Ok(()),
            ))?;
        self.configure_payload_status_for_default();
        result.map_err(|e| {
            Error::InternalError(format!(
                "setup payload for block {block_root:?} failed import: {e:?}"
            ))
        })?;

        if payload_status == Some(PayloadStatus::Invalidated) {
            // The payload has been imported optimistically. Mark it invalid in fork choice.
            self.block_on_dangerous(self.harness.chain.process_invalid_execution_payload(
                &InvalidationOperation::InvalidateOne {
                    head_hash: payload_block_hash,
                },
            ))?
            .map_err(|e| {
                Error::InternalError(format!(
                    "setup payload for block {block_root:?} invalidation failed: {e:?}"
                ))
            })?;
        }

        Ok(())
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
                    inclusion_list_satisfied: None,
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
            // These messages arrive exactly `MAXIMUM_GOSSIP_CLOCK_DISPARITY` after the previous
            // epoch window closes. The spec's window is inclusive at that instant, while
            // Lighthouse's slot-based past tolerance is exclusive, so they are ignored.
            "accepts_first_slot_when_epoch_window_closes",
            "accepts_last_slot_when_epoch_window_closes",
        ];
        const IGNORED_EXECUTION_PAYLOAD_ENVELOPE_CASES: &[&str] = &[
            // Lighthouse does not retain consensus-invalid blocks, so the harness cannot construct
            // the known-invalid block status required by this vector.
            "gossip_execution_payload_envelope__reject_block_failed_validation",
        ];
        const IGNORED_EXECUTION_PAYLOAD_BID_CASES: &[&str] = &[
            // Advancing the parent state across an epoch for every gossip bid would put epoch
            // processing on the gossip hot path. Keep this skipped pending a caching strategy.
            "gossip_execution_payload_bid__valid_requires_state_advanced_across_epoch",
        ];
        const IGNORED_PAYLOAD_ATTESTATION_CASES: &[&str] = &[
            // Lighthouse does not retain a status that distinguishes a consensus-invalid block
            // from an unseen block, so both cases are ignored as an unknown head block.
            "gossip_payload_attestation_message__reject_block_failed_validation",
        ];
        // Fulu only: the Gloas suite has no equivalent of these cases.
        const IGNORED_PARTIAL_DATA_COLUMN_CASES: &[&str] = &[
            // Lighthouse does not retain consensus-invalid blocks, so the harness cannot construct
            // the failed parent required by this vector.
            "gossip_partial_data_column_sidecar__reject_parent_failed_validation",
            // The fixture moves the clock backwards after caching a header. Lighthouse validates
            // the header's slot once, when it is cached, and time never moves backwards in
            // practice, so re-checking it for every cells-only message buys nothing.
            "gossip_partial_data_column_sidecar__ignore_cells_with_cached_header_future_slot",
            // The fixture seeds a cached header at or before the finalized slot. Lighthouse prunes
            // cached headers once their epoch is finalized, so this state only exists briefly
            // between finalization and the next maintenance run.
            "gossip_partial_data_column_sidecar__ignore_cells_with_cached_header_not_later_than_finalized_slot",
            // Fork choice hides blocks that do not descend from the finalized checkpoint, so a
            // stored parent on a conflicting fork looks unknown and the message is ignored with a
            // parent lookup. The lookup itself rejects the parent, so a REJECT here buys nothing.
            "gossip_partial_data_column_sidecar__reject_non_ancestor_finalized_checkpoint",
        ];
        const IGNORED_DATA_COLUMN_CASES: &[&str] = &[
            // Lighthouse does not retain a status that distinguishes a consensus-invalid block
            // from an unseen block, so both cases are ignored as an unknown block root.
            "gossip_data_column_sidecar__reject_block_failed_validation",
            // Fulu only. Lighthouse does not retain consensus-invalid blocks, so the harness cannot
            // construct the failed parent required by this vector.
            "gossip_data_column_sidecar__reject_parent_failed_validation",
            // Fulu only. Fork choice hides blocks that do not descend from the finalized
            // checkpoint, so a stored parent on a conflicting fork looks unknown and the column is
            // ignored with a parent lookup. The lookup itself rejects the parent.
            "gossip_data_column_sidecar__reject_non_ancestor_finalized_checkpoint",
        ];
        let Some(case_name) = self.path.file_name().and_then(|name| name.to_str()) else {
            return false;
        };

        match self.meta.topic {
            Topic::BeaconBlock => IGNORED_BEACON_BLOCK_CASES.contains(&case_name),
            Topic::BeaconAttestation | Topic::BeaconAggregateAndProof => {
                // Lighthouse does not retain consensus-invalid blocks, so vectors with a failed
                // setup block cannot be constructed through the production import path.
                self.meta.blocks.iter().any(|block| block.failed)
                    || UNSUPPORTED_TIMING_BOUNDARY_CASES
                        .iter()
                        .any(|suffix| case_name.ends_with(suffix))
            }
            Topic::ExecutionPayload => {
                IGNORED_EXECUTION_PAYLOAD_ENVELOPE_CASES.contains(&case_name)
            }
            Topic::ExecutionPayloadBid => IGNORED_EXECUTION_PAYLOAD_BID_CASES.contains(&case_name),
            Topic::PayloadAttestationMessage => {
                IGNORED_PAYLOAD_ATTESTATION_CASES.contains(&case_name)
            }
            Topic::DataColumnSidecar => IGNORED_DATA_COLUMN_CASES.contains(&case_name),
            Topic::PartialDataColumnSidecar => {
                self.path.to_string_lossy().contains("/fulu/")
                    && IGNORED_PARTIAL_DATA_COLUMN_CASES.contains(&case_name)
            }
            _ => false,
        }
    }

    /// The tests advance the state to the anchor block's slot without applying the block, so the
    /// state's `latest_block_header` still points to an earlier block.
    fn has_spec_synthetic_anchor(
        &self,
        index: usize,
        blocks: &HashMap<String, SignedBeaconBlock<E>>,
    ) -> Result<bool, Error> {
        let Some(block) = self
            .meta
            .blocks
            .get(index)
            .and_then(|setup_block| blocks.get(&setup_block.block))
        else {
            return Ok(false);
        };
        let mut state = self.state.clone();
        let state_root = state
            .update_tree_hash_cache()
            .map_err(|error| Error::InternalError(format!("unable to hash state: {error:?}")))?;
        Ok(block.slot() == state.slot()
            && block.canonical_root() != state.get_latest_block_root(state_root))
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

    /// The start of the latest slot of the state and the setup blocks.
    fn current_time_ms(
        &self,
        blocks: &HashMap<String, SignedBeaconBlock<E>>,
        spec: &ChainSpec,
    ) -> Result<u64, Error> {
        let slot = self
            .meta
            .blocks
            .iter()
            .filter_map(|setup_block| blocks.get(&setup_block.block))
            .map(|block| block.slot())
            .fold(self.state.slot(), Slot::max);
        slot_time_ms(slot, spec)
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

    /// Load setup and finalized blocks, leaving gossip messages to be decoded during validation.
    fn load_beacon_blocks(
        &self,
        spec: &ChainSpec,
    ) -> Result<HashMap<String, SignedBeaconBlock<E>>, Error> {
        let mut block_names = HashSet::new();
        block_names.extend(self.meta.blocks.iter().map(|block| block.block.clone()));
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
