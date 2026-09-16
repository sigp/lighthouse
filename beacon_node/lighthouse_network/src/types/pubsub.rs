//! Handles the encoding and decoding of pubsub messages.

use super::partial::{PARTIAL_COLUMNS_VERSION_BYTE_FULU, PARTIAL_COLUMNS_VERSION_BYTE_GLOAS};
use crate::types::{GossipEncoding, GossipKind, GossipTopic};
use libp2p::gossipsub::{DataTransform, Message, RawMessage, TopicHash};
use snap::raw::{Decoder, Encoder, decompress_len};
use ssz::{Decode, Encode};
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use types::{
    AttesterSlashing, AttesterSlashingBase, AttesterSlashingElectra, AttesterSlashingGloas,
    CellBitmap, DataColumnSidecar, DataColumnSubnetId, EthSpec, ForkContext, ForkName, Hash256,
    LightClientFinalityUpdate, LightClientOptimisticUpdate, PartialDataColumn,
    PartialDataColumnFulu, PartialDataColumnGloas, PartialDataColumnGroupId,
    PartialDataColumnHeader, PartialDataColumnSidecarFulu, PartialDataColumnSidecarGloas,
    PayloadAttestationMessage, ProposerSlashing, SignedAggregateAndProof,
    SignedAggregateAndProofBase, SignedAggregateAndProofElectra, SignedAggregateAndProofGloas,
    SignedBeaconBlock, SignedBeaconBlockAltair, SignedBeaconBlockBase, SignedBeaconBlockBellatrix,
    SignedBeaconBlockCapella, SignedBeaconBlockDeneb, SignedBeaconBlockElectra,
    SignedBeaconBlockFulu, SignedBeaconBlockGloas, SignedBeaconBlockHeze,
    SignedBlsToExecutionChange, SignedContributionAndProof, SignedExecutionPayloadBid,
    SignedExecutionPayloadEnvelope, SignedProposerPreferences, SignedVoluntaryExit,
    SingleAttestation, SubnetId, SyncCommitteeMessage, SyncSubnetId,
    execution::SignedExecutionProofEnvelope,
};

#[derive(Debug, Clone, PartialEq)]
pub enum PubsubMessage<E: EthSpec> {
    /// Gossipsub message providing notification of a new block.
    BeaconBlock(Arc<SignedBeaconBlock<E>>),
    /// Gossipsub message providing notification of a [`DataColumnSidecar`] along with the subnet id where it was received.
    DataColumnSidecar(Box<(DataColumnSubnetId, Arc<DataColumnSidecar<E>>)>),
    /// Gossipsub message providing notification of a Aggregate attestation and associated proof.
    AggregateAndProofAttestation(Box<SignedAggregateAndProof<E>>),
    /// Gossipsub message providing notification of a `SingleAttestation` with its subnet id.
    Attestation(Box<(SubnetId, SingleAttestation)>),
    /// Gossipsub message providing notification of a voluntary exit.
    VoluntaryExit(Box<SignedVoluntaryExit>),
    /// Gossipsub message providing notification of a new proposer slashing.
    ProposerSlashing(Box<ProposerSlashing>),
    /// Gossipsub message providing notification of a new attester slashing.
    AttesterSlashing(Box<AttesterSlashing<E>>),
    /// Gossipsub message providing notification of partially aggregated sync committee signatures.
    SignedContributionAndProof(Box<SignedContributionAndProof<E>>),
    /// Gossipsub message providing notification of unaggregated sync committee signatures with its subnet id.
    SyncCommitteeMessage(Box<(SyncSubnetId, SyncCommitteeMessage)>),
    /// Gossipsub message for BLS to execution change messages.
    BlsToExecutionChange(Box<SignedBlsToExecutionChange>),
    /// Gossipsub message providing notification of a signed execution payload envelope.
    ExecutionPayload(Box<SignedExecutionPayloadEnvelope<E>>),
    /// Gossipsub message providing notification of a payload attestation message.
    PayloadAttestation(Box<PayloadAttestationMessage>),
    /// Gossipsub message providing notification of a signed execution payload bid.
    ExecutionPayloadBid(Box<SignedExecutionPayloadBid<E>>),
    /// Gossipsub message providing notification of signed proposer preferences.
    ProposerPreferences(Arc<SignedProposerPreferences>),
    /// Gossipsub message providing notification of an EIP-8025 execution proof.
    ExecutionProof(Arc<SignedExecutionProofEnvelope>),
    /// Gossipsub message providing notification of a light client finality update.
    LightClientFinalityUpdate(Box<LightClientFinalityUpdate<E>>),
    /// Gossipsub message providing notification of a light client optimistic update.
    LightClientOptimisticUpdate(Box<LightClientOptimisticUpdate<E>>),
}

/// A message published via the partial gossipsub protocol.
#[derive(Debug, Clone, PartialEq)]
pub enum PubsubPartialMessage<E: EthSpec> {
    /// A partial data column sidecar from the Fulu fork.
    DataColumnFulu {
        /// The column to publish. Libp2p will cache it and treat it as the data to send if any peer
        /// asks for data within it.
        column: Arc<PartialDataColumnFulu<E>>,
        /// The cells we are requesting. Usually, this will be all-ones, as we need all cells.
        /// However, while get_blobs is still in progress, blobs we expect from the EL should not be
        /// requested to conserve bandwidth.
        request_cells: CellBitmap<E>,
        /// The header associated with the column above. This is set separately here, as the column
        /// to be published does not contain the header - it is stored without.
        header: Arc<PartialDataColumnHeader<E>>,
    },
    /// A partial data column sidecar from the Gloas fork.
    DataColumnGloas {
        column: Arc<PartialDataColumnGloas<E>>,
        request_cells: CellBitmap<E>,
    },
}

// Implements the `DataTransform` trait of gossipsub to employ snappy compression
pub struct SnappyTransform {
    /// Sets the maximum size we allow gossipsub messages to decompress to.
    max_uncompressed_len: usize,
    /// Sets the maximum size we allow for compressed gossipsub message data.
    max_compressed_len: usize,
}

impl SnappyTransform {
    pub fn new(max_uncompressed_len: usize, max_compressed_len: usize) -> Self {
        SnappyTransform {
            max_uncompressed_len,
            max_compressed_len,
        }
    }
}

impl DataTransform for SnappyTransform {
    // Provides the snappy decompression from RawGossipsubMessages
    fn inbound_transform(&self, raw_message: RawMessage) -> Result<Message, std::io::Error> {
        // first check the size of the compressed payload
        if raw_message.data.len() > self.max_compressed_len {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "ssz_snappy encoded data > max_compressed_len",
            ));
        }
        // check the length of the uncompressed bytes
        let len = decompress_len(&raw_message.data)?;
        if len > self.max_uncompressed_len {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "ssz_snappy decoded data > MAX_PAYLOAD_SIZE",
            ));
        }

        let mut decoder = Decoder::new();
        let decompressed_data = decoder.decompress_vec(&raw_message.data)?;

        // Build the GossipsubMessage struct
        Ok(Message {
            source: raw_message.source,
            data: decompressed_data,
            sequence_number: raw_message.sequence_number,
            topic: raw_message.topic,
        })
    }

    /// Provides the snappy compression logic to gossipsub.
    fn outbound_transform(
        &self,
        _topic: &TopicHash,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, std::io::Error> {
        // Currently we are not employing topic-based compression. Everything is expected to be
        // snappy compressed.
        if data.len() > self.max_uncompressed_len {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "ssz_snappy Encoded data > MAX_PAYLOAD_SIZE",
            ));
        }
        let mut encoder = Encoder::new();
        encoder.compress_vec(&data).map_err(Into::into)
    }
}

impl<E: EthSpec> PubsubMessage<E> {
    /// Returns the topics that each pubsub message will be sent across, given a supported
    /// gossipsub encoding and fork version.
    pub fn topics(&self, encoding: GossipEncoding, fork_version: [u8; 4]) -> Vec<GossipTopic> {
        vec![GossipTopic::new(self.kind(), encoding, fork_version)]
    }

    /// Returns the kind of gossipsub topic associated with the message.
    pub fn kind(&self) -> GossipKind {
        match self {
            PubsubMessage::BeaconBlock(_) => GossipKind::BeaconBlock,
            PubsubMessage::DataColumnSidecar(column_sidecar_data) => {
                GossipKind::DataColumnSidecar(column_sidecar_data.0)
            }
            PubsubMessage::AggregateAndProofAttestation(_) => GossipKind::BeaconAggregateAndProof,
            PubsubMessage::Attestation(attestation_data) => {
                GossipKind::Attestation(attestation_data.0)
            }
            PubsubMessage::VoluntaryExit(_) => GossipKind::VoluntaryExit,
            PubsubMessage::ProposerSlashing(_) => GossipKind::ProposerSlashing,
            PubsubMessage::AttesterSlashing(_) => GossipKind::AttesterSlashing,
            PubsubMessage::SignedContributionAndProof(_) => GossipKind::SignedContributionAndProof,
            PubsubMessage::SyncCommitteeMessage(data) => GossipKind::SyncCommitteeMessage(data.0),
            PubsubMessage::BlsToExecutionChange(_) => GossipKind::BlsToExecutionChange,
            PubsubMessage::ExecutionPayload(_) => GossipKind::ExecutionPayload,
            PubsubMessage::PayloadAttestation(_) => GossipKind::PayloadAttestation,
            PubsubMessage::ExecutionPayloadBid(_) => GossipKind::ExecutionPayloadBid,
            PubsubMessage::ProposerPreferences(_) => GossipKind::ProposerPreferences,
            PubsubMessage::ExecutionProof(_) => GossipKind::ExecutionProof,
            PubsubMessage::LightClientFinalityUpdate(_) => GossipKind::LightClientFinalityUpdate,
            PubsubMessage::LightClientOptimisticUpdate(_) => {
                GossipKind::LightClientOptimisticUpdate
            }
        }
    }

    /// This decodes `data` into a `PubsubMessage` given a topic.
    /* Note: This is assuming we are not hashing topics. If we choose to hash topics, these will
     * need to be modified.
     */
    pub fn decode(
        topic: &TopicHash,
        data: &[u8],
        fork_context: &ForkContext,
    ) -> Result<Self, String> {
        match GossipTopic::decode(topic.as_str()) {
            Err(_) => Err(format!("Unknown gossipsub topic: {:?}", topic)),
            Ok(gossip_topic) => {
                // All topics are currently expected to be compressed and decompressed with snappy.
                // This is done in the `SnappyTransform` struct.
                // Therefore compression has already been handled for us by the time we are
                // decoding the objects here.

                // the ssz decoders
                match gossip_topic.kind() {
                    GossipKind::BeaconAggregateAndProof => {
                        let signed_aggregate_and_proof = match fork_context
                            .get_fork_from_context_bytes(gossip_topic.fork_digest)
                        {
                            Some(&fork_name) => {
                                // [Modified in Gloas:EIP7688] Gloas and Electra produce the same
                                // SSZ bytes but different hash tree roots, so the variant must be
                                // chosen by fork.
                                if fork_name.gloas_enabled() {
                                    if data.len() > E::max_signed_aggregate_and_proof_size() {
                                        return Err(format!(
                                            "SignedAggregateAndProof size {} exceeds MAX_SIGNED_AGGREGATE_AND_PROOF_SIZE {}",
                                            data.len(),
                                            E::max_signed_aggregate_and_proof_size()
                                        ));
                                    }
                                    SignedAggregateAndProof::Gloas(
                                        SignedAggregateAndProofGloas::from_ssz_bytes(data)
                                            .map_err(|e| format!("{:?}", e))?,
                                    )
                                } else if fork_name.electra_enabled() {
                                    SignedAggregateAndProof::Electra(
                                        SignedAggregateAndProofElectra::from_ssz_bytes(data)
                                            .map_err(|e| format!("{:?}", e))?,
                                    )
                                } else {
                                    SignedAggregateAndProof::Base(
                                        SignedAggregateAndProofBase::from_ssz_bytes(data)
                                            .map_err(|e| format!("{:?}", e))?,
                                    )
                                }
                            }
                            None => {
                                return Err(format!(
                                    "Unknown gossipsub fork digest: {:?}",
                                    gossip_topic.fork_digest
                                ));
                            }
                        };
                        Ok(PubsubMessage::AggregateAndProofAttestation(Box::new(
                            signed_aggregate_and_proof,
                        )))
                    }
                    GossipKind::Attestation(subnet_id) => {
                        let attestation = SingleAttestation::from_ssz_bytes(data)
                            .map_err(|e| format!("{:?}", e))?;
                        Ok(PubsubMessage::Attestation(Box::new((
                            *subnet_id,
                            attestation,
                        ))))
                    }
                    GossipKind::BeaconBlock => {
                        let beacon_block = match fork_context
                            .get_fork_from_context_bytes(gossip_topic.fork_digest)
                        {
                            Some(ForkName::Base) => SignedBeaconBlock::<E>::Base(
                                SignedBeaconBlockBase::from_ssz_bytes(data)
                                    .map_err(|e| format!("{:?}", e))?,
                            ),
                            Some(ForkName::Altair) => SignedBeaconBlock::<E>::Altair(
                                SignedBeaconBlockAltair::from_ssz_bytes(data)
                                    .map_err(|e| format!("{:?}", e))?,
                            ),
                            Some(ForkName::Bellatrix) => SignedBeaconBlock::<E>::Bellatrix(
                                SignedBeaconBlockBellatrix::from_ssz_bytes(data)
                                    .map_err(|e| format!("{:?}", e))?,
                            ),
                            Some(ForkName::Capella) => SignedBeaconBlock::<E>::Capella(
                                SignedBeaconBlockCapella::from_ssz_bytes(data)
                                    .map_err(|e| format!("{:?}", e))?,
                            ),
                            Some(ForkName::Deneb) => SignedBeaconBlock::<E>::Deneb(
                                SignedBeaconBlockDeneb::from_ssz_bytes(data)
                                    .map_err(|e| format!("{:?}", e))?,
                            ),
                            Some(ForkName::Electra) => SignedBeaconBlock::<E>::Electra(
                                SignedBeaconBlockElectra::from_ssz_bytes(data)
                                    .map_err(|e| format!("{:?}", e))?,
                            ),
                            Some(ForkName::Fulu) => SignedBeaconBlock::<E>::Fulu(
                                SignedBeaconBlockFulu::from_ssz_bytes(data)
                                    .map_err(|e| format!("{:?}", e))?,
                            ),
                            Some(ForkName::Gloas) => SignedBeaconBlock::<E>::Gloas(
                                SignedBeaconBlockGloas::from_ssz_bytes(data)
                                    .map_err(|e| format!("{:?}", e))?,
                            ),
                            Some(ForkName::Heze) => SignedBeaconBlock::<E>::Heze(
                                SignedBeaconBlockHeze::from_ssz_bytes(data)
                                    .map_err(|e| format!("{:?}", e))?,
                            ),
                            None => {
                                return Err(format!(
                                    "Unknown gossipsub fork digest: {:?}",
                                    gossip_topic.fork_digest
                                ));
                            }
                        };
                        Ok(PubsubMessage::BeaconBlock(Arc::new(beacon_block)))
                    }
                    GossipKind::DataColumnSidecar(subnet_id) => {
                        match fork_context.get_fork_from_context_bytes(gossip_topic.fork_digest) {
                            Some(fork) if fork.fulu_enabled() => {
                                if fork.gloas_enabled()
                                    && data.len() > E::max_data_column_sidecar_size()
                                {
                                    return Err(format!(
                                        "DataColumnSidecar size {} exceeds MAX_DATA_COLUMN_SIDECAR_SIZE {}",
                                        data.len(),
                                        E::max_data_column_sidecar_size()
                                    ));
                                }
                                let col_sidecar = Arc::new(
                                    DataColumnSidecar::from_ssz_bytes_for_fork(data, *fork)
                                        .map_err(|e| format!("{:?}", e))?,
                                );
                                Ok(PubsubMessage::DataColumnSidecar(Box::new((
                                    *subnet_id,
                                    col_sidecar,
                                ))))
                            }
                            Some(_) | None => Err(format!(
                                "data_column_sidecar topic invalid for given fork digest {:?}",
                                gossip_topic.fork_digest
                            )),
                        }
                    }
                    GossipKind::VoluntaryExit => {
                        let voluntary_exit = SignedVoluntaryExit::from_ssz_bytes(data)
                            .map_err(|e| format!("{:?}", e))?;
                        Ok(PubsubMessage::VoluntaryExit(Box::new(voluntary_exit)))
                    }
                    GossipKind::ProposerSlashing => {
                        let proposer_slashing = ProposerSlashing::from_ssz_bytes(data)
                            .map_err(|e| format!("{:?}", e))?;
                        Ok(PubsubMessage::ProposerSlashing(Box::new(proposer_slashing)))
                    }
                    GossipKind::AttesterSlashing => {
                        let attester_slashing = match fork_context
                            .get_fork_from_context_bytes(gossip_topic.fork_digest)
                        {
                            Some(&fork_name) => {
                                // [Modified in Gloas:EIP7688] see `BeaconAggregateAndProof` above.
                                if fork_name.gloas_enabled() {
                                    if data.len() > E::max_attester_slashing_size() {
                                        return Err(format!(
                                            "AttesterSlashing size {} exceeds MAX_ATTESTER_SLASHING_SIZE {}",
                                            data.len(),
                                            E::max_attester_slashing_size()
                                        ));
                                    }
                                    AttesterSlashing::Gloas(
                                        AttesterSlashingGloas::from_ssz_bytes(data)
                                            .map_err(|e| format!("{:?}", e))?,
                                    )
                                } else if fork_name.electra_enabled() {
                                    AttesterSlashing::Electra(
                                        AttesterSlashingElectra::from_ssz_bytes(data)
                                            .map_err(|e| format!("{:?}", e))?,
                                    )
                                } else {
                                    AttesterSlashing::Base(
                                        AttesterSlashingBase::from_ssz_bytes(data)
                                            .map_err(|e| format!("{:?}", e))?,
                                    )
                                }
                            }
                            None => {
                                return Err(format!(
                                    "Unknown gossipsub fork digest: {:?}",
                                    gossip_topic.fork_digest
                                ));
                            }
                        };
                        Ok(PubsubMessage::AttesterSlashing(Box::new(attester_slashing)))
                    }
                    GossipKind::SignedContributionAndProof => {
                        let sync_aggregate = SignedContributionAndProof::from_ssz_bytes(data)
                            .map_err(|e| format!("{:?}", e))?;
                        Ok(PubsubMessage::SignedContributionAndProof(Box::new(
                            sync_aggregate,
                        )))
                    }
                    GossipKind::SyncCommitteeMessage(subnet_id) => {
                        let sync_committee = SyncCommitteeMessage::from_ssz_bytes(data)
                            .map_err(|e| format!("{:?}", e))?;
                        Ok(PubsubMessage::SyncCommitteeMessage(Box::new((
                            *subnet_id,
                            sync_committee,
                        ))))
                    }
                    GossipKind::BlsToExecutionChange => {
                        let bls_to_execution_change =
                            SignedBlsToExecutionChange::from_ssz_bytes(data)
                                .map_err(|e| format!("{:?}", e))?;
                        Ok(PubsubMessage::BlsToExecutionChange(Box::new(
                            bls_to_execution_change,
                        )))
                    }
                    GossipKind::ExecutionPayload => {
                        let execution_payload_envelope =
                            SignedExecutionPayloadEnvelope::from_ssz_bytes(data)
                                .map_err(|e| format!("{:?}", e))?;
                        Ok(PubsubMessage::ExecutionPayload(Box::new(
                            execution_payload_envelope,
                        )))
                    }
                    GossipKind::ExecutionPayloadBid => {
                        if data.len() > E::max_signed_execution_payload_bid_size() {
                            return Err(format!(
                                "SignedExecutionPayloadBid size {} exceeds MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE {}",
                                data.len(),
                                E::max_signed_execution_payload_bid_size()
                            ));
                        }
                        let execution_payload_bid = SignedExecutionPayloadBid::from_ssz_bytes(data)
                            .map_err(|e| format!("{:?}", e))?;
                        Ok(PubsubMessage::ExecutionPayloadBid(Box::new(
                            execution_payload_bid,
                        )))
                    }
                    GossipKind::PayloadAttestation => {
                        let payload_attestation = PayloadAttestationMessage::from_ssz_bytes(data)
                            .map_err(|e| format!("{:?}", e))?;
                        Ok(PubsubMessage::PayloadAttestation(Box::new(
                            payload_attestation,
                        )))
                    }
                    GossipKind::ProposerPreferences => {
                        let proposer_preferences = SignedProposerPreferences::from_ssz_bytes(data)
                            .map_err(|e| format!("{:?}", e))?;
                        Ok(PubsubMessage::ProposerPreferences(Arc::new(
                            proposer_preferences,
                        )))
                    }
                    GossipKind::ExecutionProof => {
                        let execution_proof = SignedExecutionProofEnvelope::from_ssz_bytes(data)
                            .map_err(|e| format!("{:?}", e))?;
                        Ok(PubsubMessage::ExecutionProof(Arc::new(execution_proof)))
                    }
                    GossipKind::LightClientFinalityUpdate => {
                        let light_client_finality_update = match fork_context
                            .get_fork_from_context_bytes(gossip_topic.fork_digest)
                        {
                            Some(&fork_name) => {
                                LightClientFinalityUpdate::from_ssz_bytes(data, fork_name)
                                    .map_err(|e| format!("{:?}", e))?
                            }
                            None => {
                                return Err(format!(
                                    "light_client_finality_update topic invalid for given fork digest {:?}",
                                    gossip_topic.fork_digest
                                ));
                            }
                        };
                        Ok(PubsubMessage::LightClientFinalityUpdate(Box::new(
                            light_client_finality_update,
                        )))
                    }
                    GossipKind::LightClientOptimisticUpdate => {
                        let light_client_optimistic_update = match fork_context
                            .get_fork_from_context_bytes(gossip_topic.fork_digest)
                        {
                            Some(&fork_name) => {
                                LightClientOptimisticUpdate::from_ssz_bytes(data, fork_name)
                                    .map_err(|e| format!("{:?}", e))?
                            }
                            None => {
                                return Err(format!(
                                    "light_client_optimistic_update topic invalid for given fork digest {:?}",
                                    gossip_topic.fork_digest
                                ));
                            }
                        };
                        Ok(PubsubMessage::LightClientOptimisticUpdate(Box::new(
                            light_client_optimistic_update,
                        )))
                    }
                }
            }
        }
    }

    /// Encodes a `PubsubMessage` based on the topic encodings. The first known encoding is used. If
    /// no encoding is known, and error is returned.
    pub fn encode(&self, _encoding: GossipEncoding) -> Vec<u8> {
        // Currently do not employ encoding strategies based on the topic. All messages are ssz
        // encoded.
        // Also note, that the compression is handled by the `SnappyTransform` struct. Gossipsub will compress the
        // messages for us.
        match &self {
            PubsubMessage::BeaconBlock(data) => data.as_ssz_bytes(),
            PubsubMessage::DataColumnSidecar(data) => data.1.as_ssz_bytes(),
            PubsubMessage::AggregateAndProofAttestation(data) => data.as_ssz_bytes(),
            PubsubMessage::VoluntaryExit(data) => data.as_ssz_bytes(),
            PubsubMessage::ProposerSlashing(data) => data.as_ssz_bytes(),
            PubsubMessage::AttesterSlashing(data) => data.as_ssz_bytes(),
            PubsubMessage::Attestation(data) => data.1.as_ssz_bytes(),
            PubsubMessage::SignedContributionAndProof(data) => data.as_ssz_bytes(),
            PubsubMessage::SyncCommitteeMessage(data) => data.1.as_ssz_bytes(),
            PubsubMessage::BlsToExecutionChange(data) => data.as_ssz_bytes(),
            PubsubMessage::ExecutionPayload(data) => data.as_ssz_bytes(),
            PubsubMessage::PayloadAttestation(data) => data.as_ssz_bytes(),
            PubsubMessage::ExecutionPayloadBid(data) => data.as_ssz_bytes(),
            PubsubMessage::ProposerPreferences(data) => data.as_ssz_bytes(),
            PubsubMessage::ExecutionProof(data) => data.as_ssz_bytes(),
            PubsubMessage::LightClientFinalityUpdate(data) => data.as_ssz_bytes(),
            PubsubMessage::LightClientOptimisticUpdate(data) => data.as_ssz_bytes(),
        }
    }
}

/// Decodes incoming partial data column sidecar from gossipsub partial protocol.
/// Note: Currently, data columns are the only supported partial messages. In future this could
/// return an enum.
pub fn decode_partial<E: EthSpec>(
    topic: &GossipTopic,
    group: &[u8],
    data: &[u8],
    fork_context: &ForkContext,
) -> Result<PartialDataColumn<E>, String> {
    match topic.kind() {
        GossipKind::DataColumnSidecar(id) => {
            let fork = *match fork_context.get_fork_from_context_bytes(topic.fork_digest) {
                Some(fork) if fork.fulu_enabled() => {
                    if fork.gloas_enabled()
                        && data.len() > E::max_partial_data_column_sidecar_size()
                    {
                        return Err(format!(
                            "PartialDataColumnSidecar size {} exceeds MAX_PARTIAL_DATA_COLUMN_SIDECAR_SIZE {}",
                            data.len(),
                            E::max_partial_data_column_sidecar_size()
                        ));
                    }
                    fork
                }
                Some(_) | None => {
                    return Err(format!(
                        "data_column_sidecar topic invalid for given fork digest {:?}",
                        topic.fork_digest
                    ));
                }
            };
            // Partial messages are spec'd under the assumption that there is one column per subnet.
            let index = **id;
            let Some((version, group_id)) = group.split_first() else {
                return Err("Empty partial group id".to_string());
            };
            match version {
                &PARTIAL_COLUMNS_VERSION_BYTE_FULU if !fork.gloas_enabled() => {
                    let sidecar = PartialDataColumnSidecarFulu::from_ssz_bytes(data)
                        .map_err(|e| format!("Error decoding sidecar: {:?}", e))?;
                    let block_root = Hash256::from_ssz_bytes(group_id)
                        .map_err(|e| format!("Error decoding Fulu group: {:?}", e))?;
                    Ok(PartialDataColumnFulu {
                        block_root,
                        index,
                        sidecar,
                    }
                    .into())
                }
                &PARTIAL_COLUMNS_VERSION_BYTE_GLOAS if fork.gloas_enabled() => {
                    let sidecar = PartialDataColumnSidecarGloas::from_ssz_bytes(data)
                        .map_err(|e| format!("Error decoding sidecar: {:?}", e))?;
                    let group_id = PartialDataColumnGroupId::from_ssz_bytes(group_id)
                        .map_err(|e| format!("Error decoding Gloas group: {:?}", e))?;
                    Ok(PartialDataColumnGloas {
                        block_root: group_id.beacon_block_root,
                        slot: group_id.slot,
                        index,
                        sidecar,
                    }
                    .into())
                }
                version => Err(format!("Unknown partial version {version} for fork {fork}")),
            }
        }
        other => Err(format!("Partial message unsupported for topic: {other}")),
    }
}

impl<E: EthSpec> std::fmt::Display for PubsubMessage<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PubsubMessage::BeaconBlock(block) => write!(
                f,
                "Beacon Block: slot: {}, proposer_index: {}",
                block.slot(),
                block.message().proposer_index()
            ),
            PubsubMessage::DataColumnSidecar(data) => write!(
                f,
                "DataColumnSidecar: slot: {}, column index: {}",
                data.1.slot(),
                data.1.index(),
            ),
            PubsubMessage::AggregateAndProofAttestation(att) => write!(
                f,
                "Aggregate and Proof: slot: {}, index: {:?}, aggregator_index: {}",
                att.message().aggregate().data().slot,
                att.message().aggregate().committee_index(),
                att.message().aggregator_index(),
            ),
            PubsubMessage::Attestation(data) => write!(
                f,
                "SingleAttestation: subnet_id: {}, attestation_slot: {}, committee_index: {:?}, attester_index: {:?}",
                *data.0, data.1.data.slot, data.1.committee_index, data.1.attester_index,
            ),
            PubsubMessage::VoluntaryExit(_data) => write!(f, "Voluntary Exit"),
            PubsubMessage::ProposerSlashing(_data) => write!(f, "Proposer Slashing"),
            PubsubMessage::AttesterSlashing(_data) => write!(f, "Attester Slashing"),
            PubsubMessage::SignedContributionAndProof(_) => {
                write!(f, "Signed Contribution and Proof")
            }
            PubsubMessage::SyncCommitteeMessage(data) => {
                write!(f, "Sync committee message: subnet_id: {}", *data.0)
            }
            PubsubMessage::BlsToExecutionChange(data) => {
                write!(
                    f,
                    "Signed BLS to execution change: validator_index: {}, address: {:?}",
                    data.message.validator_index, data.message.to_execution_address
                )
            }
            PubsubMessage::ExecutionPayload(data) => {
                write!(
                    f,
                    "Signed Execution Payload Envelope: slot: {:?}, beacon block root: {:?}",
                    data.slot(),
                    data.beacon_block_root()
                )
            }
            PubsubMessage::PayloadAttestation(data) => {
                write!(
                    f,
                    "Payload Attestation Message: slot: {:?}, beacon block root: {:?}, payload present: {:?}, blob data available: {:?}",
                    data.data.slot,
                    data.data.beacon_block_root,
                    data.data.payload_present,
                    data.data.blob_data_available
                )
            }
            PubsubMessage::ExecutionPayloadBid(data) => {
                write!(
                    f,
                    "Execution payload bid: slot: {:?} value: {:?}",
                    data.message.slot, data.message.value
                )
            }
            PubsubMessage::ProposerPreferences(data) => {
                write!(
                    f,
                    "Proposer preferences: slot: {:?}, validator_index: {:?}",
                    data.message.proposal_slot, data.message.validator_index
                )
            }
            PubsubMessage::ExecutionProof(data) => {
                write!(
                    f,
                    "Execution proof: beacon_block_root: {:?}, proof_type: {:?}, validator_index: {:?}",
                    data.message.beacon_block_root, data.message.proof_type, data.validator_index
                )
            }
            PubsubMessage::LightClientFinalityUpdate(_data) => {
                write!(f, "Light CLient Finality Update")
            }
            PubsubMessage::LightClientOptimisticUpdate(_data) => {
                write!(f, "Light CLient Optimistic Update")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::OutgoingPartialColumnGloas;
    use libp2p::gossipsub::partial_messages::Partial;
    use types::data::{CellBitmap, PartialDataColumnSidecarGloas};
    use types::{Epoch, EthSpec, MainnetEthSpec, Slot, data::DataColumnSubnetId};

    type E = MainnetEthSpec;

    fn gloas_fork_context() -> ForkContext {
        let mut spec = E::default_spec();
        spec.altair_fork_epoch = Some(Epoch::new(0));
        spec.bellatrix_fork_epoch = Some(Epoch::new(0));
        spec.capella_fork_epoch = Some(Epoch::new(0));
        spec.deneb_fork_epoch = Some(Epoch::new(0));
        spec.electra_fork_epoch = Some(Epoch::new(0));
        spec.fulu_fork_epoch = Some(Epoch::new(0));
        spec.gloas_fork_epoch = Some(Epoch::new(0));
        ForkContext::new::<E>(Slot::new(0), Hash256::ZERO, &spec)
    }

    #[test]
    fn gloas_group_id_round_trips_through_decode_partial() {
        let fork_context = gloas_fork_context();
        let topic = GossipTopic::new(
            GossipKind::DataColumnSidecar(DataColumnSubnetId::new(3)),
            GossipEncoding::default(),
            fork_context.current_fork_digest(),
        );
        let column = PartialDataColumnGloas::<E> {
            block_root: Hash256::repeat_byte(7),
            slot: Slot::new(9),
            index: 3,
            sidecar: PartialDataColumnSidecarGloas {
                cells_present_bitmap: CellBitmap::<E>::with_capacity(1).unwrap(),
                column: Default::default(),
                kzg_proofs: Default::default(),
            },
        };
        let outgoing = OutgoingPartialColumnGloas::new(
            Arc::new(column.clone()),
            column.sidecar.cells_present_bitmap.clone(),
        );

        let decoded = decode_partial::<E>(
            &topic,
            &outgoing.group_id(),
            &column.sidecar.as_ssz_bytes(),
            &fork_context,
        )
        .unwrap();

        let PartialDataColumn::Gloas(decoded) = decoded else {
            panic!("expected a Gloas partial");
        };
        assert_eq!(decoded.block_root, column.block_root);
        assert_eq!(decoded.slot, column.slot);
        assert_eq!(decoded.index, column.index);
    }

    fn decode_oversized(kind: GossipKind, size: usize) -> Result<PubsubMessage<E>, String> {
        let fork_context = gloas_fork_context();
        let topic = GossipTopic::new(
            kind,
            GossipEncoding::default(),
            fork_context.current_fork_digest(),
        );
        let topic_hash = TopicHash::from_raw(String::from(topic));
        let data = vec![0u8; size];
        PubsubMessage::decode(&topic_hash, &data, &fork_context)
    }

    #[test]
    fn gloas_aggregate_and_proof_size_bound() {
        let max = E::max_signed_aggregate_and_proof_size();
        let err = decode_oversized(GossipKind::BeaconAggregateAndProof, max + 1).unwrap_err();
        assert!(err.contains("MAX_SIGNED_AGGREGATE_AND_PROOF_SIZE"), "{err}");
        let err = decode_oversized(GossipKind::BeaconAggregateAndProof, max).unwrap_err();
        assert!(
            !err.contains("MAX_SIGNED_AGGREGATE_AND_PROOF_SIZE"),
            "{err}"
        );
    }

    #[test]
    fn gloas_attester_slashing_size_bound() {
        let max = E::max_attester_slashing_size();
        let err = decode_oversized(GossipKind::AttesterSlashing, max + 1).unwrap_err();
        assert!(err.contains("MAX_ATTESTER_SLASHING_SIZE"), "{err}");
        let err = decode_oversized(GossipKind::AttesterSlashing, max).unwrap_err();
        assert!(!err.contains("MAX_ATTESTER_SLASHING_SIZE"), "{err}");
    }

    #[test]
    fn gloas_data_column_sidecar_size_bound() {
        let max = E::max_data_column_sidecar_size();
        let kind = GossipKind::DataColumnSidecar(DataColumnSubnetId::new(0));
        let err = decode_oversized(kind.clone(), max + 1).unwrap_err();
        assert!(err.contains("MAX_DATA_COLUMN_SIDECAR_SIZE"), "{err}");
        let err = decode_oversized(kind, max).unwrap_err();
        assert!(!err.contains("MAX_DATA_COLUMN_SIDECAR_SIZE"), "{err}");
    }

    #[test]
    fn gloas_partial_data_column_sidecar_size_bound() {
        let fork_context = gloas_fork_context();
        let topic = GossipTopic::new(
            GossipKind::DataColumnSidecar(DataColumnSubnetId::new(0)),
            GossipEncoding::default(),
            fork_context.current_fork_digest(),
        );
        let group = {
            let mut group = vec![0u8];
            group.extend_from_slice(Hash256::ZERO.as_slice());
            group
        };
        let max = E::max_partial_data_column_sidecar_size();

        let data = vec![0u8; max + 1];
        let err = decode_partial::<E>(&topic, &group, &data, &fork_context).unwrap_err();
        assert!(
            err.contains("MAX_PARTIAL_DATA_COLUMN_SIDECAR_SIZE"),
            "{err}"
        );

        let data = vec![0u8; max];
        let err = decode_partial::<E>(&topic, &group, &data, &fork_context).unwrap_err();
        assert!(
            !err.contains("MAX_PARTIAL_DATA_COLUMN_SIDECAR_SIZE"),
            "{err}"
        );
    }

    #[test]
    fn gloas_execution_payload_bid_size_bound() {
        let max = E::max_signed_execution_payload_bid_size();
        let err = decode_oversized(GossipKind::ExecutionPayloadBid, max + 1).unwrap_err();
        assert!(
            err.contains("MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE"),
            "{err}"
        );
        let err = decode_oversized(GossipKind::ExecutionPayloadBid, max).unwrap_err();
        assert!(
            !err.contains("MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE"),
            "{err}"
        );
    }
}
