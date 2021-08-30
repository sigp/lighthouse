//! Handles the encoding and decoding of pubsub messages.

use crate::types::{GossipEncoding, GossipKind, GossipTopic};
use crate::TopicHash;
use libp2p::gossipsub::{DataTransform, GossipsubMessage, RawGossipsubMessage};
use snap::raw::{decompress_len, Decoder, Encoder};
use ssz::{Decode, Encode};
use std::boxed::Box;
use std::io::{Error, ErrorKind};
use types::{
    Attestation, AttesterSlashing, EthSpec, ForkContext, ForkName, ProposerSlashing,
    SignedAggregateAndProof, SignedBeaconBlock, SignedBeaconBlockAltair, SignedBeaconBlockBase,
    SignedContributionAndProof, SignedVoluntaryExit, SubnetId, SyncCommitteeMessage, SyncSubnetId,
};

#[derive(Debug, Clone, PartialEq)]
pub enum PubsubMessage<T: EthSpec> {
    /// Gossipsub message providing notification of a new block.
    BeaconBlock(Box<SignedBeaconBlock<T>>),
    /// Gossipsub message providing notification of a Aggregate attestation and associated proof.
    AggregateAndProofAttestation(Box<SignedAggregateAndProof<T>>),
    /// Gossipsub message providing notification of a raw un-aggregated attestation with its shard id.
    Attestation(Box<(SubnetId, Attestation<T>)>),
    /// Gossipsub message providing notification of a voluntary exit.
    VoluntaryExit(Box<SignedVoluntaryExit>),
    /// Gossipsub message providing notification of a new proposer slashing.
    ProposerSlashing(Box<ProposerSlashing>),
    /// Gossipsub message providing notification of a new attester slashing.
    AttesterSlashing(Box<AttesterSlashing<T>>),
    /// Gossipsub message providing notification of partially aggregated sync committee signatures.
    SignedContributionAndProof(Box<SignedContributionAndProof<T>>),
    /// Gossipsub message providing notification of unaggregated sync committee signatures with its subnet id.
    SyncCommitteeMessage(Box<(SyncSubnetId, SyncCommitteeMessage)>),
}

// Implements the `DataTransform` trait of gossipsub to employ snappy compression
pub struct SnappyTransform {
    /// Sets the maximum size we allow gossipsub messages to decompress to.
    max_size_per_message: usize,
}

impl SnappyTransform {
    pub fn new(max_size_per_message: usize) -> Self {
        SnappyTransform {
            max_size_per_message,
        }
    }
}

impl DataTransform for SnappyTransform {
    // Provides the snappy decompression from RawGossipsubMessages
    fn inbound_transform(
        &self,
        raw_message: RawGossipsubMessage,
    ) -> Result<GossipsubMessage, std::io::Error> {
        // check the length of the raw bytes
        let len = decompress_len(&raw_message.data)?;
        if len > self.max_size_per_message {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "ssz_snappy decoded data > GOSSIP_MAX_SIZE",
            ));
        }

        let mut decoder = Decoder::new();
        let decompressed_data = decoder.decompress_vec(&raw_message.data)?;

        // Build the GossipsubMessage struct
        Ok(GossipsubMessage {
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
        if data.len() > self.max_size_per_message {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "ssz_snappy Encoded data > GOSSIP_MAX_SIZE",
            ));
        }
        let mut encoder = Encoder::new();
        encoder.compress_vec(&data).map_err(Into::into)
    }
}

impl<T: EthSpec> PubsubMessage<T> {
    /// Returns the topics that each pubsub message will be sent across, given a supported
    /// gossipsub encoding and fork version.
    pub fn topics(&self, encoding: GossipEncoding, fork_version: [u8; 4]) -> Vec<GossipTopic> {
        vec![GossipTopic::new(self.kind(), encoding, fork_version)]
    }

    /// Returns the kind of gossipsub topic associated with the message.
    pub fn kind(&self) -> GossipKind {
        match self {
            PubsubMessage::BeaconBlock(_) => GossipKind::BeaconBlock,
            PubsubMessage::AggregateAndProofAttestation(_) => GossipKind::BeaconAggregateAndProof,
            PubsubMessage::Attestation(attestation_data) => {
                GossipKind::Attestation(attestation_data.0)
            }
            PubsubMessage::VoluntaryExit(_) => GossipKind::VoluntaryExit,
            PubsubMessage::ProposerSlashing(_) => GossipKind::ProposerSlashing,
            PubsubMessage::AttesterSlashing(_) => GossipKind::AttesterSlashing,
            PubsubMessage::SignedContributionAndProof(_) => GossipKind::SignedContributionAndProof,
            PubsubMessage::SyncCommitteeMessage(data) => GossipKind::SyncCommitteeMessage(data.0),
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
                        let agg_and_proof = SignedAggregateAndProof::from_ssz_bytes(data)
                            .map_err(|e| format!("{:?}", e))?;
                        Ok(PubsubMessage::AggregateAndProofAttestation(Box::new(
                            agg_and_proof,
                        )))
                    }
                    GossipKind::Attestation(subnet_id) => {
                        let attestation =
                            Attestation::from_ssz_bytes(data).map_err(|e| format!("{:?}", e))?;
                        Ok(PubsubMessage::Attestation(Box::new((
                            *subnet_id,
                            attestation,
                        ))))
                    }
                    GossipKind::BeaconBlock => {
                        let beacon_block =
                            match fork_context.from_context_bytes(gossip_topic.fork_digest) {
                                Some(ForkName::Base) => SignedBeaconBlock::<T>::Base(
                                    SignedBeaconBlockBase::from_ssz_bytes(data)
                                        .map_err(|e| format!("{:?}", e))?,
                                ),
                                Some(ForkName::Altair) => SignedBeaconBlock::<T>::Altair(
                                    SignedBeaconBlockAltair::from_ssz_bytes(data)
                                        .map_err(|e| format!("{:?}", e))?,
                                ),
                                None => {
                                    return Err(format!(
                                        "Unknown gossipsub fork digest: {:?}",
                                        gossip_topic.fork_digest
                                    ))
                                }
                            };
                        Ok(PubsubMessage::BeaconBlock(Box::new(beacon_block)))
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
                        let attester_slashing = AttesterSlashing::from_ssz_bytes(data)
                            .map_err(|e| format!("{:?}", e))?;
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
            PubsubMessage::AggregateAndProofAttestation(data) => data.as_ssz_bytes(),
            PubsubMessage::VoluntaryExit(data) => data.as_ssz_bytes(),
            PubsubMessage::ProposerSlashing(data) => data.as_ssz_bytes(),
            PubsubMessage::AttesterSlashing(data) => data.as_ssz_bytes(),
            PubsubMessage::Attestation(data) => data.1.as_ssz_bytes(),
            PubsubMessage::SignedContributionAndProof(data) => data.as_ssz_bytes(),
            PubsubMessage::SyncCommitteeMessage(data) => data.1.as_ssz_bytes(),
        }
    }
}

impl<T: EthSpec> std::fmt::Display for PubsubMessage<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PubsubMessage::BeaconBlock(block) => write!(
                f,
                "Beacon Block: slot: {}, proposer_index: {}",
                block.slot(),
                block.message().proposer_index()
            ),
            PubsubMessage::AggregateAndProofAttestation(att) => write!(
                f,
                "Aggregate and Proof: slot: {}, index: {}, aggregator_index: {}",
                att.message.aggregate.data.slot,
                att.message.aggregate.data.index,
                att.message.aggregator_index,
            ),
            PubsubMessage::Attestation(data) => write!(
                f,
                "Attestation: subnet_id: {}, attestation_slot: {}, attestation_index: {}",
                *data.0, data.1.data.slot, data.1.data.index,
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
        }
    }
}
