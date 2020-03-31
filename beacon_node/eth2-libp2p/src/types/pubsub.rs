//! Handles the encoding and decoding of pubsub messages.

use crate::types::{GossipEncoding, GossipKind, GossipTopic};
use crate::TopicHash;
use ssz::{Decode, Encode};
use std::boxed::Box;
use types::SubnetId;
use types::{
    Attestation, AttesterSlashing, EthSpec, ProposerSlashing, SignedAggregateAndProof,
    SignedBeaconBlock, VoluntaryExit,
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
    VoluntaryExit(Box<VoluntaryExit>),
    /// Gossipsub message providing notification of a new proposer slashing.
    ProposerSlashing(Box<ProposerSlashing>),
    /// Gossipsub message providing notification of a new attester slashing.
    AttesterSlashing(Box<AttesterSlashing<T>>),
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
                GossipKind::CommitteeIndex(attestation_data.0)
            }
            PubsubMessage::VoluntaryExit(_) => GossipKind::VoluntaryExit,
            PubsubMessage::ProposerSlashing(_) => GossipKind::ProposerSlashing,
            PubsubMessage::AttesterSlashing(_) => GossipKind::AttesterSlashing,
        }
    }

    /// This decodes `data` into a `PubsubMessage` given a list of topics.
    ///
    /// The topics are checked
    /// in order and as soon as one topic matches the decoded data, we return the data.
    /* Note: This is assuming we are not hashing topics. If we choose to hash topics, these will
     * need to be modified.
     *
     * Also note that a message can be associated with many topics. As soon as one of the topics is
     * known we match. If none of the topics are known we return an unknown state.
     */
    pub fn decode(topics: &[TopicHash], data: &[u8]) -> Result<Self, String> {
        let mut unknown_topics = Vec::new();
        for topic in topics {
            match GossipTopic::decode(topic.as_str()) {
                Err(_) => {
                    unknown_topics.push(topic);
                    continue;
                }
                Ok(gossip_topic) => {
                    match gossip_topic.encoding() {
                        // group each part by encoding type
                        GossipEncoding::SSZ => {
                            // the ssz decoders
                            match gossip_topic.kind() {
                                GossipKind::BeaconAggregateAndProof => {
                                    let agg_and_proof =
                                        SignedAggregateAndProof::from_ssz_bytes(data)
                                            .map_err(|e| format!("{:?}", e))?;
                                    return Ok(PubsubMessage::AggregateAndProofAttestation(
                                        Box::new(agg_and_proof),
                                    ));
                                }
                                GossipKind::CommitteeIndex(subnet_id) => {
                                    let attestation = Attestation::from_ssz_bytes(data)
                                        .map_err(|e| format!("{:?}", e))?;
                                    return Ok(PubsubMessage::Attestation(Box::new((
                                        *subnet_id,
                                        attestation,
                                    ))));
                                }
                                GossipKind::BeaconBlock => {
                                    let beacon_block = SignedBeaconBlock::from_ssz_bytes(data)
                                        .map_err(|e| format!("{:?}", e))?;
                                    return Ok(PubsubMessage::BeaconBlock(Box::new(beacon_block)));
                                }
                                GossipKind::VoluntaryExit => {
                                    let voluntary_exit = VoluntaryExit::from_ssz_bytes(data)
                                        .map_err(|e| format!("{:?}", e))?;
                                    return Ok(PubsubMessage::VoluntaryExit(Box::new(
                                        voluntary_exit,
                                    )));
                                }
                                GossipKind::ProposerSlashing => {
                                    let proposer_slashing = ProposerSlashing::from_ssz_bytes(data)
                                        .map_err(|e| format!("{:?}", e))?;
                                    return Ok(PubsubMessage::ProposerSlashing(Box::new(
                                        proposer_slashing,
                                    )));
                                }
                                GossipKind::AttesterSlashing => {
                                    let attester_slashing = AttesterSlashing::from_ssz_bytes(data)
                                        .map_err(|e| format!("{:?}", e))?;
                                    return Ok(PubsubMessage::AttesterSlashing(Box::new(
                                        attester_slashing,
                                    )));
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(format!("Unknown gossipsub topics: {:?}", unknown_topics))
    }

    /// Encodes a `PubsubMessage` based on the topic encodings. The first known encoding is used. If
    /// no encoding is known, and error is returned.
    pub fn encode(&self, encoding: GossipEncoding) -> Vec<u8> {
        match encoding {
            GossipEncoding::SSZ => {
                // SSZ Encodings
                return match &self {
                    PubsubMessage::BeaconBlock(data) => data.as_ssz_bytes(),
                    PubsubMessage::AggregateAndProofAttestation(data) => data.as_ssz_bytes(),
                    PubsubMessage::VoluntaryExit(data) => data.as_ssz_bytes(),
                    PubsubMessage::ProposerSlashing(data) => data.as_ssz_bytes(),
                    PubsubMessage::AttesterSlashing(data) => data.as_ssz_bytes(),
                    PubsubMessage::Attestation(data) => data.1.as_ssz_bytes(),
                };
            }
        }
    }
}
