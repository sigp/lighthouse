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

/// Messages that are passed to and from the pubsub (Gossipsub) behaviour.
#[derive(Debug, Clone, PartialEq)]
pub struct PubsubMessage<T: EthSpec> {
    /// The encoding to be used to encode/decode the message
    pub encoding: GossipEncoding,
    /// The actual message being sent.
    pub data: PubsubData<T>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PubsubData<T: EthSpec> {
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
    pub fn new(encoding: GossipEncoding, data: PubsubData<T>) -> Self {
        PubsubMessage { encoding, data }
    }

    /// Returns the topics that each pubsub message will be sent across, given a supported
    /// gossipsub encoding.
    pub fn topics(&self) -> Vec<GossipTopic> {
        let encoding = self.encoding.clone();
        match &self.data {
            PubsubData::BeaconBlock(_) => vec![GossipTopic::new(GossipKind::BeaconBlock, encoding)],
            PubsubData::AggregateAndProofAttestation(_) => vec![GossipTopic::new(
                GossipKind::BeaconAggregateAndProof,
                encoding,
            )],
            PubsubData::Attestation(attestation_data) => vec![GossipTopic::new(
                GossipKind::CommitteeIndex(attestation_data.0),
                encoding,
            )],
            PubsubData::VoluntaryExit(_) => {
                vec![GossipTopic::new(GossipKind::VoluntaryExit, encoding)]
            }
            PubsubData::ProposerSlashing(_) => {
                vec![GossipTopic::new(GossipKind::ProposerSlashing, encoding)]
            }
            PubsubData::AttesterSlashing(_) => {
                vec![GossipTopic::new(GossipKind::AttesterSlashing, encoding)]
            }
        }
    }

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
                            let encoding = GossipEncoding::SSZ;
                            match gossip_topic.kind() {
                                GossipKind::BeaconAggregateAndProof => {
                                    let agg_and_proof =
                                        SignedAggregateAndProof::from_ssz_bytes(data)
                                            .map_err(|e| format!("{:?}", e))?;
                                    return Ok(PubsubMessage::new(
                                        encoding,
                                        PubsubData::AggregateAndProofAttestation(Box::new(
                                            agg_and_proof,
                                        )),
                                    ));
                                }
                                GossipKind::CommitteeIndex(subnet_id) => {
                                    let attestation = Attestation::from_ssz_bytes(data)
                                        .map_err(|e| format!("{:?}", e))?;
                                    return Ok(PubsubMessage::new(
                                        encoding,
                                        PubsubData::Attestation(Box::new((
                                            *subnet_id,
                                            attestation,
                                        ))),
                                    ));
                                }
                                GossipKind::BeaconBlock => {
                                    let beacon_block = SignedBeaconBlock::from_ssz_bytes(data)
                                        .map_err(|e| format!("{:?}", e))?;
                                    return Ok(PubsubMessage::new(
                                        encoding,
                                        PubsubData::BeaconBlock(Box::new(beacon_block)),
                                    ));
                                }
                                GossipKind::VoluntaryExit => {
                                    let voluntary_exit = VoluntaryExit::from_ssz_bytes(data)
                                        .map_err(|e| format!("{:?}", e))?;
                                    return Ok(PubsubMessage::new(
                                        encoding,
                                        PubsubData::VoluntaryExit(Box::new(voluntary_exit)),
                                    ));
                                }
                                GossipKind::ProposerSlashing => {
                                    let proposer_slashing = ProposerSlashing::from_ssz_bytes(data)
                                        .map_err(|e| format!("{:?}", e))?;
                                    return Ok(PubsubMessage::new(
                                        encoding,
                                        PubsubData::ProposerSlashing(Box::new(proposer_slashing)),
                                    ));
                                }
                                GossipKind::AttesterSlashing => {
                                    let attester_slashing = AttesterSlashing::from_ssz_bytes(data)
                                        .map_err(|e| format!("{:?}", e))?;
                                    return Ok(PubsubMessage::new(
                                        encoding,
                                        PubsubData::AttesterSlashing(Box::new(attester_slashing)),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(format!("Unknown gossipsub topics: {:?}", unknown_topics))
    }

    /// Encodes a pubsub message based on the topic encodings. The first known encoding is used. If
    /// no encoding is known, and error is returned.
    pub fn encode(&self) -> Vec<u8> {
        match self.encoding {
            GossipEncoding::SSZ => {
                // SSZ Encodings
                return match &self.data {
                    PubsubData::BeaconBlock(data) => data.as_ssz_bytes(),
                    PubsubData::AggregateAndProofAttestation(data) => data.as_ssz_bytes(),
                    PubsubData::VoluntaryExit(data) => data.as_ssz_bytes(),
                    PubsubData::ProposerSlashing(data) => data.as_ssz_bytes(),
                    PubsubData::AttesterSlashing(data) => data.as_ssz_bytes(),
                    PubsubData::Attestation(data) => data.1.as_ssz_bytes(),
                };
            }
        }
    }
}
