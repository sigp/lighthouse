//! Handles the encoding and decoding of pubsub messages.

use crate::config::GOSSIP_MAX_SIZE;
use crate::types::{GossipEncoding, GossipKind, GossipTopic};
use crate::TopicHash;
use snap::raw::{decompress_len, Decoder, Encoder};
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
                    let mut decompressed_data: Vec<u8> = Vec::new();
                    let data = match gossip_topic.encoding() {
                        // group each part by encoding type
                        GossipEncoding::SSZSnappy => {
                            match decompress_len(data) {
                                Ok(n) if n > GOSSIP_MAX_SIZE => {
                                    return Err("ssz_snappy decoded data > GOSSIP_MAX_SIZE".into());
                                }
                                Ok(n) => decompressed_data.resize(n, 0),
                                Err(e) => {
                                    return Err(format!("{}", e));
                                }
                            };
                            let mut decoder = Decoder::new();
                            match decoder.decompress(data, &mut decompressed_data) {
                                Ok(n) => {
                                    decompressed_data.truncate(n);
                                    &decompressed_data
                                }
                                Err(e) => return Err(format!("{}", e)),
                            }
                        }
                        GossipEncoding::SSZ => data,
                    };
                    // the ssz decoders
                    match gossip_topic.kind() {
                        GossipKind::BeaconAggregateAndProof => {
                            let agg_and_proof = SignedAggregateAndProof::from_ssz_bytes(data)
                                .map_err(|e| format!("{:?}", e))?;
                            return Ok(PubsubMessage::AggregateAndProofAttestation(Box::new(
                                agg_and_proof,
                            )));
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
                            return Ok(PubsubMessage::VoluntaryExit(Box::new(voluntary_exit)));
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
        Err(format!("Unknown gossipsub topics: {:?}", unknown_topics))
    }

    /// Encodes a `PubsubMessage` based on the topic encodings. The first known encoding is used. If
    /// no encoding is known, and error is returned.
    pub fn encode(&self, encoding: GossipEncoding) -> Result<Vec<u8>, String> {
        let data = match &self {
            PubsubMessage::BeaconBlock(data) => data.as_ssz_bytes(),
            PubsubMessage::AggregateAndProofAttestation(data) => data.as_ssz_bytes(),
            PubsubMessage::VoluntaryExit(data) => data.as_ssz_bytes(),
            PubsubMessage::ProposerSlashing(data) => data.as_ssz_bytes(),
            PubsubMessage::AttesterSlashing(data) => data.as_ssz_bytes(),
            PubsubMessage::Attestation(data) => data.1.as_ssz_bytes(),
        };
        match encoding {
            GossipEncoding::SSZ => {
                if data.len() > GOSSIP_MAX_SIZE {
                    return Err("ssz encoded data > GOSSIP_MAX_SIZE".into());
                } else {
                    Ok(data)
                }
            }
            GossipEncoding::SSZSnappy => {
                let mut encoder = Encoder::new();
                match encoder.compress_vec(&data) {
                    Ok(compressed) if compressed.len() > GOSSIP_MAX_SIZE => {
                        Err("ssz_snappy Encoded data > GOSSIP_MAX_SIZE".into())
                    }
                    Ok(compressed) => Ok(compressed),
                    Err(e) => Err(format!("{}", e)),
                }
            }
        }
    }
}

impl<T: EthSpec> std::fmt::Display for PubsubMessage<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PubsubMessage::BeaconBlock(block) => write!(
                f,
                "Beacon Block: slot: {}, proposer_index: {}",
                block.message.slot, block.message.proposer_index
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
        }
    }
}
