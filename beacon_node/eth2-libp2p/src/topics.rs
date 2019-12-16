use libp2p::gossipsub::Topic;
use serde_derive::{Deserialize, Serialize};

/// The gossipsub topic names.
// These constants form a topic name of the form /TOPIC_PREFIX/TOPIC/ENCODING_POSTFIX
// For example /eth2/beacon_block/ssz
pub const TOPIC_PREFIX: &str = "eth2";
pub const TOPIC_ENCODING_POSTFIX: &str = "ssz";
pub const BEACON_BLOCK_TOPIC: &str = "beacon_block";
pub const BEACON_ATTESTATION_TOPIC: &str = "beacon_attestation";
pub const VOLUNTARY_EXIT_TOPIC: &str = "voluntary_exit";
pub const PROPOSER_SLASHING_TOPIC: &str = "proposer_slashing";
pub const ATTESTER_SLASHING_TOPIC: &str = "attester_slashing";
pub const SHARD_TOPIC_PREFIX: &str = "shard";

/// Enum that brings these topics into the rust type system.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GossipTopic {
    BeaconBlock,
    BeaconAttestation,
    VoluntaryExit,
    ProposerSlashing,
    AttesterSlashing,
    Shard,
    Unknown(String),
}

impl From<&str> for GossipTopic {
    fn from(topic: &str) -> GossipTopic {
        let topic_parts: Vec<&str> = topic.split('/').collect();
        if topic_parts.len() == 4
            && topic_parts[1] == TOPIC_PREFIX
            && topic_parts[3] == TOPIC_ENCODING_POSTFIX
        {
            match topic_parts[2] {
                BEACON_BLOCK_TOPIC => GossipTopic::BeaconBlock,
                BEACON_ATTESTATION_TOPIC => GossipTopic::BeaconAttestation,
                VOLUNTARY_EXIT_TOPIC => GossipTopic::VoluntaryExit,
                PROPOSER_SLASHING_TOPIC => GossipTopic::ProposerSlashing,
                ATTESTER_SLASHING_TOPIC => GossipTopic::AttesterSlashing,
                unknown_topic => GossipTopic::Unknown(unknown_topic.into()),
            }
        } else {
            GossipTopic::Unknown(topic.into())
        }
    }
}

impl Into<Topic> for GossipTopic {
    fn into(self) -> Topic {
        Topic::new(self.into())
    }
}

impl Into<String> for GossipTopic {
    fn into(self) -> String {
        match self {
            GossipTopic::BeaconBlock => topic_builder(BEACON_BLOCK_TOPIC),
            GossipTopic::BeaconAttestation => topic_builder(BEACON_ATTESTATION_TOPIC),
            GossipTopic::VoluntaryExit => topic_builder(VOLUNTARY_EXIT_TOPIC),
            GossipTopic::ProposerSlashing => topic_builder(PROPOSER_SLASHING_TOPIC),
            GossipTopic::AttesterSlashing => topic_builder(ATTESTER_SLASHING_TOPIC),
            GossipTopic::Shard => topic_builder(SHARD_TOPIC_PREFIX),
            GossipTopic::Unknown(topic) => topic,
        }
    }
}

fn topic_builder(topic: &'static str) -> String {
    format!("/{}/{}/{}", TOPIC_PREFIX, topic, TOPIC_ENCODING_POSTFIX,)
}
