use crate::types::SubnetId;
use libp2p::gossipsub::Topic;
use serde_derive::{Deserialize, Serialize};

/// The gossipsub topic names.
// These constants form a topic name of the form /TOPIC_PREFIX/TOPIC/ENCODING_POSTFIX
// For example /eth2/beacon_block/ssz
pub const TOPIC_PREFIX: &str = "eth2";
pub const TOPIC_ENCODING_POSTFIX: &str = "ssz";
pub const BEACON_BLOCK_TOPIC: &str = "beacon_block";
pub const BEACON_AGGREGATE_AND_PROOF_TOPIC: &str = "beacon_aggregate_and_proof";
// for speed and easier string manipulation, committee topic index is split into a prefix and a
// postfix. The topic is committee_index{}_beacon_attestation where {} is an integer.
pub const COMMITEE_INDEX_TOPIC_PREFIX: &str = "committee_index";
pub const COMMITEE_INDEX_TOPIC_POSTFIX: &str = "_beacon_attestation";
pub const VOLUNTARY_EXIT_TOPIC: &str = "voluntary_exit";
pub const PROPOSER_SLASHING_TOPIC: &str = "proposer_slashing";
pub const ATTESTER_SLASHING_TOPIC: &str = "attester_slashing";
/// The maximum number of attestation subnets.
pub const ATTESTATION_SUBNET_COUNT: u64 = 64;

/// Enum that brings these topics into the rust type system.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GossipTopic {
    BeaconBlock,
    BeaconAggregateAndProof,
    CommitteeIndex(SubnetId),
    VoluntaryExit,
    ProposerSlashing,
    AttesterSlashing,
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
                BEACON_AGGREGATE_AND_PROOF_TOPIC => GossipTopic::BeaconAggregateAndProof,
                VOLUNTARY_EXIT_TOPIC => GossipTopic::VoluntaryExit,
                PROPOSER_SLASHING_TOPIC => GossipTopic::ProposerSlashing,
                ATTESTER_SLASHING_TOPIC => GossipTopic::AttesterSlashing,
                topic => match committee_topic_index(topic) {
                    Some(subnet_id) => GossipTopic::CommitteeIndex(subnet_id),
                    None => GossipTopic::Unknown(topic.into()),
                },
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
            GossipTopic::BeaconAggregateAndProof => topic_builder(BEACON_AGGREGATE_AND_PROOF_TOPIC),
            GossipTopic::VoluntaryExit => topic_builder(VOLUNTARY_EXIT_TOPIC),
            GossipTopic::ProposerSlashing => topic_builder(PROPOSER_SLASHING_TOPIC),
            GossipTopic::AttesterSlashing => topic_builder(ATTESTER_SLASHING_TOPIC),
            GossipTopic::CommitteeIndex(index) => topic_builder(format!(
                "{}{}{}",
                COMMITEE_INDEX_TOPIC_PREFIX, *index, COMMITEE_INDEX_TOPIC_POSTFIX
            )),
            GossipTopic::Unknown(topic) => topic,
        }
    }
}

// helper functions

// Determines if a string is a committee topic.
fn committee_topic_index(topic: &str) -> Option<SubnetId> {
    if topic.starts_with(COMMITEE_INDEX_TOPIC_PREFIX)
        && topic.ends_with(COMMITEE_INDEX_TOPIC_POSTFIX)
    {
        return Some(SubnetId::new(
            u64::from_str_radix(
                topic
                    .trim_start_matches(COMMITEE_INDEX_TOPIC_PREFIX)
                    .trim_end_matches(COMMITEE_INDEX_TOPIC_POSTFIX),
                10,
            )
            .ok()?,
        ));
    }
    None
}

// builds a full topic string
fn topic_builder(topic: impl Into<String>) -> String {
    format!(
        "/{}/{}/{}",
        TOPIC_PREFIX,
        topic.into(),
        TOPIC_ENCODING_POSTFIX,
    )
}
