use libp2p::gossipsub::Topic;
use serde_derive::{Deserialize, Serialize};
use types::SubnetId;

/// The gossipsub topic names.
// These constants form a topic name of the form /TOPIC_PREFIX/TOPIC/ENCODING_POSTFIX
// For example /eth2/beacon_block/ssz
pub const TOPIC_PREFIX: &str = "eth2";
pub const SSZ_ENCODING_POSTFIX: &str = "ssz";
pub const SSZ_SNAPPY_ENCODING_POSTFIX: &str = "ssz_snappy";
pub const BEACON_BLOCK_TOPIC: &str = "beacon_block";
pub const BEACON_AGGREGATE_AND_PROOF_TOPIC: &str = "beacon_aggregate_and_proof";
// for speed and easier string manipulation, committee topic index is split into a prefix and a
// postfix. The topic is committee_index{}_beacon_attestation where {} is an integer.
pub const COMMITEE_INDEX_TOPIC_PREFIX: &str = "committee_index";
pub const COMMITEE_INDEX_TOPIC_POSTFIX: &str = "_beacon_attestation";
pub const VOLUNTARY_EXIT_TOPIC: &str = "voluntary_exit";
pub const PROPOSER_SLASHING_TOPIC: &str = "proposer_slashing";
pub const ATTESTER_SLASHING_TOPIC: &str = "attester_slashing";

/// A gossipsub topic which encapsulates the type of messages that should be sent and received over
/// the pubsub protocol and the way the messages should be encoded.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GossipTopic {
    /// The encoding of the topic.
    encoding: GossipEncoding,
    /// The fork digest of the topic,
    fork_digest: [u8; 4],
    /// The kind of topic.
    kind: GossipKind,
}

/// Enum that brings these topics into the rust type system.
// NOTE: There is intentionally no unknown type here. We only allow known gossipsub topics.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum GossipKind {
    /// Topic for publishing beacon blocks.
    BeaconBlock,
    /// Topic for publishing aggregate attestations and proofs.    
    BeaconAggregateAndProof,
    /// Topic for publishing raw attestations on a particular subnet.
    CommitteeIndex(SubnetId),
    /// Topic for publishing voluntary exits.
    VoluntaryExit,
    /// Topic for publishing block proposer slashings.
    ProposerSlashing,
    /// Topic for publishing attester slashings.
    AttesterSlashing,
}

impl std::fmt::Display for GossipKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GossipKind::BeaconBlock => write!(f, "beacon_block"),
            GossipKind::BeaconAggregateAndProof => write!(f, "beacon_aggregate_and_proof"),
            GossipKind::CommitteeIndex(subnet_id) => write!(f, "committee_index_{}", **subnet_id),
            GossipKind::VoluntaryExit => write!(f, "voluntary_exit"),
            GossipKind::ProposerSlashing => write!(f, "proposer_slashing"),
            GossipKind::AttesterSlashing => write!(f, "attester_slashing"),
        }
    }
}

/// The known encoding types for gossipsub messages.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum GossipEncoding {
    /// Messages are encoded with SSZ.
    SSZ,
    /// Messages are encoded with SSZSnappy.
    SSZSnappy,
}

impl Default for GossipEncoding {
    fn default() -> Self {
        GossipEncoding::SSZSnappy
    }
}

impl GossipTopic {
    pub fn new(kind: GossipKind, encoding: GossipEncoding, fork_digest: [u8; 4]) -> Self {
        GossipTopic {
            encoding,
            kind,
            fork_digest,
        }
    }

    /// Returns the encoding type for the gossipsub topic.
    pub fn encoding(&self) -> &GossipEncoding {
        &self.encoding
    }

    /// Returns a mutable reference to the fork digest of the gossipsub topic.
    pub fn digest(&mut self) -> &mut [u8; 4] {
        &mut self.fork_digest
    }

    /// Returns the kind of message expected on the gossipsub topic.
    pub fn kind(&self) -> &GossipKind {
        &self.kind
    }

    pub fn decode(topic: &str) -> Result<Self, String> {
        let topic_parts: Vec<&str> = topic.split('/').collect();
        if topic_parts.len() == 5 && topic_parts[1] == TOPIC_PREFIX {
            let digest_bytes = hex::decode(topic_parts[2])
                .map_err(|e| format!("Could not decode fork_digest hex: {}", e))?;

            if digest_bytes.len() != 4 {
                return Err(format!(
                    "Invalid gossipsub fork digest size: {}",
                    digest_bytes.len()
                ));
            }

            let mut fork_digest = [0; 4];
            fork_digest.copy_from_slice(&digest_bytes);

            let encoding = match topic_parts[4] {
                SSZ_ENCODING_POSTFIX => GossipEncoding::SSZ,
                SSZ_SNAPPY_ENCODING_POSTFIX => GossipEncoding::SSZSnappy,
                _ => return Err(format!("Unknown encoding: {}", topic)),
            };
            let kind = match topic_parts[3] {
                BEACON_BLOCK_TOPIC => GossipKind::BeaconBlock,
                BEACON_AGGREGATE_AND_PROOF_TOPIC => GossipKind::BeaconAggregateAndProof,
                VOLUNTARY_EXIT_TOPIC => GossipKind::VoluntaryExit,
                PROPOSER_SLASHING_TOPIC => GossipKind::ProposerSlashing,
                ATTESTER_SLASHING_TOPIC => GossipKind::AttesterSlashing,
                topic => match committee_topic_index(topic) {
                    Some(subnet_id) => GossipKind::CommitteeIndex(subnet_id),
                    None => return Err(format!("Unknown topic: {}", topic)),
                },
            };

            return Ok(GossipTopic {
                encoding,
                kind,
                fork_digest,
            });
        }

        Err(format!("Unknown topic: {}", topic))
    }
}

impl Into<Topic> for GossipTopic {
    fn into(self) -> Topic {
        Topic::new(self.into())
    }
}

impl Into<String> for GossipTopic {
    fn into(self) -> String {
        let encoding = match self.encoding {
            GossipEncoding::SSZ => SSZ_ENCODING_POSTFIX,
            GossipEncoding::SSZSnappy => SSZ_SNAPPY_ENCODING_POSTFIX,
        };

        let kind = match self.kind {
            GossipKind::BeaconBlock => BEACON_BLOCK_TOPIC.into(),
            GossipKind::BeaconAggregateAndProof => BEACON_AGGREGATE_AND_PROOF_TOPIC.into(),
            GossipKind::VoluntaryExit => VOLUNTARY_EXIT_TOPIC.into(),
            GossipKind::ProposerSlashing => PROPOSER_SLASHING_TOPIC.into(),
            GossipKind::AttesterSlashing => ATTESTER_SLASHING_TOPIC.into(),
            GossipKind::CommitteeIndex(index) => format!(
                "{}{}{}",
                COMMITEE_INDEX_TOPIC_PREFIX, *index, COMMITEE_INDEX_TOPIC_POSTFIX
            ),
        };
        format!(
            "/{}/{}/{}/{}",
            TOPIC_PREFIX,
            hex::encode(self.fork_digest),
            kind,
            encoding
        )
    }
}

impl From<SubnetId> for GossipKind {
    fn from(subnet_id: SubnetId) -> Self {
        GossipKind::CommitteeIndex(subnet_id)
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
