use libp2p::gossipsub::{IdentTopic as Topic, TopicHash};
use serde_derive::{Deserialize, Serialize};
use strum::AsRefStr;
use types::SubnetId;

/// The gossipsub topic names.
// These constants form a topic name of the form /TOPIC_PREFIX/TOPIC/ENCODING_POSTFIX
// For example /eth2/beacon_block/ssz
pub const TOPIC_PREFIX: &str = "eth2";
pub const SSZ_SNAPPY_ENCODING_POSTFIX: &str = "ssz_snappy";
pub const BEACON_BLOCK_TOPIC: &str = "beacon_block";
pub const BEACON_AGGREGATE_AND_PROOF_TOPIC: &str = "beacon_aggregate_and_proof";
pub const BEACON_ATTESTATION_PREFIX: &str = "beacon_attestation_";
pub const VOLUNTARY_EXIT_TOPIC: &str = "voluntary_exit";
pub const PROPOSER_SLASHING_TOPIC: &str = "proposer_slashing";
pub const ATTESTER_SLASHING_TOPIC: &str = "attester_slashing";

pub const CORE_TOPICS: [GossipKind; 5] = [
    GossipKind::BeaconBlock,
    GossipKind::BeaconAggregateAndProof,
    GossipKind::VoluntaryExit,
    GossipKind::ProposerSlashing,
    GossipKind::AttesterSlashing,
];

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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum GossipKind {
    /// Topic for publishing beacon blocks.
    BeaconBlock,
    /// Topic for publishing aggregate attestations and proofs.
    BeaconAggregateAndProof,
    /// Topic for publishing raw attestations on a particular subnet.
    #[strum(serialize = "beacon_attestation")]
    Attestation(SubnetId),
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
            GossipKind::Attestation(subnet_id) => write!(f, "beacon_attestation_{}", **subnet_id),
            x => f.write_str(x.as_ref()),
        }
    }
}

/// The known encoding types for gossipsub messages.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum GossipEncoding {
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
            fork_digest,
            kind,
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
                    Some(subnet_id) => GossipKind::Attestation(subnet_id),
                    None => return Err(format!("Unknown topic: {}", topic)),
                },
            };

            return Ok(GossipTopic {
                encoding,
                fork_digest,
                kind,
            });
        }

        Err(format!("Unknown topic: {}", topic))
    }
}

impl Into<Topic> for GossipTopic {
    fn into(self) -> Topic {
        Topic::new(self)
    }
}

impl Into<String> for GossipTopic {
    fn into(self) -> String {
        let encoding = match self.encoding {
            GossipEncoding::SSZSnappy => SSZ_SNAPPY_ENCODING_POSTFIX,
        };

        let kind = match self.kind {
            GossipKind::BeaconBlock => BEACON_BLOCK_TOPIC.into(),
            GossipKind::BeaconAggregateAndProof => BEACON_AGGREGATE_AND_PROOF_TOPIC.into(),
            GossipKind::VoluntaryExit => VOLUNTARY_EXIT_TOPIC.into(),
            GossipKind::ProposerSlashing => PROPOSER_SLASHING_TOPIC.into(),
            GossipKind::AttesterSlashing => ATTESTER_SLASHING_TOPIC.into(),
            GossipKind::Attestation(index) => format!("{}{}", BEACON_ATTESTATION_PREFIX, *index,),
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
        GossipKind::Attestation(subnet_id)
    }
}

// helper functions

/// Get subnet id from an attestation subnet topic hash.
pub fn subnet_id_from_topic_hash(topic_hash: &TopicHash) -> Option<SubnetId> {
    let gossip_topic = GossipTopic::decode(topic_hash.as_str()).ok()?;
    if let GossipKind::Attestation(subnet_id) = gossip_topic.kind() {
        return Some(*subnet_id);
    }
    None
}

// Determines if a string is a committee topic.
fn committee_topic_index(topic: &str) -> Option<SubnetId> {
    if topic.starts_with(BEACON_ATTESTATION_PREFIX) {
        return Some(SubnetId::new(
            topic
                .trim_start_matches(BEACON_ATTESTATION_PREFIX)
                .parse::<u64>()
                .ok()?,
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::GossipKind::*;
    use super::*;

    const GOOD_FORK_DIGEST: &str = "e1925f3b";
    const BAD_PREFIX: &str = "tezos";
    const BAD_FORK_DIGEST: &str = "e1925f3b4b";
    const BAD_ENCODING: &str = "rlp";
    const BAD_KIND: &str = "blocks";

    fn topics() -> Vec<String> {
        let mut topics = Vec::new();
        let fork_digest: [u8; 4] = [1, 2, 3, 4];
        for encoding in [GossipEncoding::SSZSnappy].iter() {
            for kind in [
                BeaconBlock,
                BeaconAggregateAndProof,
                Attestation(SubnetId::new(42)),
                VoluntaryExit,
                ProposerSlashing,
                AttesterSlashing,
            ]
            .iter()
            {
                topics.push(GossipTopic::new(kind.clone(), encoding.clone(), fork_digest).into());
            }
        }
        topics
    }

    fn create_topic(prefix: &str, fork_digest: &str, kind: &str, encoding: &str) -> String {
        format!("/{}/{}/{}/{}", prefix, fork_digest, kind, encoding)
    }

    #[test]
    fn test_decode() {
        for topic in topics().iter() {
            assert!(GossipTopic::decode(topic.as_str()).is_ok());
        }
    }

    #[test]
    fn test_decode_malicious() {
        let bad_prefix_str = create_topic(
            BAD_PREFIX,
            GOOD_FORK_DIGEST,
            BEACON_BLOCK_TOPIC,
            SSZ_SNAPPY_ENCODING_POSTFIX,
        );
        assert!(GossipTopic::decode(bad_prefix_str.as_str()).is_err());

        let bad_digest_str = create_topic(
            TOPIC_PREFIX,
            BAD_FORK_DIGEST,
            BEACON_BLOCK_TOPIC,
            SSZ_SNAPPY_ENCODING_POSTFIX,
        );
        assert!(GossipTopic::decode(bad_digest_str.as_str()).is_err());

        let bad_kind_str = create_topic(
            TOPIC_PREFIX,
            GOOD_FORK_DIGEST,
            BAD_KIND,
            SSZ_SNAPPY_ENCODING_POSTFIX,
        );
        assert!(GossipTopic::decode(bad_kind_str.as_str()).is_err());

        let bad_encoding_str = create_topic(
            TOPIC_PREFIX,
            GOOD_FORK_DIGEST,
            BEACON_BLOCK_TOPIC,
            BAD_ENCODING,
        );
        assert!(GossipTopic::decode(bad_encoding_str.as_str()).is_err());

        // Extra parts
        assert!(
            GossipTopic::decode("/eth2/e1925f3b/beacon_block/ssz_snappy/yolo").is_err(),
            "should have exactly 5 parts"
        );
        // Empty string
        assert!(GossipTopic::decode("").is_err());
        // Empty parts
        assert!(GossipTopic::decode("////").is_err());
    }

    #[test]
    fn test_subnet_id_from_topic_hash() {
        let topic_hash = TopicHash::from_raw("/eth2/e1925f3b/beacon_block/ssz_snappy");
        assert!(subnet_id_from_topic_hash(&topic_hash).is_none());

        let topic_hash = TopicHash::from_raw("/eth2/e1925f3b/beacon_attestation_42/ssz_snappy");
        assert_eq!(
            subnet_id_from_topic_hash(&topic_hash),
            Some(SubnetId::new(42))
        );
    }

    #[test]
    fn test_as_str_ref() {
        assert_eq!("beacon_block", BeaconBlock.as_ref());
        assert_eq!(
            "beacon_aggregate_and_proof",
            BeaconAggregateAndProof.as_ref()
        );
        assert_eq!(
            "beacon_attestation",
            Attestation(SubnetId::new(42)).as_ref()
        );
        assert_eq!("voluntary_exit", VoluntaryExit.as_ref());
        assert_eq!("proposer_slashing", ProposerSlashing.as_ref());
        assert_eq!("attester_slashing", AttesterSlashing.as_ref());
    }
}
