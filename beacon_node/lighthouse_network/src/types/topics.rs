use gossipsub::{IdentTopic as Topic, TopicHash};
use serde::{Deserialize, Serialize};
use strum::AsRefStr;
use types::{ChainSpec, DataColumnSubnetId, EthSpec, ForkName, SubnetId, SyncSubnetId, Unsigned};

use crate::Subnet;

/// The gossipsub topic names.
// These constants form a topic name of the form /TOPIC_PREFIX/TOPIC/ENCODING_POSTFIX
// For example /eth2/beacon_block/ssz
pub const TOPIC_PREFIX: &str = "eth2";
pub const SSZ_SNAPPY_ENCODING_POSTFIX: &str = "ssz_snappy";
pub const BEACON_BLOCK_TOPIC: &str = "beacon_block";
pub const BEACON_AGGREGATE_AND_PROOF_TOPIC: &str = "beacon_aggregate_and_proof";
pub const BEACON_ATTESTATION_PREFIX: &str = "beacon_attestation_";
pub const BLOB_SIDECAR_PREFIX: &str = "blob_sidecar_";
pub const DATA_COLUMN_SIDECAR_PREFIX: &str = "data_column_sidecar_";
pub const VOLUNTARY_EXIT_TOPIC: &str = "voluntary_exit";
pub const PROPOSER_SLASHING_TOPIC: &str = "proposer_slashing";
pub const ATTESTER_SLASHING_TOPIC: &str = "attester_slashing";
pub const SIGNED_CONTRIBUTION_AND_PROOF_TOPIC: &str = "sync_committee_contribution_and_proof";
pub const SYNC_COMMITTEE_PREFIX_TOPIC: &str = "sync_committee_";
pub const BLS_TO_EXECUTION_CHANGE_TOPIC: &str = "bls_to_execution_change";
pub const LIGHT_CLIENT_FINALITY_UPDATE: &str = "light_client_finality_update";
pub const LIGHT_CLIENT_OPTIMISTIC_UPDATE: &str = "light_client_optimistic_update";

pub const BASE_CORE_TOPICS: [GossipKind; 5] = [
    GossipKind::BeaconBlock,
    GossipKind::BeaconAggregateAndProof,
    GossipKind::VoluntaryExit,
    GossipKind::ProposerSlashing,
    GossipKind::AttesterSlashing,
];

pub const ALTAIR_CORE_TOPICS: [GossipKind; 1] = [GossipKind::SignedContributionAndProof];

pub const CAPELLA_CORE_TOPICS: [GossipKind; 1] = [GossipKind::BlsToExecutionChange];

pub const LIGHT_CLIENT_GOSSIP_TOPICS: [GossipKind; 2] = [
    GossipKind::LightClientFinalityUpdate,
    GossipKind::LightClientOptimisticUpdate,
];

pub const DENEB_CORE_TOPICS: [GossipKind; 0] = [];

/// Returns the core topics associated with each fork that are new to the previous fork
pub fn fork_core_topics<E: EthSpec>(fork_name: &ForkName, spec: &ChainSpec) -> Vec<GossipKind> {
    match fork_name {
        ForkName::Base => BASE_CORE_TOPICS.to_vec(),
        ForkName::Altair => ALTAIR_CORE_TOPICS.to_vec(),
        ForkName::Bellatrix => vec![],
        ForkName::Capella => CAPELLA_CORE_TOPICS.to_vec(),
        ForkName::Deneb => {
            // All of deneb blob topics are core topics
            let mut deneb_blob_topics = Vec::new();
            for i in 0..spec.blob_sidecar_subnet_count {
                deneb_blob_topics.push(GossipKind::BlobSidecar(i));
            }
            let mut deneb_topics = DENEB_CORE_TOPICS.to_vec();
            deneb_topics.append(&mut deneb_blob_topics);
            deneb_topics
        }
        ForkName::Electra => vec![],
        ForkName::EIP7732 => todo!("EIP-7732 core topics"),
    }
}

/// Returns all the attestation and sync committee topics, for a given fork.
pub fn attestation_sync_committee_topics<E: EthSpec>() -> impl Iterator<Item = GossipKind> {
    (0..E::SubnetBitfieldLength::to_usize())
        .map(|subnet_id| GossipKind::Attestation(SubnetId::new(subnet_id as u64)))
        .chain(
            (0..E::SyncCommitteeSubnetCount::to_usize()).map(|sync_committee_id| {
                GossipKind::SyncCommitteeMessage(SyncSubnetId::new(sync_committee_id as u64))
            }),
        )
}

/// Returns all the topics that we need to subscribe to for a given fork
/// including topics from older forks and new topics for the current fork.
pub fn core_topics_to_subscribe<E: EthSpec>(
    mut current_fork: ForkName,
    spec: &ChainSpec,
) -> Vec<GossipKind> {
    let mut topics = fork_core_topics::<E>(&current_fork, spec);
    while let Some(previous_fork) = current_fork.previous_fork() {
        let previous_fork_topics = fork_core_topics::<E>(&previous_fork, spec);
        topics.extend(previous_fork_topics);
        current_fork = previous_fork;
    }
    topics
}

/// A gossipsub topic which encapsulates the type of messages that should be sent and received over
/// the pubsub protocol and the way the messages should be encoded.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GossipTopic {
    /// The encoding of the topic.
    encoding: GossipEncoding,
    /// The fork digest of the topic,
    pub fork_digest: [u8; 4],
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
    /// Topic for publishing BlobSidecars.
    BlobSidecar(u64),
    /// Topic for publishing DataColumnSidecars.
    DataColumnSidecar(DataColumnSubnetId),
    /// Topic for publishing raw attestations on a particular subnet.
    #[strum(serialize = "beacon_attestation")]
    Attestation(SubnetId),
    /// Topic for publishing voluntary exits.
    VoluntaryExit,
    /// Topic for publishing block proposer slashings.
    ProposerSlashing,
    /// Topic for publishing attester slashings.
    AttesterSlashing,
    /// Topic for publishing partially aggregated sync committee signatures.
    SignedContributionAndProof,
    /// Topic for publishing unaggregated sync committee signatures on a particular subnet.
    #[strum(serialize = "sync_committee")]
    SyncCommitteeMessage(SyncSubnetId),
    /// Topic for validator messages which change their withdrawal address.
    BlsToExecutionChange,
    /// Topic for publishing finality updates for light clients.
    LightClientFinalityUpdate,
    /// Topic for publishing optimistic updates for light clients.
    LightClientOptimisticUpdate,
}

impl std::fmt::Display for GossipKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GossipKind::Attestation(subnet_id) => write!(f, "beacon_attestation_{}", **subnet_id),
            GossipKind::SyncCommitteeMessage(subnet_id) => {
                write!(f, "sync_committee_{}", **subnet_id)
            }
            GossipKind::BlobSidecar(blob_index) => {
                write!(f, "{}{}", BLOB_SIDECAR_PREFIX, blob_index)
            }
            GossipKind::DataColumnSidecar(column_index) => {
                write!(f, "{}{}", DATA_COLUMN_SIDECAR_PREFIX, **column_index)
            }
            x => f.write_str(x.as_ref()),
        }
    }
}

/// The known encoding types for gossipsub messages.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub enum GossipEncoding {
    /// Messages are encoded with SSZSnappy.
    #[default]
    SSZSnappy,
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
                SIGNED_CONTRIBUTION_AND_PROOF_TOPIC => GossipKind::SignedContributionAndProof,
                VOLUNTARY_EXIT_TOPIC => GossipKind::VoluntaryExit,
                PROPOSER_SLASHING_TOPIC => GossipKind::ProposerSlashing,
                ATTESTER_SLASHING_TOPIC => GossipKind::AttesterSlashing,
                BLS_TO_EXECUTION_CHANGE_TOPIC => GossipKind::BlsToExecutionChange,
                LIGHT_CLIENT_FINALITY_UPDATE => GossipKind::LightClientFinalityUpdate,
                LIGHT_CLIENT_OPTIMISTIC_UPDATE => GossipKind::LightClientOptimisticUpdate,
                topic => match subnet_topic_index(topic) {
                    Some(kind) => kind,
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

    pub fn subnet_id(&self) -> Option<Subnet> {
        match self.kind() {
            GossipKind::Attestation(subnet_id) => Some(Subnet::Attestation(*subnet_id)),
            GossipKind::SyncCommitteeMessage(subnet_id) => Some(Subnet::SyncCommittee(*subnet_id)),
            GossipKind::DataColumnSidecar(subnet_id) => Some(Subnet::DataColumn(*subnet_id)),
            _ => None,
        }
    }
}

impl From<GossipTopic> for Topic {
    fn from(topic: GossipTopic) -> Topic {
        Topic::new(topic)
    }
}

impl From<GossipTopic> for String {
    fn from(topic: GossipTopic) -> String {
        // Use the `Display` implementation below.
        topic.to_string()
    }
}

impl std::fmt::Display for GossipTopic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
            GossipKind::SignedContributionAndProof => SIGNED_CONTRIBUTION_AND_PROOF_TOPIC.into(),
            GossipKind::SyncCommitteeMessage(index) => {
                format!("{}{}", SYNC_COMMITTEE_PREFIX_TOPIC, *index)
            }
            GossipKind::BlobSidecar(blob_index) => {
                format!("{}{}", BLOB_SIDECAR_PREFIX, blob_index)
            }
            GossipKind::DataColumnSidecar(index) => {
                format!("{}{}", DATA_COLUMN_SIDECAR_PREFIX, *index)
            }
            GossipKind::BlsToExecutionChange => BLS_TO_EXECUTION_CHANGE_TOPIC.into(),
            GossipKind::LightClientFinalityUpdate => LIGHT_CLIENT_FINALITY_UPDATE.into(),
            GossipKind::LightClientOptimisticUpdate => LIGHT_CLIENT_OPTIMISTIC_UPDATE.into(),
        };
        write!(
            f,
            "/{}/{}/{}/{}",
            TOPIC_PREFIX,
            hex::encode(self.fork_digest),
            kind,
            encoding
        )
    }
}

impl From<Subnet> for GossipKind {
    fn from(subnet_id: Subnet) -> Self {
        match subnet_id {
            Subnet::Attestation(s) => GossipKind::Attestation(s),
            Subnet::SyncCommittee(s) => GossipKind::SyncCommitteeMessage(s),
            Subnet::DataColumn(s) => GossipKind::DataColumnSidecar(s),
        }
    }
}

// helper functions

/// Get subnet id from an attestation subnet topic hash.
pub fn subnet_from_topic_hash(topic_hash: &TopicHash) -> Option<Subnet> {
    GossipTopic::decode(topic_hash.as_str()).ok()?.subnet_id()
}

// Determines if the topic name is of an indexed topic.
fn subnet_topic_index(topic: &str) -> Option<GossipKind> {
    if let Some(index) = topic.strip_prefix(BEACON_ATTESTATION_PREFIX) {
        return Some(GossipKind::Attestation(SubnetId::new(
            index.parse::<u64>().ok()?,
        )));
    } else if let Some(index) = topic.strip_prefix(SYNC_COMMITTEE_PREFIX_TOPIC) {
        return Some(GossipKind::SyncCommitteeMessage(SyncSubnetId::new(
            index.parse::<u64>().ok()?,
        )));
    } else if let Some(index) = topic.strip_prefix(BLOB_SIDECAR_PREFIX) {
        return Some(GossipKind::BlobSidecar(index.parse::<u64>().ok()?));
    } else if let Some(index) = topic.strip_prefix(DATA_COLUMN_SIDECAR_PREFIX) {
        return Some(GossipKind::DataColumnSidecar(DataColumnSubnetId::new(
            index.parse::<u64>().ok()?,
        )));
    }
    None
}

#[cfg(test)]
mod tests {
    use types::MainnetEthSpec;

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
                SignedContributionAndProof,
                Attestation(SubnetId::new(42)),
                SyncCommitteeMessage(SyncSubnetId::new(42)),
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
    fn test_subnet_from_topic_hash() {
        let topic_hash = TopicHash::from_raw("/eth2/e1925f3b/beacon_block/ssz_snappy");
        assert!(subnet_from_topic_hash(&topic_hash).is_none());

        let topic_hash = TopicHash::from_raw("/eth2/e1925f3b/beacon_attestation_42/ssz_snappy");
        assert_eq!(
            subnet_from_topic_hash(&topic_hash),
            Some(Subnet::Attestation(SubnetId::new(42)))
        );

        let topic_hash = TopicHash::from_raw("/eth2/e1925f3b/sync_committee_42/ssz_snappy");
        assert_eq!(
            subnet_from_topic_hash(&topic_hash),
            Some(Subnet::SyncCommittee(SyncSubnetId::new(42)))
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

        assert_eq!(
            "sync_committee",
            SyncCommitteeMessage(SyncSubnetId::new(42)).as_ref()
        );
        assert_eq!("voluntary_exit", VoluntaryExit.as_ref());
        assert_eq!("proposer_slashing", ProposerSlashing.as_ref());
        assert_eq!("attester_slashing", AttesterSlashing.as_ref());
    }

    #[test]
    fn test_core_topics_to_subscribe() {
        type E = MainnetEthSpec;
        let spec = E::default_spec();
        let mut all_topics = Vec::new();
        let mut deneb_core_topics = fork_core_topics::<E>(&ForkName::Deneb, &spec);
        all_topics.append(&mut deneb_core_topics);
        all_topics.extend(CAPELLA_CORE_TOPICS);
        all_topics.extend(ALTAIR_CORE_TOPICS);
        all_topics.extend(BASE_CORE_TOPICS);

        let latest_fork = *ForkName::list_all().last().unwrap();
        assert_eq!(
            core_topics_to_subscribe::<E>(latest_fork, &spec),
            all_topics
        );
    }
}
