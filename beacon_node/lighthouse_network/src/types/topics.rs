use gossipsub::{IdentTopic as Topic, TopicHash};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use strum::AsRefStr;
use types::{
    ChainSpec, DataColumnSubnetId, Epoch, EthSpec, ForkName, SubnetId, SyncSubnetId, Unsigned,
};

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

#[derive(Default)]
pub struct TopicSubscriptionOpts {
    pub enable_light_client_server: bool,
    pub subscribe_all_subnets: bool,
    pub subscribe_all_data_column_subnets: bool,
    pub custody_subnets: Vec<DataColumnSubnetId>,
}

/// Returns all the topics the node should subscribe at `epoch`
pub fn core_topics_to_subscribe<E: EthSpec>(
    spec: &ChainSpec,
    epoch: Epoch,
    opts: &TopicSubscriptionOpts,
) -> Vec<GossipKind> {
    let fork_name = spec.fork_name_at_epoch(epoch);

    let mut topics = vec![
        GossipKind::BeaconBlock,
        GossipKind::BeaconAggregateAndProof,
        GossipKind::VoluntaryExit,
        GossipKind::ProposerSlashing,
        GossipKind::AttesterSlashing,
    ];

    if opts.subscribe_all_subnets {
        for index in 0..spec.attestation_subnet_count {
            topics.push(GossipKind::Attestation(index.into()));
        }
    }

    if fork_name.altair_enabled() {
        topics.push(GossipKind::SignedContributionAndProof);

        if opts.subscribe_all_subnets {
            for index in 0..E::SyncCommitteeSubnetCount::to_u64() {
                topics.push(GossipKind::SyncCommitteeMessage(index.into()));
            }
        }

        if opts.enable_light_client_server {
            topics.push(GossipKind::LightClientFinalityUpdate);
            topics.push(GossipKind::LightClientOptimisticUpdate);
        }
    }

    if fork_name.capella_enabled() {
        topics.push(GossipKind::BlsToExecutionChange);
    }

    if fork_name.deneb_enabled() && !spec.is_peer_das_enabled_for_epoch(epoch) {
        // All of deneb blob topics are core topics
        for i in 0..spec.blob_sidecar_subnet_count {
            topics.push(GossipKind::BlobSidecar(i));
        }
    }

    if spec.is_peer_das_enabled_for_epoch(epoch) {
        if opts.subscribe_all_data_column_subnets {
            for index in 0..spec.data_column_sidecar_subnet_count {
                topics.push(GossipKind::DataColumnSidecar(index.into()));
            }
        } else {
            for &index in &opts.custody_subnets {
                topics.push(GossipKind::DataColumnSidecar(index));
            }
        }
    }

    topics
}

pub fn new_topics_to_subscribe_at_epoch<E: EthSpec>(
    spec: &ChainSpec,
    next_epoch: Epoch,
    opts: &TopicSubscriptionOpts,
) -> Vec<GossipKind> {
    if next_epoch == Epoch::new(0) {
        // Handle the genesis case explicitly. Otherwise prev_set == next_set and the node will not
        // subscribe to anything
        core_topics_to_subscribe::<E>(spec, next_epoch, opts)
    } else {
        let prev_epoch = next_epoch.saturating_sub(Epoch::new(1));
        let prev_set = core_topics_to_subscribe::<E>(spec, prev_epoch, opts)
            .into_iter()
            .collect::<HashSet<_>>();
        let next_set = core_topics_to_subscribe::<E>(spec, next_epoch, opts)
            .into_iter()
            .collect::<HashSet<_>>();
        next_set.difference(&prev_set).cloned().collect()
    }
}

pub fn old_topics_to_unsubscribe_at_epoch<E: EthSpec>(
    spec: &ChainSpec,
    next_epoch: Epoch,
    opts: &TopicSubscriptionOpts,
) -> Vec<GossipKind> {
    // No need to handle genesis case explicitly, as we never need to unsubscribe anything at
    // genesis. Because prev_set == next_set at genesis, this function will return `vec![]`
    let prev_epoch = next_epoch.saturating_sub(Epoch::new(1));
    let prev_set = core_topics_to_subscribe::<E>(spec, prev_epoch, opts)
        .into_iter()
        .collect::<HashSet<_>>();
    let next_set = core_topics_to_subscribe::<E>(spec, next_epoch, opts)
        .into_iter()
        .collect::<HashSet<_>>();
    prev_set.difference(&next_set).cloned().collect()
}

pub fn all_topics_at_fork<E: EthSpec>(spec: &ChainSpec, epoch: Epoch) -> Vec<GossipKind> {
    // Compute the worst case of all forks
    let opts = TopicSubscriptionOpts {
        enable_light_client_server: true,
        subscribe_all_subnets: true,
        subscribe_all_data_column_subnets: true,
        custody_subnets: vec![],
    };
    core_topics_to_subscribe::<E>(spec, epoch, &opts)
}

/// Returns the list of all possible topics across known forks
pub fn all_topics<E: EthSpec>(spec: &ChainSpec) -> Vec<GossipKind> {
    ForkName::list_all()
        .iter()
        // Only forks that are scheduled (fork declared and not far future)
        .filter_map(|fork| spec.fork_epoch(*fork))
        .filter(|epoch| epoch != &Epoch::max_value())
        .flat_map(|epoch| all_topics_at_fork::<E>(spec, epoch))
        .unique()
        .collect()
}

/// Returns the max count of topics at any given fork
pub fn max_topic_count<E: EthSpec>(spec: &ChainSpec) -> usize {
    ForkName::list_all()
        .iter()
        .filter_map(|fork| spec.fork_epoch(*fork))
        .map(|epoch| all_topics_at_fork::<E>(spec, epoch).len())
        .max()
        .unwrap_or(0)
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

    type E = MainnetEthSpec;

    fn get_spec() -> ChainSpec {
        let mut spec = E::default_spec();
        spec.altair_fork_epoch = Some(Epoch::new(1));
        spec.bellatrix_fork_epoch = Some(Epoch::new(2));
        spec.capella_fork_epoch = Some(Epoch::new(3));
        spec.deneb_fork_epoch = Some(Epoch::new(4));
        spec.eip7594_fork_epoch = Some(Epoch::new(99));
        spec
    }

    #[test]
    fn base_topics_are_always_active() {
        let spec = get_spec();
        for fork in ForkName::list_all() {
            assert!(core_topics_to_subscribe::<E>(
                &spec,
                spec.fork_epoch(fork).unwrap_or(Epoch::max_value()),
                &TopicSubscriptionOpts::default()
            )
            .contains(&GossipKind::BeaconBlock));
        }
    }

    #[test]
    fn blobs_are_not_subscribed_in_peerdas() {
        let spec = get_spec();
        assert!(!core_topics_to_subscribe::<E>(
            &spec,
            spec.eip7594_fork_epoch.unwrap(),
            &TopicSubscriptionOpts::default()
        )
        .contains(&GossipKind::BlobSidecar(0)));
    }

    #[test]
    fn columns_are_subscribed_in_peerdas() {
        let spec = get_spec();
        assert!(core_topics_to_subscribe::<E>(
            &spec,
            spec.eip7594_fork_epoch.unwrap(),
            &TopicSubscriptionOpts {
                subscribe_all_data_column_subnets: true,
                ..Default::default()
            }
        )
        .contains(&GossipKind::DataColumnSidecar(0.into())));
    }
}
