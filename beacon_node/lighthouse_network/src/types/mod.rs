pub mod error;
mod globals;
mod pubsub;
mod subnet;
mod sync_state;
mod topics;

use types::{BitVector, EthSpec};

pub type EnrAttestationBitfield<E> = BitVector<<E as EthSpec>::SubnetBitfieldLength>;
pub type EnrSyncCommitteeBitfield<E> = BitVector<<E as EthSpec>::SyncCommitteeSubnetCount>;

pub type Enr = discv5::enr::Enr<discv5::enr::CombinedKey>;

pub use globals::NetworkGlobals;
pub use pubsub::{PubsubMessage, SnappyTransform};
pub use subnet::{Subnet, SubnetDiscovery};
pub use sync_state::{BackFillState, SyncState};
pub use topics::{
    attestation_sync_committee_topics, core_topics_to_subscribe, fork_core_topics,
    subnet_from_topic_hash, GossipEncoding, GossipKind, GossipTopic, ALTAIR_CORE_TOPICS,
    BASE_CORE_TOPICS, CAPELLA_CORE_TOPICS, DENEB_CORE_TOPICS, LIGHT_CLIENT_GOSSIP_TOPICS,
};
