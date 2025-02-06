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
    all_topics_at_fork, core_topics_to_subscribe, is_fork_non_core_topic, subnet_from_topic_hash,
    GossipEncoding, GossipKind, GossipTopic, TopicConfig,
};
