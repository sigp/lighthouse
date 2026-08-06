mod globals;
mod partial;
mod pubsub;
mod subnet;
mod topics;

use ssz_types::BitVector;
use types::Spec;

pub type EnrAttestationBitfield = BitVector<typenum::U<{ Spec::SUBNET_BITFIELD_LENGTH }>>;
pub type EnrSyncCommitteeBitfield = BitVector<typenum::U<{ Spec::SYNC_COMMITTEE_SUBNET_COUNT }>>;

pub type Enr = discv5::enr::Enr<discv5::enr::CombinedKey>;

pub use eth2::lighthouse::sync_state::{BackFillState, CustodyBackFillState, SyncState};
pub use globals::NetworkGlobals;
pub use partial::HeaderSentSet;
pub use partial::OutgoingPartialColumn;
pub use pubsub::{PubsubMessage, PubsubPartialMessage, SnappyTransform, decode_partial};
pub use subnet::{Subnet, SubnetDiscovery};
pub use topics::{
    GossipEncoding, GossipKind, GossipTopic, TopicConfig, all_topics_at_fork,
    core_topics_to_subscribe, is_fork_non_core_topic, subnet_from_topic_hash,
};
