pub mod error;
mod globals;
mod pubsub;
mod subnet;
mod sync_state;
mod topics;

use types::{BitVector, EthSpec};

pub type EnrAttestationBitfield<T> = BitVector<<T as EthSpec>::SubnetBitfieldLength>;
pub type EnrSyncCommitteeBitfield<T> = BitVector<<T as EthSpec>::SyncCommitteeSubnetCount>;

pub type Enr = discv5::enr::Enr<discv5::enr::CombinedKey>;

pub use globals::NetworkGlobals;
pub use pubsub::{PubsubMessage, SnappyTransform};
pub use subnet::{Subnet, SubnetDiscovery};
pub use sync_state::{BackFillState, SyncState};
pub use topics::{subnet_from_topic_hash, GossipEncoding, GossipKind, GossipTopic, CORE_TOPICS};
