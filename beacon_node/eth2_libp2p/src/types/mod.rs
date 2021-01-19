pub mod error;
mod globals;
mod pubsub;
mod subnet;
mod sync_state;
mod topics;

use types::{BitVector, EthSpec};

#[allow(type_alias_bounds)]
pub type EnrBitfield<T: EthSpec> = BitVector<T::SubnetBitfieldLength>;

pub type Enr = discv5::enr::Enr<discv5::enr::CombinedKey>;

pub use globals::NetworkGlobals;
pub use pubsub::{PubsubMessage, SnappyTransform};
pub use subnet::SubnetDiscovery;
pub use sync_state::SyncState;
pub use topics::{subnet_id_from_topic_hash, GossipEncoding, GossipKind, GossipTopic, CORE_TOPICS};
