pub mod error;
mod globals;
mod pubsub;
mod sync_state;
mod topics;

use types::{BitVector, EthSpec};

#[allow(type_alias_bounds)]
pub type EnrBitfield<T: EthSpec> = BitVector<T::SubnetBitfieldLength>;

pub type Enr = libp2p::discv5::enr::Enr<libp2p::discv5::enr::CombinedKey>;

pub use globals::NetworkGlobals;
pub use pubsub::PubsubMessage;
pub use sync_state::SyncState;
pub use topics::{GossipEncoding, GossipKind, GossipTopic};
