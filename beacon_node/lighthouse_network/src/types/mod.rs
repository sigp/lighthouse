pub mod error;
mod globals;
mod pubsub;
mod subnet;
mod sync_state;
mod topics;

use types::{BitVector, Epoch, EthSpec, Hash256};

pub type EnrAttestationBitfield<T> = BitVector<<T as EthSpec>::SubnetBitfieldLength>;
pub type EnrSyncCommitteeBitfield<T> = BitVector<<T as EthSpec>::SyncCommitteeSubnetCount>;

pub type Enr = discv5::enr::Enr<discv5::enr::CombinedKey>;

pub use globals::NetworkGlobals;
pub use pubsub::{PubsubMessage, SnappyTransform};
pub use subnet::{Subnet, SubnetDiscovery};
pub use sync_state::{BackFillState, SyncState};
pub use topics::{
    core_topics_to_subscribe, fork_core_topics, subnet_from_topic_hash, GossipEncoding, GossipKind,
    GossipTopic, LIGHT_CLIENT_GOSSIP_TOPICS,
};

/// Id associated to a batch processing request, either a sync batch or a parent lookup.
///
/// Shared with the `network` and `beacon_processor` crates.
#[derive(Clone, Debug, PartialEq)]
pub enum ChainSegmentProcessId {
    /// Processing Id of a range syncing batch.
    RangeBatchId(u64, Epoch),
    /// Processing ID for a backfill syncing batch.
    BackSyncBatchId(Epoch),
    /// Processing Id of the parent lookup of a block.
    ParentLookup(Hash256),
}
