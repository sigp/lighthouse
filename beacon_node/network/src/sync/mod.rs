//! Syncing for lighthouse.
//!
//! Stores the various syncing methods for the beacon chain.
pub mod manager;
mod network_context;
mod peer_sync_info;
mod range_sync;

pub use manager::{BatchProcessResult, SyncMessage};
pub use peer_sync_info::PeerSyncInfo;
pub use range_sync::{BatchId, ChainId};

/// Type of id of rpc requests sent by sync
pub type RequestId = usize;
