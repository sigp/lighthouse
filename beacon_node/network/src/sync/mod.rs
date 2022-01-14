//! Syncing for lighthouse.
//!
//! Stores the various syncing methods for the beacon chain.
mod backfill_sync;
pub mod manager;
mod network_context;
mod peer_sync_info;
mod range_sync;

pub use manager::{BatchProcessResult, SyncMessage};
pub use range_sync::ChainId;

/// Type of id of rpc requests sent by sync
pub type RequestId = usize;
