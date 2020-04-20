//! Syncing for lighthouse.
//!
//! Stores the various syncing methods for the beacon chain.
mod block_processor;
pub mod manager;
mod network_context;
mod range_sync;

/// Currently implemented sync methods.
pub enum SyncMethod {
    SimpleSync,
}

pub use manager::SyncMessage;
