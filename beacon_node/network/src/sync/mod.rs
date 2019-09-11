//! Syncing for lighthouse.
//!
//! Stores the various syncing methods for the beacon chain.
mod manager;
mod message_processor;

pub use message_processor::MessageProcessor;

/// Currently implemented sync methods.
pub enum SyncMethod {
    SimpleSync,
}
