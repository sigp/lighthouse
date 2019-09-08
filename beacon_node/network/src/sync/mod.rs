mod manager;
/// Syncing for lighthouse.
///
/// Stores the various syncing methods for the beacon chain.
mod simple_sync;

pub use simple_sync::MessageProcessor;

/// Currently implemented sync methods.
pub enum SyncMethod {
    SimpleSync,
}
