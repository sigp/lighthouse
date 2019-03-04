/// Syncing for lighthouse.
///
/// Stores the various syncing methods for the beacon chain.
mod simple_sync;

pub use crate::SimpleSync;

pub enum SyncMethod {
    SimpleSync,
}
