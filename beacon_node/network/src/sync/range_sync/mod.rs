//! This provides the logic for syncing a chain when the local node is far behind it's current
//! peers.

mod chain;
mod chain_collection;
mod range;

pub use range::RangeSync;
