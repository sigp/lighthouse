//! This provides the logic for syncing a chain when the local node is far behind it's current
//! peers.

mod batch;
mod chain;
mod chain_collection;
mod range;
mod sync_type;

pub use batch::BatchInfo;
pub use chain::{BatchId, ChainId, EPOCHS_PER_BATCH};
pub use range::RangeSync;
