//! This provides the logic for syncing a chain when the local node is far behind it's current
//! peers.

mod batch;
mod chain;
mod chain_collection;
mod range;
mod sync_type;

pub use batch::{BatchConfig, BatchInfo, BatchState};
pub use chain::{BatchId, ChainId, EPOCHS_PER_BATCH};
pub use range::RangeSync;
pub use sync_type::RangeSyncType;
