use crate::sync::custody_sync::CustodyBackfillSync;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::PeerAction;
use std::sync::Arc;

struct CustodySyncManager<T: BeaconChainTypes> {
    /// A reference to the underlying beacon chain.
    chain: Arc<BeaconChain<T>>,

    /// Custody Backfill syncing.
    custody_backfill_sync: CustodyBackfillSync<T>,
}

/// The result of processing multiple data columns for custody backfill sync.
#[derive(Debug)]
pub enum CustodyBatchProcessResult {
    /// The batch was completed successfully. It carries whether the sent batch contained data columns.
    Success {
        sent_data_columns: usize,
        imported_data_columns: usize,
    },
    /// The batch processing failed. It carries whether the processing imported any data columns.
    FaultyFailure {
        imported_data_columns: usize,
        penalty: PeerAction,
    },
    NonFaultyFailure,
}
