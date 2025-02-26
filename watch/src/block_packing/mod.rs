pub mod database;
pub mod server;
pub mod updater;

use crate::database::watch_types::WatchSlot;
use crate::updater::error::Error;

pub use database::{
    get_block_packing_by_root, get_block_packing_by_slot, get_highest_block_packing,
    get_lowest_block_packing, get_unknown_block_packing, insert_batch_block_packing,
    WatchBlockPacking,
};
pub use server::block_packing_routes;

use eth2::BeaconNodeHttpClient;
use types::Epoch;

/// Sends a request to `lighthouse/analysis/block_packing`.
/// Formats the response into a vector of `WatchBlockPacking`.
///
/// Will fail if `start_epoch == 0`.
pub async fn get_block_packing(
    bn: &BeaconNodeHttpClient,
    start_epoch: Epoch,
    end_epoch: Epoch,
) -> Result<Vec<WatchBlockPacking>, Error> {
    Ok(bn
        .get_lighthouse_analysis_block_packing(start_epoch, end_epoch)
        .await?
        .into_iter()
        .map(|data| WatchBlockPacking {
            slot: WatchSlot::from_slot(data.slot),
            available: data.available_attestations as i32,
            included: data.included_attestations as i32,
            prior_skip_slots: data.prior_skip_slots as i32,
        })
        .collect())
}
