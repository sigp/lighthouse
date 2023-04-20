pub mod database;
mod server;
mod updater;

use crate::database::watch_types::WatchSlot;
use crate::updater::error::Error;

pub use database::{
    get_block_rewards_by_root, get_block_rewards_by_slot, get_highest_block_rewards,
    get_lowest_block_rewards, get_unknown_block_rewards, insert_batch_block_rewards,
    WatchBlockRewards,
};
pub use server::block_rewards_routes;

use eth2::BeaconNodeHttpClient;
use types::Slot;

/// Sends a request to `lighthouse/analysis/block_rewards`.
/// Formats the response into a vector of `WatchBlockRewards`.
///
/// Will fail if `start_slot == 0`.
pub async fn get_block_rewards(
    bn: &BeaconNodeHttpClient,
    start_slot: Slot,
    end_slot: Slot,
) -> Result<Vec<WatchBlockRewards>, Error> {
    Ok(bn
        .get_lighthouse_analysis_block_rewards(start_slot, end_slot)
        .await?
        .into_iter()
        .map(|data| WatchBlockRewards {
            slot: WatchSlot::from_slot(data.meta.slot),
            total: data.total as i32,
            attestation_reward: data.attestation_rewards.total as i32,
            sync_committee_reward: data.sync_committee_rewards as i32,
        })
        .collect())
}
