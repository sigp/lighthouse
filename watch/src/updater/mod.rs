use crate::config::Config as FullConfig;
use crate::database::{
    WatchBlockPacking, WatchBlockRewards, WatchHash, WatchProposerInfo, WatchSlot,
};
use error::Error;
use eth2::{types::BlockId, BeaconNodeHttpClient};
use handler::UpdateHandler;
use log::{error, info};
use types::{BeaconBlockHeader, Epoch, Slot};

pub use config::Config;

mod config;
mod error;
pub mod handler;

pub async fn run_once(config: FullConfig) -> Result<(), Error> {
    let mut watch = UpdateHandler::new(config.clone())?;

    let sync_data = watch.ensure_bn_synced().await?;
    if watch.ensure_bn_synced().await?.is_syncing {
        error!(
            "Connected beacon node is still syncing: head_slot => {:?}, distance => {}",
            sync_data.head_slot, sync_data.sync_distance
        );
        return Err(Error::BeaconNodeSyncing);
    }

    info!("Performing head update");
    watch.perform_head_update().await?;
    info!("Performing block backfill");
    watch.backfill_canonical_slots().await?;
    info!("Updating unknown blocks");
    watch.update_unknown_blocks().await?;

    // Run additional modules
    if config.updater.proposer_info || config.updater.block_rewards {
        info!("Updating block rewards/proposer info");
        watch.fill_block_rewards_and_proposer_info().await?;
        watch.backfill_block_rewards_and_proposer_info().await?;
    }

    if config.updater.block_packing {
        info!("Updating block packing statistics");
        watch.fill_block_packing().await?;
        watch.backfill_block_packing().await?;
    }

    Ok(())
}

/// Queries the beacon node for a given `BlockId` and returns the `BeaconBlockHeader` if it exists.
pub async fn get_header(
    bn: &BeaconNodeHttpClient,
    block_id: BlockId,
) -> Result<Option<BeaconBlockHeader>, Error> {
    let resp = bn
        .get_beacon_headers_block_id(block_id)
        .await?
        .map(|resp| (resp.data.root, resp.data.header.message));
    // When quering with root == 0x000... , slot 0 will be returned with parent_root == 0x0000...
    // This check escapes the loop.
    if let Some((root, header)) = resp {
        if root == header.parent_root {
            return Ok(None);
        } else {
            return Ok(Some(header));
        }
    }
    Ok(None)
}

/// Sends a request to `lighthouse/analysis/block_rewards`.
/// Formats the response into a vector of `WatchBlockRewards` and a vector of `WatchProposerInfo`.
///
/// Will fail if `start_slot == 0`.
pub async fn get_block_rewards_and_proposer_info(
    bn: &BeaconNodeHttpClient,
    start_slot: Slot,
    end_slot: Slot,
) -> Result<(Vec<WatchBlockRewards>, Vec<WatchProposerInfo>), Error> {
    Ok(bn
        .get_lighthouse_analysis_block_rewards(start_slot, end_slot)
        .await?
        .into_iter()
        .map(|data| {
            (
                WatchBlockRewards {
                    block_root: WatchHash::from_hash(data.block_root),
                    slot: WatchSlot::from_slot(data.meta.slot),
                    total: data.total as i32,
                    attestation_reward: data.attestation_rewards.total as i32,
                    sync_committee_reward: data.sync_committee_rewards as i32,
                },
                WatchProposerInfo {
                    block_root: WatchHash::from_hash(data.block_root),
                    slot: WatchSlot::from_slot(data.meta.slot),
                    proposer_index: data.meta.proposer_index as i32,
                    graffiti: data.meta.graffiti,
                },
            )
        })
        .unzip())
}

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
            block_root: WatchHash::from_hash(data.block_hash),
            slot: WatchSlot::from_slot(data.slot),
            available: data.available_attestations as i32,
            included: data.included_attestations as i32,
            prior_skip_slots: data.prior_skip_slots as i32,
        })
        .collect())
}
