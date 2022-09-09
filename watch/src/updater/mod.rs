use crate::config::Config as FullConfig;
use crate::database::{
    WatchBlockPacking, WatchBlockRewards, WatchPK, WatchProposerInfo, WatchSlot,
    WatchSuboptimalAttestation, WatchValidator,
};
use error::Error;
use eth2::{
    types::{BlockId, StateId},
    BeaconNodeHttpClient,
};
use handler::UpdateHandler;
use log::{debug, error, info};
use std::collections::HashSet;
use std::time::Instant;
use types::{BeaconBlockHeader, Epoch, Slot};

pub use config::Config;

mod config;
mod error;
pub mod handler;

const FAR_FUTURE_EPOCH: u64 = u64::MAX;

pub async fn run_once(config: FullConfig) -> Result<(), Error> {
    let mut watch = UpdateHandler::new(config.clone()).await?;

    let sync_data = watch.get_bn_syncing_status().await?;
    if sync_data.is_syncing {
        error!(
            "Connected beacon node is still syncing: head_slot => {:?}, distance => {}",
            sync_data.head_slot, sync_data.sync_distance
        );
        return Err(Error::BeaconNodeSyncing);
    }

    info!("Performing head update");
    let head_timer = Instant::now();
    watch.perform_head_update().await?;
    let head_timer_elapsed = head_timer.elapsed();
    debug!("Head update complete, time taken: {head_timer_elapsed:?}");

    info!("Performing block backfill");
    let block_backfill_timer = Instant::now();
    watch.backfill_canonical_slots().await?;
    let block_backfill_timer_elapsed = block_backfill_timer.elapsed();
    debug!("Block backfill complete, time taken: {block_backfill_timer_elapsed:?}");

    info!("Updating unknown blocks");
    let unknown_block_timer = Instant::now();
    watch.update_unknown_blocks().await?;
    let unknown_block_timer_elapsed = unknown_block_timer.elapsed();
    debug!("Unknown block update complete, time taken: {unknown_block_timer_elapsed:?}");

    info!("Updating validator set");
    let validator_timer = Instant::now();
    watch.update_validator_set().await?;
    let validator_timer_elapsed = validator_timer.elapsed();
    debug!("Validator update complete, time taken: {validator_timer_elapsed:?}");

    // Run additional modules
    if config.updater.attestations {
        info!("Updating suboptimal attestations");
        let attestation_timer = Instant::now();
        watch.fill_suboptimal_attestations().await?;
        watch.backfill_suboptimal_attestations().await?;
        let attestation_timer_elapsed = attestation_timer.elapsed();
        debug!("Attestation update complete, time taken: {attestation_timer_elapsed:?}");
    }

    if config.updater.proposer_info || config.updater.block_rewards {
        info!("Updating block rewards/proposer info");
        let proposer_timer = Instant::now();
        watch.fill_block_rewards_and_proposer_info().await?;
        watch.backfill_block_rewards_and_proposer_info().await?;
        let proposer_timer_elapsed = proposer_timer.elapsed();
        debug!(
            "Block Rewards/Proposer info update complete, time taken: {proposer_timer_elapsed:?}"
        );
    }

    if config.updater.block_packing {
        info!("Updating block packing statistics");
        let packing_timer = Instant::now();
        watch.fill_block_packing().await?;
        watch.backfill_block_packing().await?;
        let packing_timer_elapsed = packing_timer.elapsed();
        debug!("Block packing update complete, time taken: {packing_timer_elapsed:?}");
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

/// Queries the beacon node for the current validator set.
pub async fn get_validators(bn: &BeaconNodeHttpClient) -> Result<HashSet<WatchValidator>, Error> {
    let mut validator_map = HashSet::new();

    let validators = bn
        .get_beacon_states_validators(StateId::Head, None, None)
        .await?
        .ok_or(Error::NoValidatorsFound)?
        .data;

    for val in validators {
        // Only store `activation_epoch` if it not the `FAR_FUTURE_EPOCH`.
        let activation_epoch = if val.validator.activation_epoch.as_u64() == FAR_FUTURE_EPOCH {
            None
        } else {
            Some(val.validator.activation_epoch.as_u64() as i32)
        };
        // Only store `exit_epoch` if it is not the `FAR_FUTURE_EPOCH`.
        let exit_epoch = if val.validator.exit_epoch.as_u64() == FAR_FUTURE_EPOCH {
            None
        } else {
            Some(val.validator.exit_epoch.as_u64() as i32)
        };
        validator_map.insert(WatchValidator {
            index: val.index as i32,
            public_key: WatchPK::from_pubkey(val.validator.pubkey),
            status: val.status.to_string(),
            client: None,
            activation_epoch,
            exit_epoch,
        });
    }
    Ok(validator_map)
}

/// Sends a request to `lighthouse/analysis/attestation_performance`.
/// Formats the response into a vector of `WatchSuboptimalAttestation`.
///
/// Any attestations with `source == true && head == true && target == true` are ignored.
pub async fn get_attestation_performances(
    bn: &BeaconNodeHttpClient,
    start_epoch: Epoch,
    end_epoch: Epoch,
    slots_per_epoch: u64,
) -> Result<Vec<WatchSuboptimalAttestation>, Error> {
    let mut output = Vec::new();
    let result = bn
        .get_lighthouse_analysis_attestation_performance(
            start_epoch,
            end_epoch,
            "global".to_string(),
        )
        .await?;
    for index in result {
        for epoch in index.epochs {
            if epoch.1.active {
                // Check if the attestation is suboptimal.
                if !epoch.1.source || !epoch.1.head || !epoch.1.target {
                    output.push(WatchSuboptimalAttestation {
                        epoch_start_slot: WatchSlot::from_slot(
                            Epoch::new(epoch.0).start_slot(slots_per_epoch),
                        ),
                        index: index.index as i32,
                        source: epoch.1.source,
                        head: epoch.1.head,
                        target: epoch.1.target,
                    })
                }
            }
        }
    }
    Ok(output)
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
                    slot: WatchSlot::from_slot(data.meta.slot),
                    total: data.total as i32,
                    attestation_reward: data.attestation_rewards.total as i32,
                    sync_committee_reward: data.sync_committee_rewards as i32,
                },
                WatchProposerInfo {
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
            slot: WatchSlot::from_slot(data.slot),
            available: data.available_attestations as i32,
            included: data.included_attestations as i32,
            prior_skip_slots: data.prior_skip_slots as i32,
        })
        .collect())
}
