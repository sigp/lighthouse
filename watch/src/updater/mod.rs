use crate::config::Config as FullConfig;
use crate::database::{WatchPK, WatchValidator};
use eth2::{
    types::{BlockId, StateId},
    BeaconNodeHttpClient, SensitiveUrl, Timeouts,
};
use log::{debug, error, info};
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::time::{Duration, Instant};
use types::{BeaconBlockHeader, EthSpec, GnosisEthSpec, MainnetEthSpec, SignedBeaconBlock};

pub use config::Config;
pub use error::Error;
pub use handler::UpdateHandler;

mod config;
pub mod error;
pub mod handler;

const FAR_FUTURE_EPOCH: u64 = u64::MAX;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

const MAINNET: &str = "mainnet";
const GNOSIS: &str = "gnosis";

pub struct WatchSpec<T: EthSpec> {
    network: String,
    spec: PhantomData<T>,
}

impl<T: EthSpec> WatchSpec<T> {
    fn slots_per_epoch(&self) -> u64 {
        T::slots_per_epoch()
    }
}

impl WatchSpec<MainnetEthSpec> {
    pub fn mainnet(network: String) -> Self {
        Self {
            network,
            spec: PhantomData,
        }
    }
}

impl WatchSpec<GnosisEthSpec> {
    fn gnosis(network: String) -> Self {
        Self {
            network,
            spec: PhantomData,
        }
    }
}

pub async fn run_updater(config: FullConfig) -> Result<(), Error> {
    let beacon_node_url =
        SensitiveUrl::parse(&config.updater.beacon_node_url).map_err(Error::SensitiveUrl)?;
    let bn = BeaconNodeHttpClient::new(beacon_node_url, Timeouts::set_all(DEFAULT_TIMEOUT));

    let config_map = bn.get_config_spec::<HashMap<String, String>>().await?.data;

    let config_name = config_map
        .get("CONFIG_NAME")
        .ok_or_else(|| {
            Error::BeaconNodeNotCompatible("No field CONFIG_NAME on beacon node spec".to_string())
        })?
        .clone();

    match config_map
        .get("PRESET_BASE")
        .ok_or_else(|| {
            Error::BeaconNodeNotCompatible("No field PRESET_BASE on beacon node spec".to_string())
        })?
        .to_lowercase()
        .as_str()
    {
        MAINNET => {
            let spec = WatchSpec::mainnet(config_name);
            run_once(bn, spec, config).await
        }
        GNOSIS => {
            let spec = WatchSpec::gnosis(config_name);
            run_once(bn, spec, config).await
        }
        _ => unimplemented!("unsupported PRESET_BASE"),
    }
}

pub async fn run_once<T: EthSpec>(
    bn: BeaconNodeHttpClient,
    spec: WatchSpec<T>,
    config: FullConfig,
) -> Result<(), Error> {
    let mut watch = UpdateHandler::new(bn, spec, config.clone()).await?;

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

    info!("Updating validator set");
    let validator_timer = Instant::now();
    watch.update_validator_set().await?;
    let validator_timer_elapsed = validator_timer.elapsed();
    debug!("Validator update complete, time taken: {validator_timer_elapsed:?}");

    // Update blocks after updating the validator set since the `proposer_index` must exist in the
    // `validators` table.
    info!("Updating unknown blocks");
    let unknown_block_timer = Instant::now();
    watch.update_unknown_blocks().await?;
    let unknown_block_timer_elapsed = unknown_block_timer.elapsed();
    debug!("Unknown block update complete, time taken: {unknown_block_timer_elapsed:?}");

    // Run additional modules
    if config.updater.attestations {
        info!("Updating suboptimal attestations");
        let attestation_timer = Instant::now();
        watch.fill_suboptimal_attestations().await?;
        watch.backfill_suboptimal_attestations().await?;
        let attestation_timer_elapsed = attestation_timer.elapsed();
        debug!("Attestation update complete, time taken: {attestation_timer_elapsed:?}");
    }

    if config.updater.block_rewards {
        info!("Updating block rewards");
        let rewards_timer = Instant::now();
        watch.fill_block_rewards().await?;
        watch.backfill_block_rewards().await?;
        let rewards_timer_elapsed = rewards_timer.elapsed();
        debug!("Block Rewards update complete, time taken: {rewards_timer_elapsed:?}");
    }

    if config.updater.block_packing {
        info!("Updating block packing statistics");
        let packing_timer = Instant::now();
        watch.fill_block_packing().await?;
        watch.backfill_block_packing().await?;
        let packing_timer_elapsed = packing_timer.elapsed();
        debug!("Block packing update complete, time taken: {packing_timer_elapsed:?}");
    }

    if config.blockprint.enabled {
        info!("Updating blockprint");
        let blockprint_timer = Instant::now();
        watch.fill_blockprint().await?;
        watch.backfill_blockprint().await?;
        let blockprint_timer_elapsed = blockprint_timer.elapsed();
        debug!("Blockprint update complete, time taken: {blockprint_timer_elapsed:?}");
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

pub async fn get_beacon_block<T: EthSpec>(
    bn: &BeaconNodeHttpClient,
    block_id: BlockId,
) -> Result<Option<SignedBeaconBlock<T>>, Error> {
    let block = bn.get_beacon_blocks(block_id).await?.map(|resp| resp.data);

    Ok(block)
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
            activation_epoch,
            exit_epoch,
        });
    }
    Ok(validator_map)
}
