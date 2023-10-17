use crate::Eth2NetworkConfig;
use lazy_static::lazy_static;
use std::{
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use types::Config;

const PERIOD: u64 = 604800;

/// Structure storing current Ephemery configuration.
struct EphemeryConfig {
    purge_after_update: bool,
    iteration: u64,
}

lazy_static! {
    static ref EPHEMERY_CONFIG: Mutex<EphemeryConfig> = Mutex::new(EphemeryConfig {
        iteration: u64::MAX,
        purge_after_update: false
    });
}

/// Checks if the given `Eth2NetworkConfig` needs to be updated based on its genesis time.
/// If the genesis time is outdated, updates the config with a new genesis time, chain ID, and network ID.
/// Returns a `Result` containing the updated `Eth2NetworkConfig` if an update was made, or the original `Eth2NetworkConfig` if no update was necessary.
pub fn check_update_config(
    eth2_network_config: Eth2NetworkConfig,
) -> Result<Eth2NetworkConfig, String> {
    let genesis_time = eth2_network_config.config.get_min_genesis_time();
    let iteration = calculate_iteration()?;
    set_iteration(iteration);
    if genesis_outdated(genesis_time) {
        set_purge_after_update(true);
        let mut updated_config = eth2_network_config;
        let genesis_0 = get_genesis_0()?;
        let new_genesis_time = PERIOD * get_iteration()? + genesis_0.get_min_genesis_time();
        let new_id = genesis_0.get_chain_id() + get_iteration()?;
        updated_config.config.set_min_genesis_time(new_genesis_time);
        updated_config.config.set_chain_id(new_id);
        updated_config.config.set_network_id(new_id);
        Ok(updated_config)
    } else {
        Ok(eth2_network_config)
    }
}

/// Returns the current iteration of the network.
pub fn calculate_iteration() -> Result<u64, String> {
    let config = get_genesis_0()?;
    Ok((timestamp_now() - config.get_min_genesis_time()) / PERIOD as u64)
}

/// Returns the genesis 0 config from built in network configs files.
fn get_genesis_0() -> Result<Config, String> {
    let genesis_0 = Eth2NetworkConfig::constant("ephemery")?;
    match genesis_0 {
        Some(genesis_0) => Ok(genesis_0.config),
        None => Err("Could not find genesis 0.".to_string()),
    }
}

/// If the genesis time of the stored network config is outdated,
/// remove the datadir and return true.
pub fn genesis_outdated(min_genesis_time: u64) -> bool {
    if min_genesis_time + PERIOD < timestamp_now() {
        true
    } else {
        false
    }
}

/// Returns the duration since the unix epoch.
fn timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

/// Setters and getters for Ephemery configuration.
pub fn set_iteration(iteration: u64) {
    let mut data = EPHEMERY_CONFIG.lock().unwrap();
    data.iteration = iteration;
}

pub fn get_iteration() -> Result<u64, String> {
    let data = EPHEMERY_CONFIG.lock().unwrap();
    match data.iteration {
        u64::MAX => Err("invalid iteration".to_string()),
        _ => Ok(data.iteration),
    }
}

pub fn set_purge_after_update(purge_after_update: bool) {
    let mut data = EPHEMERY_CONFIG.lock().unwrap();
    data.purge_after_update = purge_after_update;
}

pub fn get_purge_after_update() -> bool {
    let data = EPHEMERY_CONFIG.lock().unwrap();
    data.purge_after_update
}
