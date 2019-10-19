mod block_cache;
pub mod cache_2;
mod deposit_cache;
mod eth1_cache;
pub mod http;

pub use block_cache::BlockCache;
pub use deposit_cache::{DepositCache, DepositLog};
pub use eth1_cache::{
    update_block_cache, update_deposit_cache, BlockCacheUpdateOutcome, DepositCacheUpdateOutcome,
    Eth1Cache, Eth1CacheBuilder,
};

use futures::{Future, Stream};
use slog::{debug, error, Logger};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::TaskExecutor;
use tokio::timer::Interval;
use types::Address;

pub struct Config {
    pub http_endpoint: String,
    pub deposit_contract_address: Address,
    pub deposit_contract_deploy_block: u64,
    pub follow_distance: u64,
    pub block_cache_len: usize,
    pub update_interval_seconds: u64,
}

pub fn start_service(config: Config, executor: &TaskExecutor, log: Logger) -> Result<(), String> {
    let current_block_number =
        http::get_block_number(&config.http_endpoint, Duration::from_secs(1))
            .wait()
            .map_err(|e| {
                format!(
                    "Unable to get block number from eth1 node. Is it running? Error: {}",
                    e
                )
            })?;

    let cache = Arc::new(
        Eth1CacheBuilder::new(
            config.http_endpoint,
            config.deposit_contract_address.to_string(),
        )
        .eth1_follow_distance(config.follow_distance)
        .initial_eth1_block(current_block_number.saturating_sub(config.follow_distance))
        .target_block_cache_len(config.block_cache_len)
        .deposit_contract_deploy_block(config.deposit_contract_deploy_block)
        .build(),
    );

    executor.spawn(block_cache_updater(
        cache.clone(),
        Duration::from_secs(config.update_interval_seconds),
        log.clone(),
    ));

    executor.spawn(deposit_cache_updater(
        cache.clone(),
        Duration::from_secs(config.update_interval_seconds),
        log.clone(),
    ));

    Ok(())
}

fn deposit_cache_updater(
    cache: Arc<Eth1Cache>,
    update_interval: Duration,
    log: Logger,
) -> impl Future<Item = (), Error = ()> {
    let log_1 = log.clone();

    Interval::new(Instant::now(), update_interval)
        .map_err(move |e| {
            error!(
                log,
                "Failed to start eth block cache update";
                "error" => format!("{:?}", e)
            );
        })
        .for_each(move |_instant| {
            let log = log_1.clone();

            update_deposit_cache(cache.clone())
                .map_err(|e| format!("Failed to update eth1 cache: {:?}", e))
                .then(move |result| {
                    match result {
                        Ok(DepositCacheUpdateOutcome::Success { logs_imported }) => debug!(
                            log,
                            "Updated eth1 deposit cache";
                            "logs_imported" => logs_imported,
                        ),
                        Err(e) => error!(
                            log,
                            "Failed to update eth1 deposit cache";
                            "error" => e
                        ),
                    };

                    Ok(())
                })
        })
}

fn block_cache_updater(
    cache: Arc<Eth1Cache>,
    update_interval: Duration,
    log: Logger,
) -> impl Future<Item = (), Error = ()> {
    let log_1 = log.clone();

    Interval::new(Instant::now(), update_interval)
        .map_err(move |e| {
            error!(
                log,
                "Failed to start eth block cache update";
                "error" => format!("{:?}", e)
            );
        })
        .for_each(move |_instant| {
            let log = log_1.clone();

            update_block_cache(cache.clone())
                .map_err(|e| format!("Failed to update eth1 cache: {:?}", e))
                .then(move |result| {
                    match result {
                        Ok(BlockCacheUpdateOutcome::Success {
                            blocks_imported,
                            head_block_number,
                        }) => debug!(
                            log,
                            "Updated eth1 block cache";
                            "blocks_imported" => blocks_imported,
                            "head_block" => head_block_number,
                        ),
                        Err(e) => error!(
                            log,
                            "Failed to update eth1 block cache";
                            "error" => e
                        ),
                    };

                    Ok(())
                })
        })
}
