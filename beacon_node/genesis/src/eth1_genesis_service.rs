pub use crate::{common::genesis_deposits, interop::interop_genesis_state};
pub use eth1::Config as Eth1Config;

use eth1::{DepositLog, Eth1Block, Service};
use parking_lot::Mutex;
use slog::{debug, error, info, trace, Logger};
use state_processing::{
    eth2_genesis_time, initialize_beacon_state_from_eth1, is_valid_genesis_state,
    per_block_processing::process_deposit, process_activations,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::delay_for;
use types::{BeaconState, ChainSpec, Deposit, Eth1Data, EthSpec, Hash256};

/// Provides a service that connects to some Eth1 HTTP JSON-RPC endpoint and maintains a cache of eth1
/// blocks and deposits, listening for the eth1 block that triggers eth2 genesis and returning the
/// genesis `BeaconState`.
///
/// Is a wrapper around the `Service` struct of the `eth1` crate.
#[derive(Clone)]
pub struct Eth1GenesisService {
    /// The underlying service. Access to this object is only required for testing and diagnosis.
    pub core: Service,
    /// The highest block number we've processed and determined it does not trigger genesis.
    highest_processed_block: Arc<Mutex<Option<u64>>>,
    /// Enabled when the genesis service should start downloading blocks.
    ///
    /// It is disabled until there are enough deposit logs to start syncing.
    sync_blocks: Arc<Mutex<bool>>,
}

impl Eth1GenesisService {
    /// Creates a new service. Does not attempt to connect to the Eth1 node.
    ///
    /// Modifies the given `config` to make it more suitable to the task of listening to genesis.
    pub fn new(config: Eth1Config, log: Logger) -> Self {
        let config = Eth1Config {
            // Truncating the block cache makes searching for genesis more
            // complicated.
            block_cache_truncation: None,
            // Scan large ranges of blocks when awaiting genesis.
            blocks_per_log_query: 1_000,
            // Only perform a few log requests each time the eth1 node is polled.
            //
            // For small testnets this makes finding genesis much faster,
            // as it usually happens within 1,000 blocks.
            max_log_requests_per_update: Some(5),
            // Only perform a few logs requests each time the eth1 node is polled.
            //
            // For small testnets, this is much faster as they do not have
            // a `MIN_GENESIS_SECONDS`, so after `MIN_GENESIS_VALIDATOR_COUNT`
            // has been reached only a single block needs to be read.
            max_blocks_per_update: Some(5),
            ..config
        };

        Self {
            core: Service::new(config, log),
            highest_processed_block: Arc::new(Mutex::new(None)),
            sync_blocks: Arc::new(Mutex::new(false)),
        }
    }

    fn first_viable_eth1_block(&self, min_genesis_active_validator_count: usize) -> Option<u64> {
        if self.core.deposit_cache_len() < min_genesis_active_validator_count {
            None
        } else {
            self.core
                .deposits()
                .read()
                .cache
                .get(min_genesis_active_validator_count.saturating_sub(1))
                .map(|log| log.block_number)
        }
    }

    /// Returns a future that will keep updating the cache and resolve once it has discovered the
    /// first Eth1 block that triggers an Eth2 genesis.
    ///
    /// ## Returns
    ///
    /// - `Ok(state)` once the canonical eth2 genesis state has been discovered.
    /// - `Err(e)` if there is some internal error during updates.
    pub async fn wait_for_genesis_state<E: EthSpec>(
        &self,
        update_interval: Duration,
        spec: ChainSpec,
    ) -> Result<BeaconState<E>, String> {
        let service = self.clone();
        let log = service.core.log.clone();
        let min_genesis_active_validator_count = spec.min_genesis_active_validator_count;
        let min_genesis_time = spec.min_genesis_time;
        loop {
            // **WARNING** `delay_for` panics on error
            delay_for(update_interval).await;
            let update_result = Service::update_deposit_cache(self.core.clone())
                .await
                .map_err(|e| format!("{:?}", e));

            if let Err(e) = update_result {
                error!(
                    log,
                    "Failed to update eth1 deposit cache";
                    "error" => e
                )
            }

            // Do not exit the loop if there is an error whilst updating.
            // Only enable the `sync_blocks` flag if there are enough deposits to feasibly
            // trigger genesis.
            //
            // Note: genesis is triggered by the _active_ validator count, not just the
            // deposit count, so it's possible that block downloads are started too early.
            // This is just wasteful, not erroneous.
            let mut sync_blocks = self.sync_blocks.lock();

            if !(*sync_blocks) {
                if let Some(viable_eth1_block) =
                    self.first_viable_eth1_block(min_genesis_active_validator_count as usize)
                {
                    info!(
                        log,
                        "Minimum genesis deposit count met";
                        "deposit_count" => min_genesis_active_validator_count,
                        "block_number" => viable_eth1_block,
                    );
                    self.core.set_lowest_cached_block(viable_eth1_block);
                    *sync_blocks = true
                }
            }

            let should_update_block_cache = *sync_blocks;
            if should_update_block_cache {
                let update_result = Service::update_block_cache(self.core.clone()).await;
                if let Err(e) = update_result {
                    error!(
                        log,
                        "Failed to update eth1 block cache";
                        "error" => format!("{:?}", e)
                    );
                }
            };
            if let Some(genesis_state) = self
                .scan_new_blocks::<E>(&spec)
                .map_err(|e| format!("Failed to scan for new blocks: {}", e))?
            {
                break Ok(genesis_state);
            } else {
                debug!(
                    log,
                    "No eth1 genesis block found";
                    "latest_block_timestamp" => self.core.latest_block_timestamp(),
                    "min_genesis_time" => min_genesis_time,
                    "min_validator_count" => min_genesis_active_validator_count,
                    "cached_blocks" => self.core.block_cache_len(),
                    "cached_deposits" => self.core.deposit_cache_len(),
                    "cache_head" => self.highest_known_block(),
                );
            }
        }
    }

    /// Processes any new blocks that have appeared since this function was last run.
    ///
    /// A `highest_processed_block` value is stored in `self`. This function will find any blocks
    /// in it's caches that have a higher block number than `highest_processed_block` and check to
    /// see if they would trigger an Eth2 genesis.
    ///
    /// Blocks are always tested in increasing order, starting with the lowest unknown block
    /// number in the cache.
    ///
    /// ## Returns
    ///
    /// - `Ok(Some(eth1_block))` if a previously-unprocessed block would trigger Eth2 genesis.
    /// - `Ok(None)` if none of the new blocks would trigger genesis, or there were no new blocks.
    /// - `Err(_)` if there was some internal error.
    fn scan_new_blocks<E: EthSpec>(
        &self,
        spec: &ChainSpec,
    ) -> Result<Option<BeaconState<E>>, String> {
        let genesis_trigger_eth1_block = self
            .core
            .blocks()
            .read()
            .iter()
            // Filter out any blocks that would result in a genesis time that is earlier than
            // `MIN_GENESIS_TIME`.
            //
            // Note: any `SafeArith` errors are suppressed here; we simply skip blocks that cause
            // overflow/div-by-zero.
            .filter(|block| {
                eth2_genesis_time(block.timestamp, spec)
                    .map_or(false, |t| t >= spec.min_genesis_time)
            })
            // The block cache might be more recently updated than deposit cache. Restrict any
            // block numbers that are not known by all caches.
            .filter(|block| {
                self.highest_known_block()
                    .map(|n| block.number <= n)
                    .unwrap_or_else(|| true)
            })
            .find(|block| {
                let mut highest_processed_block = self.highest_processed_block.lock();
                let block_number = block.number;

                let next_new_block_number =
                    highest_processed_block.map(|n| n + 1).unwrap_or_else(|| 0);

                if block_number < next_new_block_number {
                    return false;
                }

                self.is_valid_genesis_eth1_block::<E>(block, &spec, &self.core.log)
                    .and_then(|val| {
                        *highest_processed_block = Some(block.number);
                        Ok(val)
                    })
                    .map(|is_valid| {
                        if !is_valid {
                            info!(
                                self.core.log,
                                "Inspected new eth1 block";
                                "msg" => "did not trigger genesis",
                                "block_number" => block_number
                            );
                        };
                        is_valid
                    })
                    .unwrap_or_else(|_| {
                        error!(
                            self.core.log,
                            "Failed to detect if eth1 block triggers genesis";
                            "eth1_block_number" => block.number,
                            "eth1_block_hash" => format!("{}", block.hash),
                        );
                        false
                    })
            })
            .cloned();

        if let Some(eth1_block) = genesis_trigger_eth1_block {
            debug!(
                self.core.log,
                "All genesis conditions met";
                "eth1_block_height" => eth1_block.number,
            );

            let genesis_state = self
                .genesis_from_eth1_block(eth1_block.clone(), &spec)
                .map_err(|e| format!("Failed to generate valid genesis state : {}", e))?;

            info!(
                self.core.log,
                "Deposit contract genesis complete";
                "eth1_block_height" => eth1_block.number,
                "validator_count" => genesis_state.validators.len(),
            );

            Ok(Some(genesis_state))
        } else {
            Ok(None)
        }
    }

    /// Produces an eth2 genesis `BeaconState` from the given `eth1_block`.
    ///
    /// ## Returns
    ///
    /// - Ok(genesis_state) if all went well.
    /// - Err(e) if the given `eth1_block` was not a viable block to trigger genesis or there was
    /// an internal error.
    fn genesis_from_eth1_block<E: EthSpec>(
        &self,
        eth1_block: Eth1Block,
        spec: &ChainSpec,
    ) -> Result<BeaconState<E>, String> {
        let deposit_logs = self
            .core
            .deposits()
            .read()
            .cache
            .iter()
            .take_while(|log| log.block_number <= eth1_block.number)
            .map(|log| log.deposit_data.clone())
            .collect::<Vec<_>>();

        let genesis_state = initialize_beacon_state_from_eth1(
            eth1_block.hash,
            eth1_block.timestamp,
            genesis_deposits(deposit_logs, &spec)?,
            &spec,
        )
        .map_err(|e| format!("Unable to initialize genesis state: {:?}", e))?;

        if is_valid_genesis_state(&genesis_state, &spec) {
            Ok(genesis_state)
        } else {
            Err("Generated state was not valid.".to_string())
        }
    }

    /// A cheap (compared to using `initialize_beacon_state_from_eth1) method for determining if some
    /// `target_block` will trigger genesis.
    fn is_valid_genesis_eth1_block<E: EthSpec>(
        &self,
        target_block: &Eth1Block,
        spec: &ChainSpec,
        log: &Logger,
    ) -> Result<bool, String> {
        if target_block.timestamp < spec.min_genesis_time {
            Ok(false)
        } else {
            let mut local_state: BeaconState<E> = BeaconState::new(
                0,
                Eth1Data {
                    block_hash: Hash256::zero(),
                    deposit_root: Hash256::zero(),
                    deposit_count: 0,
                },
                &spec,
            );

            local_state.genesis_time = target_block.timestamp;

            self.deposit_logs_at_block(target_block.number)
                .iter()
                // TODO: add the signature field back.
                //.filter(|deposit_log| deposit_log.signature_is_valid)
                .map(|deposit_log| Deposit {
                    proof: vec![Hash256::zero(); spec.deposit_contract_tree_depth as usize].into(),
                    data: deposit_log.deposit_data.clone(),
                })
                .try_for_each(|deposit| {
                    // No need to verify proofs in order to test if some block will trigger genesis.
                    const PROOF_VERIFICATION: bool = false;

                    // Note: presently all the signatures are verified each time this function is
                    // run.
                    //
                    // It would be more efficient to pre-verify signatures, filter out the invalid
                    // ones and disable verification for `process_deposit`.
                    //
                    // This is only more efficient in scenarios where `min_genesis_time` occurs
                    // _before_ `min_validator_count` is met. We're unlikely to see this scenario
                    // in testnets (`min_genesis_time` is usually `0`) and I'm not certain it will
                    // happen for the real, production deposit contract.

                    process_deposit(&mut local_state, &deposit, spec, PROOF_VERIFICATION)
                        .map_err(|e| format!("Error whilst processing deposit: {:?}", e))
                })?;

            process_activations(&mut local_state, spec)
                .map_err(|e| format!("Error whilst processing activations: {:?}", e))?;
            let is_valid = is_valid_genesis_state(&local_state, spec);

            trace!(
                log,
                "Eth1 block inspected for genesis";
                "active_validators" => local_state.get_active_validator_indices(local_state.current_epoch()).len(),
                "validators" => local_state.validators.len()
            );

            Ok(is_valid)
        }
    }

    /// Returns the `block_number` of the highest (by block number) block in the cache.
    ///
    /// Takes the lower block number of the deposit and block caches to ensure this number is safe.
    fn highest_known_block(&self) -> Option<u64> {
        let block_cache = self.core.blocks().read().highest_block_number()?;
        let deposit_cache = self.core.deposits().read().last_processed_block?;

        Some(std::cmp::min(block_cache, deposit_cache))
    }

    /// Returns all deposit logs included in `block_number` and all prior blocks.
    fn deposit_logs_at_block(&self, block_number: u64) -> Vec<DepositLog> {
        self.core
            .deposits()
            .read()
            .cache
            .iter()
            .take_while(|log| log.block_number <= block_number)
            .cloned()
            .collect()
    }

    /// Returns the `Service` contained in `self`.
    pub fn into_core_service(self) -> Service {
        self.core
    }
}
