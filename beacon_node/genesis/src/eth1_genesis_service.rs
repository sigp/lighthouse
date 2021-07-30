pub use crate::{common::genesis_deposits, interop::interop_genesis_state};
pub use eth1::Config as Eth1Config;

use eth1::{DepositLog, Eth1Block, Service as Eth1Service};
use slog::{debug, error, info, trace, Logger};
use state_processing::{
    eth2_genesis_time, initialize_beacon_state_from_eth1, is_valid_genesis_state,
    per_block_processing::process_operations::process_deposit, process_activations,
};
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::time::sleep;
use types::{BeaconState, ChainSpec, Deposit, Eth1Data, EthSpec, Hash256};

/// The number of blocks that are pulled per request whilst waiting for genesis.
const BLOCKS_PER_GENESIS_POLL: usize = 99;

/// Stats about the eth1 genesis process.
pub struct Statistics {
    highest_processed_block: AtomicU64,
    active_validator_count: AtomicUsize,
    total_deposit_count: AtomicUsize,
    latest_timestamp: AtomicU64,
}

/// Provides a service that connects to some Eth1 HTTP JSON-RPC endpoint and maintains a cache of
/// eth1 blocks and deposits, listening for the eth1 block that triggers eth2 genesis and returning
/// the genesis `BeaconState`.
///
/// Is a wrapper around the `Service` struct of the `eth1` crate.
#[derive(Clone)]
pub struct Eth1GenesisService {
    /// The underlying service. Access to this object is only required for testing and diagnosis.
    pub eth1_service: Eth1Service,
    /// Statistics about genesis progress.
    stats: Arc<Statistics>,
}

impl Eth1GenesisService {
    /// Creates a new service. Does not attempt to connect to the Eth1 node.
    ///
    /// Modifies the given `config` to make it more suitable to the task of listening to genesis.
    pub fn new(config: Eth1Config, log: Logger, spec: ChainSpec) -> Self {
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
            max_blocks_per_update: Some(BLOCKS_PER_GENESIS_POLL),
            ..config
        };

        Self {
            eth1_service: Eth1Service::new(config, log, spec),
            stats: Arc::new(Statistics {
                highest_processed_block: AtomicU64::new(0),
                active_validator_count: AtomicUsize::new(0),
                total_deposit_count: AtomicUsize::new(0),
                latest_timestamp: AtomicU64::new(0),
            }),
        }
    }

    /// Returns the first eth1 block that has enough deposits that it's a (potentially invalid)
    /// candidate for genesis.
    fn first_candidate_eth1_block(&self, min_genesis_active_validator_count: usize) -> Option<u64> {
        if self.eth1_service.deposit_cache_len() < min_genesis_active_validator_count {
            None
        } else {
            self.eth1_service
                .deposits()
                .read()
                .cache
                .get(min_genesis_active_validator_count.saturating_sub(1))
                .map(|log| log.block_number)
        }
    }

    /// Scans the Eth1 chain, returning a genesis state once it has been discovered.
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
        let eth1_service = &self.eth1_service;
        let log = &eth1_service.log;

        let mut sync_blocks = false;
        let mut highest_processed_block = None;

        info!(
            log,
            "Importing eth1 deposit logs";
        );

        let endpoints = eth1_service.init_endpoints();

        loop {
            let update_result = eth1_service
                .update_deposit_cache(None, &endpoints)
                .await
                .map_err(|e| format!("{:?}", e));

            if let Err(e) = update_result {
                error!(
                    log,
                    "Failed to update eth1 deposit cache";
                    "error" => e
                )
            }

            self.stats
                .total_deposit_count
                .store(eth1_service.deposit_cache_len(), Ordering::Relaxed);

            if !sync_blocks {
                if let Some(viable_eth1_block) = self
                    .first_candidate_eth1_block(spec.min_genesis_active_validator_count as usize)
                {
                    info!(
                        log,
                        "Importing eth1 blocks";
                    );
                    self.eth1_service.set_lowest_cached_block(viable_eth1_block);
                    sync_blocks = true
                } else {
                    info!(
                        log,
                        "Waiting for more deposits";
                        "min_genesis_active_validators" => spec.min_genesis_active_validator_count,
                        "total_deposits" => eth1_service.deposit_cache_len(),
                        "valid_deposits" => eth1_service.get_raw_valid_signature_count(),
                    );

                    sleep(update_interval).await;

                    continue;
                }
            }

            // Download new eth1 blocks into the cache.
            let blocks_imported = match eth1_service.update_block_cache(None, &endpoints).await {
                Ok(outcome) => {
                    debug!(
                        log,
                        "Imported eth1 blocks";
                        "latest_block_timestamp" => eth1_service.latest_block_timestamp(),
                        "cache_head" => eth1_service.highest_safe_block(),
                        "count" => outcome.blocks_imported,
                    );
                    outcome.blocks_imported
                }
                Err(e) => {
                    error!(
                        log,
                        "Failed to update eth1 block cache";
                        "error" => format!("{:?}", e)
                    );
                    0
                }
            };

            // Scan the new eth1 blocks, searching for genesis.
            if let Some(genesis_state) =
                self.scan_new_blocks::<E>(&mut highest_processed_block, &spec)?
            {
                info!(
                    log,
                    "Genesis ceremony complete";
                    "genesis_validators" => genesis_state
                        .get_active_validator_indices(E::genesis_epoch(), &spec)
                        .map_err(|e| format!("Genesis validators error: {:?}", e))?
                        .len(),
                    "genesis_time" => genesis_state.genesis_time(),
                );
                break Ok(genesis_state);
            }

            // Drop all the scanned blocks as they are no longer required.
            eth1_service.clear_block_cache();

            // Load some statistics from the atomics.
            let active_validator_count = self.stats.active_validator_count.load(Ordering::Relaxed);
            let total_deposit_count = self.stats.total_deposit_count.load(Ordering::Relaxed);
            let latest_timestamp = self.stats.latest_timestamp.load(Ordering::Relaxed);

            // Perform some logging.
            if timestamp_can_trigger_genesis(latest_timestamp, &spec)? {
                // Indicate that we are awaiting adequate active validators.
                if (active_validator_count as u64) < spec.min_genesis_active_validator_count {
                    info!(
                        log,
                        "Waiting for more validators";
                        "min_genesis_active_validators" => spec.min_genesis_active_validator_count,
                        "active_validators" => active_validator_count,
                        "total_deposits" => total_deposit_count,
                        "valid_deposits" => eth1_service.get_valid_signature_count().unwrap_or(0),
                    );
                }
            } else {
                info!(
                    log,
                    "Waiting for adequate eth1 timestamp";
                    "genesis_delay" => spec.genesis_delay,
                    "genesis_time" => spec.min_genesis_time,
                    "latest_eth1_timestamp" => latest_timestamp,
                );
            }

            // If we imported the full number of blocks, poll again in a short amount of time.
            //
            // We assume that if we imported a large chunk of blocks then we're some distance from
            // the head and we should sync faster.
            if blocks_imported >= BLOCKS_PER_GENESIS_POLL {
                sleep(Duration::from_millis(50)).await;
            } else {
                sleep(update_interval).await;
            }
        }
    }

    /// Processes any new blocks that have appeared since this function was last run.
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
        highest_processed_block: &mut Option<u64>,
        spec: &ChainSpec,
    ) -> Result<Option<BeaconState<E>>, String> {
        let eth1_service = &self.eth1_service;
        let log = &eth1_service.log;

        for block in eth1_service.blocks().read().iter() {
            // It's possible that the block and deposit caches aren't synced. Ignore any blocks
            // which are not safe for both caches.
            //
            // Don't update the highest processed block since we want to come back and process this
            // again later.
            if eth1_service
                .highest_safe_block()
                .map_or(true, |n| block.number > n)
            {
                continue;
            }

            // Ignore any block that has already been processed or update the highest processed
            // block.
            if highest_processed_block.map_or(false, |highest| highest >= block.number) {
                continue;
            } else {
                self.stats
                    .highest_processed_block
                    .store(block.number, Ordering::Relaxed);
                self.stats
                    .latest_timestamp
                    .store(block.timestamp, Ordering::Relaxed);

                *highest_processed_block = Some(block.number)
            }

            // Ignore any block with an insufficient timestamp.
            if !timestamp_can_trigger_genesis(block.timestamp, spec)? {
                trace!(
                    log,
                    "Insufficient block timestamp";
                    "genesis_delay" => spec.genesis_delay,
                    "min_genesis_time" => spec.min_genesis_time,
                    "eth1_block_timestamp" => block.timestamp,
                    "eth1_block_number" => block.number,
                );
                continue;
            }

            let valid_signature_count = eth1_service
                .get_valid_signature_count_at_block(block.number)
                .unwrap_or(0);
            if (valid_signature_count as u64) < spec.min_genesis_active_validator_count {
                trace!(
                    log,
                    "Insufficient valid signatures";
                    "genesis_delay" => spec.genesis_delay,
                    "valid_signature_count" => valid_signature_count,
                    "min_validator_count" => spec.min_genesis_active_validator_count,
                    "eth1_block_number" => block.number,
                );
                continue;
            }

            // Generate a potential beacon state for this eth1 block.
            //
            // Note: this state is fully valid, some fields have been bypassed to make verification
            // faster.
            let state = self.cheap_state_at_eth1_block::<E>(block, spec)?;
            let active_validator_count = state
                .get_active_validator_indices(E::genesis_epoch(), spec)
                .map_err(|e| format!("Genesis validators error: {:?}", e))?
                .len();

            self.stats
                .active_validator_count
                .store(active_validator_count, Ordering::Relaxed);

            if is_valid_genesis_state(&state, spec) {
                let genesis_state = self
                    .genesis_from_eth1_block(block.clone(), spec)
                    .map_err(|e| format!("Failed to generate valid genesis state : {}", e))?;

                return Ok(Some(genesis_state));
            } else {
                trace!(
                    log,
                    "Insufficient active validators";
                    "min_genesis_active_validator_count" => format!("{}", spec.min_genesis_active_validator_count),
                    "active_validators" => active_validator_count,
                    "eth1_block_number" => block.number,
                );
            }
        }

        Ok(None)
    }

    /// Produces an eth2 genesis `BeaconState` from the given `eth1_block`. The caller should have
    /// verified that `eth1_block` produces a valid genesis state.
    ///
    /// ## Returns
    ///
    /// - `Ok(genesis_state)`: if all went well.
    /// - `Err(e)`: if the given `eth1_block` was not a viable block to trigger genesis or there was
    /// an internal error.
    fn genesis_from_eth1_block<E: EthSpec>(
        &self,
        eth1_block: Eth1Block,
        spec: &ChainSpec,
    ) -> Result<BeaconState<E>, String> {
        let deposit_logs = self
            .eth1_service
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
            genesis_deposits(deposit_logs, spec)?,
            spec,
        )
        .map_err(|e| format!("Unable to initialize genesis state: {:?}", e))?;

        if is_valid_genesis_state(&genesis_state, spec) {
            Ok(genesis_state)
        } else {
            Err("Generated state was not valid.".to_string())
        }
    }

    /// Generates an incomplete `BeaconState` for some `eth1_block` that can be used for checking
    /// to see if that `eth1_block` triggers eth2 genesis.
    ///
    /// ## Notes
    ///
    /// The returned `BeaconState` should **not** be used as the genesis state, it is
    /// incomplete.
    fn cheap_state_at_eth1_block<E: EthSpec>(
        &self,
        eth1_block: &Eth1Block,
        spec: &ChainSpec,
    ) -> Result<BeaconState<E>, String> {
        let genesis_time = eth2_genesis_time(eth1_block.timestamp, spec)
            .map_err(|e| format!("Unable to set genesis time: {:?}", e))?;

        let mut state: BeaconState<E> = BeaconState::new(
            genesis_time,
            Eth1Data {
                block_hash: Hash256::zero(),
                deposit_root: Hash256::zero(),
                deposit_count: 0,
            },
            spec,
        );

        self.deposit_logs_at_block(eth1_block.number)
            .iter()
            .map(|deposit_log| Deposit {
                // Generate a bogus proof.
                //
                // The deposits are coming directly from our own deposit tree to there's no need to
                // make proofs about their inclusion in it.
                proof: vec![Hash256::zero(); spec.deposit_contract_tree_depth as usize].into(),
                data: deposit_log.deposit_data.clone(),
            })
            .try_for_each(|deposit| {
                // Skip proof verification (see comment about bogus proof generation).
                const PROOF_VERIFICATION: bool = false;

                // Note: presently all the signatures are verified each time this function is
                // run.
                //
                // It would be more efficient to pre-verify signatures, filter out the invalid
                // ones and disable verification for `process_deposit`.
                //
                // Such an optimization would only be useful in a scenario where `MIN_GENESIS_TIME`
                // is reached _prior_ to `MIN_ACTIVE_VALIDATOR_COUNT`. I suspect this won't be the
                // case for mainnet, so we defer this optimization.

                process_deposit(&mut state, &deposit, spec, PROOF_VERIFICATION)
                    .map_err(|e| format!("Error whilst processing deposit: {:?}", e))
            })?;

        process_activations(&mut state, spec)
            .map_err(|e| format!("Error whilst processing activations: {:?}", e))?;

        Ok(state)
    }

    /// Returns all deposit logs included in `block_number` and all prior blocks.
    fn deposit_logs_at_block(&self, block_number: u64) -> Vec<DepositLog> {
        self.eth1_service
            .deposits()
            .read()
            .cache
            .iter()
            .take_while(|log| log.block_number <= block_number)
            .cloned()
            .collect()
    }

    /// Returns statistics about eth1 genesis.
    pub fn statistics(&self) -> &Statistics {
        &self.stats
    }

    /// Returns the `Service` contained in `self`.
    pub fn into_core_service(self) -> Eth1Service {
        self.eth1_service
    }
}

/// Returns `false` for a timestamp that would result in a genesis time that is earlier than
/// `MIN_GENESIS_TIME`.
fn timestamp_can_trigger_genesis(timestamp: u64, spec: &ChainSpec) -> Result<bool, String> {
    eth2_genesis_time(timestamp, spec)
        .map(|t| t >= spec.min_genesis_time)
        .map_err(|e| format!("Arith error when during genesis calculation: {:?}", e))
}
