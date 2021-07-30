use crate::metrics;
use eth1::{Config as Eth1Config, Eth1Block, Service as HttpService};
use eth2::lighthouse::Eth1SyncStatusData;
use eth2_hashing::hash;
use int_to_bytes::int_to_bytes32;
use slog::{debug, error, trace, Logger};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::per_block_processing::get_new_eth1_data;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::iter::DoubleEndedIterator;
use std::marker::PhantomData;
use std::time::{SystemTime, UNIX_EPOCH};
use store::{DBColumn, Error as StoreError, StoreItem};
use task_executor::TaskExecutor;
use types::{
    BeaconState, BeaconStateError, ChainSpec, Deposit, Eth1Data, EthSpec, Hash256, Slot, Unsigned,
    DEPOSIT_TREE_DEPTH,
};

type BlockNumber = u64;
type Eth1DataVoteCount = HashMap<(Eth1Data, BlockNumber), u64>;

/// We will declare ourself synced with the Eth1 chain, even if we are this many blocks behind.
///
/// This number (8) was chosen somewhat arbitrarily.
const ETH1_SYNC_TOLERANCE: u64 = 8;

#[derive(Debug)]
pub enum Error {
    /// Unable to return an Eth1Data for the given epoch.
    EpochUnavailable,
    /// An error from the backend service (e.g., the web3 data fetcher).
    BackendError(String),
    /// The deposit index of the state is higher than the deposit contract. This is a critical
    /// consensus error.
    DepositIndexTooHigh,
    /// The current state was unable to return the root for the state at the start of the eth1
    /// voting period.
    UnableToGetPreviousStateRoot(BeaconStateError),
    /// The state required to find the previous eth1 block was not found in the store.
    PreviousStateNotInDB(Hash256),
    /// There was an error accessing an object in the database.
    StoreError(StoreError),
    /// The eth1 head block at the start of the eth1 voting period is unknown.
    ///
    /// The eth1 caches are likely stale.
    UnknownVotingPeriodHead,
    /// The block that was previously voted into the state is unknown.
    ///
    /// The eth1 caches are stale, or a junk value was voted into the chain.
    UnknownPreviousEth1BlockHash,
    /// An arithmetic error occurred.
    ArithError(safe_arith::ArithError),
}

impl From<safe_arith::ArithError> for Error {
    fn from(e: safe_arith::ArithError) -> Self {
        Self::ArithError(e)
    }
}

/// Returns an `Eth1SyncStatusData` given some parameters:
///
/// - `latest_cached_block`: The latest eth1 block in our cache, if any.
/// - `head_block`: The block at the very head of our eth1 node (ignoring follow distance, etc).
/// - `genesis_time`: beacon chain genesis time.
/// - `current_slot`: current beacon chain slot.
/// - `spec`: current beacon chain specification.
fn get_sync_status<T: EthSpec>(
    latest_cached_block: Option<&Eth1Block>,
    head_block: Option<&Eth1Block>,
    genesis_time: u64,
    current_slot: Option<Slot>,
    spec: &ChainSpec,
) -> Option<Eth1SyncStatusData> {
    let eth1_follow_distance_seconds = spec
        .seconds_per_eth1_block
        .saturating_mul(spec.eth1_follow_distance);

    // The voting target timestamp needs to be special-cased when we're before
    // genesis (as defined by `current_slot == None`).
    //
    // For the sake of this status, when prior to genesis we want to invent some voting periods
    // that are *before* genesis, so that we can indicate to users that we're actually adequately
    // cached for where they are in time.
    let voting_target_timestamp = if let Some(current_slot) = current_slot {
        let period = T::SlotsPerEth1VotingPeriod::to_u64();
        let voting_period_start_slot = (current_slot / period) * period;

        let period_start = slot_start_seconds::<T>(
            genesis_time,
            spec.seconds_per_slot,
            voting_period_start_slot,
        );

        period_start.saturating_sub(eth1_follow_distance_seconds)
    } else {
        // The number of seconds in an eth1 voting period.
        let voting_period_duration =
            T::slots_per_eth1_voting_period() as u64 * spec.seconds_per_slot;

        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();

        // The number of seconds between now and genesis.
        let seconds_till_genesis = genesis_time.saturating_sub(now);

        // Determine how many voting periods are contained in distance between
        // now and genesis, rounding up.
        let voting_periods_past =
            (seconds_till_genesis + voting_period_duration - 1) / voting_period_duration;

        // Return the start time of the current voting period*.
        //
        // *: This voting period doesn't *actually* exist, we're just using it to
        // give useful logs prior to genesis.
        genesis_time
            .saturating_sub(voting_periods_past * voting_period_duration)
            .saturating_sub(eth1_follow_distance_seconds)
    };

    let latest_cached_block_number = latest_cached_block.map(|b| b.number);
    let latest_cached_block_timestamp = latest_cached_block.map(|b| b.timestamp);
    let head_block_number = head_block.map(|b| b.number);
    let head_block_timestamp = head_block.map(|b| b.timestamp);

    let eth1_node_sync_status_percentage = if let Some(head_block) = head_block {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let head_age = now.saturating_sub(head_block.timestamp);

        if head_age < ETH1_SYNC_TOLERANCE * spec.seconds_per_eth1_block {
            // Always indicate we are fully synced if it's within the sync threshold.
            100.0
        } else {
            let blocks_behind = head_age
                .checked_div(spec.seconds_per_eth1_block)
                .unwrap_or(0);

            let part = f64::from(head_block.number as u32);
            let whole = f64::from(head_block.number.saturating_add(blocks_behind) as u32);

            if whole > 0.0 {
                (part / whole) * 100.0
            } else {
                // Avoids a divide-by-zero.
                0.0
            }
        }
    } else {
        // Always return 0% synced if the head block of the eth1 chain is unknown.
        0.0
    };

    // Lighthouse is "cached and ready" when it has cached enough blocks to cover the start of the
    // current voting period.
    let lighthouse_is_cached_and_ready =
        latest_cached_block_timestamp.map_or(false, |t| t >= voting_target_timestamp);

    Some(Eth1SyncStatusData {
        head_block_number,
        head_block_timestamp,
        latest_cached_block_number,
        latest_cached_block_timestamp,
        voting_target_timestamp,
        eth1_node_sync_status_percentage,
        lighthouse_is_cached_and_ready,
    })
}

#[derive(Encode, Decode, Clone)]
pub struct SszEth1 {
    use_dummy_backend: bool,
    backend_bytes: Vec<u8>,
}

impl StoreItem for SszEth1 {
    fn db_column() -> DBColumn {
        DBColumn::Eth1Cache
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        Self::from_ssz_bytes(bytes).map_err(Into::into)
    }
}

/// Holds an `Eth1ChainBackend` and serves requests from the `BeaconChain`.
pub struct Eth1Chain<T, E>
where
    T: Eth1ChainBackend<E>,
    E: EthSpec,
{
    backend: T,
    /// When `true`, the backend will be ignored and dummy data from the 2019 Canada interop method
    /// will be used instead.
    use_dummy_backend: bool,
    _phantom: PhantomData<E>,
}

impl<T, E> Eth1Chain<T, E>
where
    T: Eth1ChainBackend<E>,
    E: EthSpec,
{
    pub fn new(backend: T) -> Self {
        Self {
            backend,
            use_dummy_backend: false,
            _phantom: PhantomData,
        }
    }

    pub fn new_dummy(backend: T) -> Self {
        Self {
            use_dummy_backend: true,
            ..Self::new(backend)
        }
    }

    /// Returns the `Eth1Data` that should be included in a block being produced for the given
    /// `state`.
    pub fn eth1_data_for_block_production(
        &self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<Eth1Data, Error> {
        if self.use_dummy_backend {
            let dummy_backend: DummyEth1ChainBackend<E> = DummyEth1ChainBackend::default();
            dummy_backend.eth1_data(state, spec)
        } else {
            self.backend.eth1_data(state, spec)
        }
    }

    /// Returns a list of `Deposits` that may be included in a block.
    ///
    /// Including all of the returned `Deposits` in a block should _not_ cause it to become
    /// invalid (i.e., this function should respect the maximum).
    ///
    /// `eth1_data_vote` is the `Eth1Data` that the block producer would include in their
    /// block. This vote may change the `state.eth1_data` value, which would change the deposit
    /// count and therefore change the output of this function.
    pub fn deposits_for_block_inclusion(
        &self,
        state: &BeaconState<E>,
        eth1_data_vote: &Eth1Data,
        spec: &ChainSpec,
    ) -> Result<Vec<Deposit>, Error> {
        if self.use_dummy_backend {
            let dummy_backend: DummyEth1ChainBackend<E> = DummyEth1ChainBackend::default();
            dummy_backend.queued_deposits(state, eth1_data_vote, spec)
        } else {
            self.backend.queued_deposits(state, eth1_data_vote, spec)
        }
    }

    /// Returns a status indicating how synced our caches are with the eth1 chain.
    pub fn sync_status(
        &self,
        genesis_time: u64,
        current_slot: Option<Slot>,
        spec: &ChainSpec,
    ) -> Option<Eth1SyncStatusData> {
        get_sync_status::<E>(
            self.backend.latest_cached_block().as_ref(),
            self.backend.head_block().as_ref(),
            genesis_time,
            current_slot,
            spec,
        )
    }

    /// Instantiate `Eth1Chain` from a persisted `SszEth1`.
    ///
    /// The `Eth1Chain` will have the same caches as the persisted `SszEth1`.
    pub fn from_ssz_container(
        ssz_container: &SszEth1,
        config: Eth1Config,
        log: &Logger,
        spec: ChainSpec,
    ) -> Result<Self, String> {
        let backend =
            Eth1ChainBackend::from_bytes(&ssz_container.backend_bytes, config, log.clone(), spec)?;
        Ok(Self {
            use_dummy_backend: ssz_container.use_dummy_backend,
            backend,
            _phantom: PhantomData,
        })
    }

    /// Return a `SszEth1` containing the state of `Eth1Chain`.
    pub fn as_ssz_container(&self) -> SszEth1 {
        SszEth1 {
            use_dummy_backend: self.use_dummy_backend,
            backend_bytes: self.backend.as_bytes(),
        }
    }

    /// Consumes `self`, returning the backend.
    pub fn into_backend(self) -> T {
        self.backend
    }
}

pub trait Eth1ChainBackend<T: EthSpec>: Sized + Send + Sync {
    /// Returns the `Eth1Data` that should be included in a block being produced for the given
    /// `state`.
    fn eth1_data(&self, beacon_state: &BeaconState<T>, spec: &ChainSpec)
        -> Result<Eth1Data, Error>;

    /// Returns all `Deposits` between `state.eth1_deposit_index` and
    /// `state.eth1_data.deposit_count`.
    ///
    /// # Note:
    ///
    /// It is possible that not all returned `Deposits` can be included in a block. E.g., there may
    /// be more than `MAX_DEPOSIT_COUNT` or the churn may be too high.
    fn queued_deposits(
        &self,
        beacon_state: &BeaconState<T>,
        eth1_data_vote: &Eth1Data,
        spec: &ChainSpec,
    ) -> Result<Vec<Deposit>, Error>;

    /// Returns the latest block stored in the cache. Used to obtain an idea of how up-to-date the
    /// beacon node eth1 cache is.
    fn latest_cached_block(&self) -> Option<Eth1Block>;

    /// Returns the block at the head of the chain (ignoring follow distance, etc). Used to obtain
    /// an idea of how up-to-date the remote eth1 node is.
    fn head_block(&self) -> Option<Eth1Block>;

    /// Encode the `Eth1ChainBackend` instance to bytes.
    fn as_bytes(&self) -> Vec<u8>;

    /// Create a `Eth1ChainBackend` instance given encoded bytes.
    fn from_bytes(
        bytes: &[u8],
        config: Eth1Config,
        log: Logger,
        spec: ChainSpec,
    ) -> Result<Self, String>;
}

/// Provides a simple, testing-only backend that generates deterministic, meaningless eth1 data.
///
/// Never creates deposits, therefore the validator set is static.
///
/// This was used in the 2019 Canada interop workshops.
pub struct DummyEth1ChainBackend<T: EthSpec>(PhantomData<T>);

impl<T: EthSpec> Eth1ChainBackend<T> for DummyEth1ChainBackend<T> {
    /// Produce some deterministic junk based upon the current epoch.
    fn eth1_data(&self, state: &BeaconState<T>, _spec: &ChainSpec) -> Result<Eth1Data, Error> {
        let current_epoch = state.current_epoch();
        let slots_per_voting_period = T::slots_per_eth1_voting_period() as u64;
        let current_voting_period: u64 = current_epoch.as_u64() / slots_per_voting_period;

        let deposit_root = hash(&int_to_bytes32(current_voting_period));
        let block_hash = hash(&deposit_root);

        Ok(Eth1Data {
            deposit_root: Hash256::from_slice(&deposit_root),
            deposit_count: state.eth1_deposit_index(),
            block_hash: Hash256::from_slice(&block_hash),
        })
    }

    /// The dummy back-end never produces deposits.
    fn queued_deposits(
        &self,
        _: &BeaconState<T>,
        _: &Eth1Data,
        _: &ChainSpec,
    ) -> Result<Vec<Deposit>, Error> {
        Ok(vec![])
    }

    fn latest_cached_block(&self) -> Option<Eth1Block> {
        None
    }

    fn head_block(&self) -> Option<Eth1Block> {
        None
    }

    /// Return empty Vec<u8> for dummy backend.
    fn as_bytes(&self) -> Vec<u8> {
        Vec::new()
    }

    /// Create dummy eth1 backend.
    fn from_bytes(
        _bytes: &[u8],
        _config: Eth1Config,
        _log: Logger,
        _spec: ChainSpec,
    ) -> Result<Self, String> {
        Ok(Self(PhantomData))
    }
}

impl<T: EthSpec> Default for DummyEth1ChainBackend<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

/// Maintains a cache of eth1 blocks and deposits and provides functions to allow block producers
/// to include new deposits and vote on `Eth1Data`.
///
/// The `core` connects to some external eth1 client (e.g., Parity/Geth) and polls it for
/// information.
#[derive(Clone)]
pub struct CachingEth1Backend<T: EthSpec> {
    pub core: HttpService,
    log: Logger,
    _phantom: PhantomData<T>,
}

impl<T: EthSpec> CachingEth1Backend<T> {
    /// Instantiates `self` with empty caches.
    ///
    /// Does not connect to the eth1 node or start any tasks to keep the cache updated.
    pub fn new(config: Eth1Config, log: Logger, spec: ChainSpec) -> Self {
        Self {
            core: HttpService::new(config, log.clone(), spec),
            log,
            _phantom: PhantomData,
        }
    }

    /// Starts the routine which connects to the external eth1 node and updates the caches.
    pub fn start(&self, handle: TaskExecutor) {
        HttpService::auto_update(self.core.clone(), handle);
    }

    /// Instantiates `self` from an existing service.
    pub fn from_service(service: HttpService) -> Self {
        Self {
            log: service.log.clone(),
            core: service,
            _phantom: PhantomData,
        }
    }
}

impl<T: EthSpec> Eth1ChainBackend<T> for CachingEth1Backend<T> {
    fn eth1_data(&self, state: &BeaconState<T>, spec: &ChainSpec) -> Result<Eth1Data, Error> {
        let period = T::SlotsPerEth1VotingPeriod::to_u64();
        let voting_period_start_slot = (state.slot() / period) * period;
        let voting_period_start_seconds = slot_start_seconds::<T>(
            state.genesis_time(),
            spec.seconds_per_slot,
            voting_period_start_slot,
        );

        let blocks = self.core.blocks().read();

        let votes_to_consider =
            get_votes_to_consider(blocks.iter(), voting_period_start_seconds, spec);

        trace!(
            self.log,
            "Found eth1 data votes_to_consider";
            "votes_to_consider" => votes_to_consider.len(),
        );
        let valid_votes = collect_valid_votes(state, &votes_to_consider);

        let eth1_data = if let Some(eth1_data) = find_winning_vote(valid_votes) {
            eth1_data
        } else {
            // In this case, there are no valid votes available.
            //
            // Here we choose the eth1_data corresponding to the latest block in our voting window.
            // If no votes exist, choose `state.eth1_data` as default vote.
            votes_to_consider
                .iter()
                .max_by_key(|(_, block_number)| *block_number)
                .map(|vote| {
                    let vote = vote.0.clone();
                    debug!(
                        self.log,
                        "No valid eth1_data votes";
                        "outcome" => "Casting vote corresponding to last candidate eth1 block",
                        "vote" => ?vote
                    );
                    vote
                })
                .unwrap_or_else(|| {
                    let vote = state.eth1_data().clone();
                    error!(
                        self.log,
                        "No valid eth1_data votes, `votes_to_consider` empty";
                        "lowest_block_number" => self.core.lowest_block_number(),
                        "earliest_block_timestamp" => self.core.earliest_block_timestamp(),
                        "genesis_time" => state.genesis_time(),
                        "outcome" => "casting `state.eth1_data` as eth1 vote"
                    );
                    metrics::inc_counter(&metrics::DEFAULT_ETH1_VOTES);
                    vote
                })
        };

        debug!(
            self.log,
            "Produced vote for eth1 chain";
            "deposit_root" => format!("{:?}", eth1_data.deposit_root),
            "deposit_count" => eth1_data.deposit_count,
            "block_hash" => format!("{:?}", eth1_data.block_hash),
        );

        Ok(eth1_data)
    }

    fn queued_deposits(
        &self,
        state: &BeaconState<T>,
        eth1_data_vote: &Eth1Data,
        _spec: &ChainSpec,
    ) -> Result<Vec<Deposit>, Error> {
        let deposit_index = state.eth1_deposit_index();
        let deposit_count = if let Some(new_eth1_data) = get_new_eth1_data(state, eth1_data_vote)? {
            new_eth1_data.deposit_count
        } else {
            state.eth1_data().deposit_count
        };

        match deposit_index.cmp(&deposit_count) {
            Ordering::Greater => Err(Error::DepositIndexTooHigh),
            Ordering::Equal => Ok(vec![]),
            Ordering::Less => {
                let next = deposit_index;
                let last = std::cmp::min(deposit_count, next + T::MaxDeposits::to_u64());

                self.core
                    .deposits()
                    .read()
                    .cache
                    .get_deposits(next, last, deposit_count, DEPOSIT_TREE_DEPTH)
                    .map_err(|e| Error::BackendError(format!("Failed to get deposits: {:?}", e)))
                    .map(|(_deposit_root, deposits)| deposits)
            }
        }
    }

    fn latest_cached_block(&self) -> Option<Eth1Block> {
        self.core.latest_cached_block()
    }

    fn head_block(&self) -> Option<Eth1Block> {
        self.core.head_block()
    }

    /// Return encoded byte representation of the block and deposit caches.
    fn as_bytes(&self) -> Vec<u8> {
        self.core.as_bytes()
    }

    /// Recover the cached backend from encoded bytes.
    fn from_bytes(
        bytes: &[u8],
        config: Eth1Config,
        log: Logger,
        spec: ChainSpec,
    ) -> Result<Self, String> {
        let inner = HttpService::from_bytes(bytes, config, log.clone(), spec)?;
        Ok(Self {
            core: inner,
            log,
            _phantom: PhantomData,
        })
    }
}

/// Get all votes from eth1 blocks which are in the list of candidate blocks for the
/// current eth1 voting period.
///
/// Returns a hashmap of `Eth1Data` to its associated eth1 `block_number`.
fn get_votes_to_consider<'a, I>(
    blocks: I,
    voting_period_start_seconds: u64,
    spec: &ChainSpec,
) -> HashMap<Eth1Data, u64>
where
    I: DoubleEndedIterator<Item = &'a Eth1Block> + Clone,
{
    blocks
        .rev()
        .skip_while(|eth1_block| !is_candidate_block(eth1_block, voting_period_start_seconds, spec))
        .take_while(|eth1_block| is_candidate_block(eth1_block, voting_period_start_seconds, spec))
        .filter_map(|eth1_block| {
            eth1_block
                .clone()
                .eth1_data()
                .map(|eth1_data| (eth1_data, eth1_block.number))
        })
        .collect()
}

/// Collect all valid votes that are cast during the current voting period.
/// Return hashmap with count of each vote cast.
fn collect_valid_votes<T: EthSpec>(
    state: &BeaconState<T>,
    votes_to_consider: &HashMap<Eth1Data, BlockNumber>,
) -> Eth1DataVoteCount {
    let mut valid_votes = HashMap::new();
    state
        .eth1_data_votes()
        .iter()
        .filter_map(|vote| {
            votes_to_consider
                .get(vote)
                .map(|block_num| (vote.clone(), *block_num))
        })
        .for_each(|(eth1_data, block_number)| {
            valid_votes
                .entry((eth1_data, block_number))
                .and_modify(|count| *count += 1)
                .or_insert(1_u64);
        });
    valid_votes
}

/// Selects the winning vote from `valid_votes`.
fn find_winning_vote(valid_votes: Eth1DataVoteCount) -> Option<Eth1Data> {
    valid_votes
        .iter()
        .max_by_key(|((_eth1_data, block_number), vote_count)| (*vote_count, block_number))
        .map(|((eth1_data, _), _)| eth1_data.clone())
}

/// Returns the unix-epoch seconds at the start of the given `slot`.
fn slot_start_seconds<T: EthSpec>(
    genesis_unix_seconds: u64,
    seconds_per_slot: u64,
    slot: Slot,
) -> u64 {
    genesis_unix_seconds + slot.as_u64() * seconds_per_slot
}

/// Returns a boolean denoting if a given `Eth1Block` is a candidate for `Eth1Data` calculation
/// at the timestamp `period_start`.
///
/// Note: `period_start` needs to be atleast (`spec.seconds_per_eth1_block * spec.eth1_follow_distance * 2`)
/// for this function to return meaningful values.
fn is_candidate_block(block: &Eth1Block, period_start: u64, spec: &ChainSpec) -> bool {
    block.timestamp
        <= period_start.saturating_sub(spec.seconds_per_eth1_block * spec.eth1_follow_distance)
        && block.timestamp
            >= period_start
                .saturating_sub(spec.seconds_per_eth1_block * spec.eth1_follow_distance * 2)
}

#[cfg(test)]
mod test {
    use super::*;
    use environment::null_logger;
    use types::{DepositData, MinimalEthSpec, Signature};

    type E = MinimalEthSpec;

    fn get_eth1_data(i: u64) -> Eth1Data {
        Eth1Data {
            block_hash: Hash256::from_low_u64_be(i),
            deposit_root: Hash256::from_low_u64_be(u64::max_value() - i),
            deposit_count: i,
        }
    }

    fn get_voting_period_start_seconds(state: &BeaconState<E>, spec: &ChainSpec) -> u64 {
        let period = <E as EthSpec>::SlotsPerEth1VotingPeriod::to_u64();
        let voting_period_start_slot = (state.slot() / period) * period;
        slot_start_seconds::<E>(
            state.genesis_time(),
            spec.seconds_per_slot,
            voting_period_start_slot,
        )
    }

    #[test]
    fn slot_start_time() {
        let zero_sec = 0;
        assert_eq!(slot_start_seconds::<E>(100, zero_sec, Slot::new(2)), 100);

        let one_sec = 1;
        assert_eq!(slot_start_seconds::<E>(100, one_sec, Slot::new(0)), 100);
        assert_eq!(slot_start_seconds::<E>(100, one_sec, Slot::new(1)), 101);
        assert_eq!(slot_start_seconds::<E>(100, one_sec, Slot::new(2)), 102);

        let three_sec = 3;
        assert_eq!(slot_start_seconds::<E>(100, three_sec, Slot::new(0)), 100);
        assert_eq!(slot_start_seconds::<E>(100, three_sec, Slot::new(1)), 103);
        assert_eq!(slot_start_seconds::<E>(100, three_sec, Slot::new(2)), 106);

        let five_sec = 5;
        assert_eq!(slot_start_seconds::<E>(100, five_sec, Slot::new(0)), 100);
        assert_eq!(slot_start_seconds::<E>(100, five_sec, Slot::new(1)), 105);
        assert_eq!(slot_start_seconds::<E>(100, five_sec, Slot::new(2)), 110);
        assert_eq!(slot_start_seconds::<E>(100, five_sec, Slot::new(3)), 115);
    }

    fn get_eth1_block(timestamp: u64, number: u64) -> Eth1Block {
        Eth1Block {
            number,
            timestamp,
            hash: Hash256::from_low_u64_be(number),
            deposit_root: Some(Hash256::from_low_u64_be(number)),
            deposit_count: Some(number),
        }
    }

    mod eth1_chain_json_backend {
        use super::*;
        use eth1::DepositLog;
        use types::{test_utils::generate_deterministic_keypair, EthSpec, MainnetEthSpec};

        fn get_eth1_chain() -> Eth1Chain<CachingEth1Backend<E>, E> {
            let eth1_config = Eth1Config {
                ..Eth1Config::default()
            };

            let log = null_logger().unwrap();
            Eth1Chain::new(CachingEth1Backend::new(
                eth1_config,
                log,
                MainnetEthSpec::default_spec(),
            ))
        }

        fn get_deposit_log(i: u64, spec: &ChainSpec) -> DepositLog {
            let keypair = generate_deterministic_keypair(i as usize);
            let mut deposit = DepositData {
                pubkey: keypair.pk.into(),
                withdrawal_credentials: Hash256::zero(),
                amount: spec.max_effective_balance,
                signature: Signature::empty().into(),
            };

            deposit.signature = deposit.create_signature(&keypair.sk, &E::default_spec());

            DepositLog {
                deposit_data: deposit,
                block_number: i,
                index: i,
                signature_is_valid: true,
            }
        }

        #[test]
        fn deposits_empty_cache() {
            let spec = &E::default_spec();

            let eth1_chain = get_eth1_chain();

            assert!(
                !eth1_chain.use_dummy_backend,
                "test should not use dummy backend"
            );

            let mut state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), spec);
            *state.eth1_deposit_index_mut() = 0;
            state.eth1_data_mut().deposit_count = 0;

            assert!(
                eth1_chain
                    .deposits_for_block_inclusion(&state, &Eth1Data::default(), spec)
                    .is_ok(),
                "should succeed if cache is empty but no deposits are required"
            );

            state.eth1_data_mut().deposit_count = 1;

            assert!(
                eth1_chain
                    .deposits_for_block_inclusion(&state, &Eth1Data::default(), spec)
                    .is_err(),
                "should fail to get deposits if required, but cache is empty"
            );
        }

        #[test]
        fn deposits_with_cache() {
            let spec = &E::default_spec();

            let eth1_chain = get_eth1_chain();
            let max_deposits = <E as EthSpec>::MaxDeposits::to_u64();

            assert!(
                !eth1_chain.use_dummy_backend,
                "test should not use dummy backend"
            );

            let deposits: Vec<_> = (0..max_deposits + 2)
                .map(|i| get_deposit_log(i, spec))
                .inspect(|log| {
                    eth1_chain
                        .backend
                        .core
                        .deposits()
                        .write()
                        .cache
                        .insert_log(log.clone())
                        .expect("should insert log");
                })
                .collect();

            assert_eq!(
                eth1_chain.backend.core.deposits().write().cache.len(),
                deposits.len(),
                "cache should store all logs"
            );

            let mut state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), spec);
            *state.eth1_deposit_index_mut() = 0;
            state.eth1_data_mut().deposit_count = 0;

            assert!(
                eth1_chain
                    .deposits_for_block_inclusion(&state, &Eth1Data::default(), spec)
                    .is_ok(),
                "should succeed if no deposits are required"
            );

            (0..3).for_each(|initial_deposit_index| {
                *state.eth1_deposit_index_mut() = initial_deposit_index as u64;

                (initial_deposit_index..deposits.len()).for_each(|i| {
                    state.eth1_data_mut().deposit_count = i as u64;

                    let deposits_for_inclusion = eth1_chain
                        .deposits_for_block_inclusion(&state, &Eth1Data::default(), spec)
                        .unwrap_or_else(|_| panic!("should find deposit for {}", i));

                    let expected_len =
                        std::cmp::min(i - initial_deposit_index, max_deposits as usize);

                    assert_eq!(
                        deposits_for_inclusion.len(),
                        expected_len,
                        "should find {} deposits",
                        expected_len
                    );

                    let deposit_data_for_inclusion: Vec<_> = deposits_for_inclusion
                        .into_iter()
                        .map(|deposit| deposit.data)
                        .collect();

                    let expected_deposit_data: Vec<_> = deposits[initial_deposit_index
                        ..std::cmp::min(initial_deposit_index + expected_len, deposits.len())]
                        .iter()
                        .map(|log| log.deposit_data.clone())
                        .collect();

                    assert_eq!(
                        deposit_data_for_inclusion, expected_deposit_data,
                        "should find the correct deposits for {}",
                        i
                    );
                });
            })
        }

        #[test]
        fn eth1_data_empty_cache() {
            let spec = &E::default_spec();

            let eth1_chain = get_eth1_chain();

            assert!(
                !eth1_chain.use_dummy_backend,
                "test should not use dummy backend"
            );

            let state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), spec);

            let a = eth1_chain
                .eth1_data_for_block_production(&state, spec)
                .expect("should produce default eth1 data vote");
            assert_eq!(
                a,
                *state.eth1_data(),
                "default vote should be same as state.eth1_data"
            );
        }

        #[test]
        fn default_vote() {
            let spec = &E::default_spec();
            let slots_per_eth1_voting_period = <E as EthSpec>::SlotsPerEth1VotingPeriod::to_u64();
            let eth1_follow_distance = spec.eth1_follow_distance;

            let eth1_chain = get_eth1_chain();

            assert!(
                !eth1_chain.use_dummy_backend,
                "test should not use dummy backend"
            );

            let mut state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), spec);

            *state.slot_mut() = Slot::from(slots_per_eth1_voting_period * 10);
            let follow_distance_seconds = eth1_follow_distance * spec.seconds_per_eth1_block;
            let voting_period_start = get_voting_period_start_seconds(&state, spec);
            let start_eth1_block = voting_period_start - follow_distance_seconds * 2;
            let end_eth1_block = voting_period_start - follow_distance_seconds;

            // Populate blocks cache with candidate eth1 blocks
            let blocks = (start_eth1_block..end_eth1_block)
                .map(|i| get_eth1_block(i, i))
                .collect::<Vec<_>>();

            blocks.iter().for_each(|block| {
                eth1_chain
                    .backend
                    .core
                    .blocks()
                    .write()
                    .insert_root_or_child(block.clone())
                    .expect("should add blocks to cache");
            });

            let vote = eth1_chain
                .eth1_data_for_block_production(&state, spec)
                .expect("should produce default eth1 data vote");

            assert_eq!(
                vote,
                blocks
                    .last()
                    .expect("should have blocks")
                    .clone()
                    .eth1_data()
                    .expect("should have valid eth1 data"),
                "default vote must correspond to last block in candidate blocks"
            );
        }
    }

    mod eth1_data_sets {
        use super::*;

        #[test]
        fn empty_cache() {
            let spec = &E::default_spec();
            let state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), spec);

            let blocks = vec![];

            assert_eq!(
                get_votes_to_consider(
                    blocks.iter(),
                    get_voting_period_start_seconds(&state, spec),
                    spec,
                ),
                HashMap::new()
            );
        }

        #[test]
        fn ideal_scenario() {
            let spec = E::default_spec();

            let slots_per_eth1_voting_period = <E as EthSpec>::SlotsPerEth1VotingPeriod::to_u64();
            let eth1_follow_distance = spec.eth1_follow_distance;

            let mut state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), &spec);
            *state.genesis_time_mut() = 0;
            *state.slot_mut() = Slot::from(slots_per_eth1_voting_period * 10);

            let follow_distance_seconds = eth1_follow_distance * spec.seconds_per_eth1_block;
            let voting_period_start = get_voting_period_start_seconds(&state, &spec);
            let start_eth1_block = voting_period_start - follow_distance_seconds * 2;
            let end_eth1_block = voting_period_start - follow_distance_seconds;
            let blocks = (start_eth1_block..end_eth1_block)
                .map(|i| get_eth1_block(i, i))
                .collect::<Vec<_>>();

            let votes_to_consider =
                get_votes_to_consider(blocks.iter(), voting_period_start, &spec);
            assert_eq!(
                votes_to_consider.len() as u64,
                end_eth1_block - start_eth1_block,
                "all produced eth1 blocks should be in votes to consider"
            );

            (start_eth1_block..end_eth1_block)
                .map(|i| get_eth1_block(i, i))
                .for_each(|eth1_block| {
                    assert_eq!(
                        eth1_block.number,
                        *votes_to_consider
                            .get(&eth1_block.clone().eth1_data().unwrap())
                            .expect("votes_to_consider should have expected block numbers")
                    )
                });
        }
    }

    mod collect_valid_votes {
        use super::*;

        fn get_eth1_data_vec(n: u64, block_number_offset: u64) -> Vec<(Eth1Data, BlockNumber)> {
            (0..n)
                .map(|i| (get_eth1_data(i), i + block_number_offset))
                .collect()
        }

        macro_rules! assert_votes {
            ($votes: expr, $expected: expr, $text: expr) => {
                let expected: Vec<(Eth1Data, BlockNumber)> = $expected;
                assert_eq!(
                    $votes.len(),
                    expected.len(),
                    "map should have the same number of elements"
                );
                expected.iter().for_each(|(eth1_data, block_number)| {
                    $votes
                        .get(&(eth1_data.clone(), *block_number))
                        .expect("should contain eth1 data");
                })
            };
        }

        #[test]
        fn no_votes_in_state() {
            let slots = <E as EthSpec>::SlotsPerEth1VotingPeriod::to_u64();
            let spec = &E::default_spec();
            let state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), spec);

            let votes_to_consider = get_eth1_data_vec(slots, 0);

            let votes = collect_valid_votes(&state, &votes_to_consider.into_iter().collect());
            assert_eq!(
                votes.len(),
                0,
                "should not find any votes when state has no votes"
            );
        }

        #[test]
        fn distinct_votes_in_state() {
            let slots = <E as EthSpec>::SlotsPerEth1VotingPeriod::to_u64();
            let spec = &E::default_spec();
            let mut state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), spec);

            let votes_to_consider = get_eth1_data_vec(slots, 0);

            *state.eth1_data_votes_mut() = votes_to_consider[0..slots as usize / 4]
                .iter()
                .map(|(eth1_data, _)| eth1_data)
                .cloned()
                .collect::<Vec<_>>()
                .into();

            let votes =
                collect_valid_votes(&state, &votes_to_consider.clone().into_iter().collect());
            assert_votes!(
                votes,
                votes_to_consider[0..slots as usize / 4].to_vec(),
                "should find as many votes as were in the state"
            );
        }

        #[test]
        fn duplicate_votes_in_state() {
            let slots = <E as EthSpec>::SlotsPerEth1VotingPeriod::to_u64();
            let spec = &E::default_spec();
            let mut state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), spec);

            let votes_to_consider = get_eth1_data_vec(slots, 0);

            let duplicate_eth1_data = votes_to_consider
                .last()
                .expect("should have some eth1 data")
                .clone();

            *state.eth1_data_votes_mut() = vec![duplicate_eth1_data.clone(); 4]
                .iter()
                .map(|(eth1_data, _)| eth1_data)
                .cloned()
                .collect::<Vec<_>>()
                .into();

            let votes = collect_valid_votes(&state, &votes_to_consider.into_iter().collect());
            assert_votes!(
                votes,
                // There should only be one value if there's a duplicate
                vec![duplicate_eth1_data.clone()],
                "should find as many votes as were in the state"
            );

            assert_eq!(
                *votes
                    .get(&duplicate_eth1_data)
                    .expect("should contain vote"),
                4,
                "should have four votes"
            );
        }
    }

    mod winning_vote {
        use super::*;

        type Vote = ((Eth1Data, u64), u64);

        fn vote(block_number: u64, vote_count: u64) -> Vote {
            (
                (
                    Eth1Data {
                        deposit_root: Hash256::from_low_u64_be(block_number),
                        deposit_count: block_number,
                        block_hash: Hash256::from_low_u64_be(block_number),
                    },
                    block_number,
                ),
                vote_count,
            )
        }

        fn vote_data(vote: &Vote) -> Eth1Data {
            (vote.0).0.clone()
        }

        #[test]
        fn no_votes() {
            let no_votes = vec![vote(0, 0), vote(1, 0), vote(3, 0), vote(2, 0)];

            assert_eq!(
                // Favour the highest block number when there are no votes.
                vote_data(&no_votes[2]),
                find_winning_vote(no_votes.into_iter().collect()).expect("should find winner")
            );
        }

        #[test]
        fn equal_votes() {
            let votes = vec![vote(0, 1), vote(1, 1), vote(3, 1), vote(2, 1)];

            assert_eq!(
                // Favour the highest block number when there are equal votes.
                vote_data(&votes[2]),
                find_winning_vote(votes.into_iter().collect()).expect("should find winner")
            );
        }

        #[test]
        fn some_votes() {
            let votes = vec![vote(0, 0), vote(1, 1), vote(3, 1), vote(2, 2)];

            assert_eq!(
                // Favour the highest vote over the highest block number.
                vote_data(&votes[3]),
                find_winning_vote(votes.into_iter().collect()).expect("should find winner")
            );
        }

        #[test]
        fn tying_votes() {
            let votes = vec![vote(0, 0), vote(1, 1), vote(2, 2), vote(3, 2)];

            assert_eq!(
                // Favour the highest block number for tying votes.
                vote_data(&votes[3]),
                find_winning_vote(votes.into_iter().collect()).expect("should find winner")
            );
        }

        #[test]
        fn all_tying_votes() {
            let votes = vec![vote(3, 42), vote(2, 42), vote(1, 42), vote(0, 42)];

            assert_eq!(
                // Favour the highest block number for tying votes.
                vote_data(&votes[0]),
                find_winning_vote(votes.into_iter().collect()).expect("should find winner")
            );
        }
    }
}
