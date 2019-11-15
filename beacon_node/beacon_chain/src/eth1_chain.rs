use eth1::{Config as Eth1Config, Eth1Block, Service as HttpService};
use eth2_hashing::hash;
use exit_future::Exit;
use futures::Future;
use integer_sqrt::IntegerSquareRoot;
use rand::prelude::*;
use slog::{crit, Logger};
use std::collections::HashMap;
use std::iter::DoubleEndedIterator;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::sync::Arc;
use store::{Error as StoreError, Store};
use types::{
    BeaconState, BeaconStateError, ChainSpec, Deposit, Eth1Data, EthSpec, Hash256, Slot, Unsigned,
    DEPOSIT_TREE_DEPTH,
};

type BlockNumber = u64;
type Eth1DataBlockNumber = HashMap<Eth1Data, BlockNumber>;
type Eth1DataVoteCount = HashMap<(Eth1Data, BlockNumber), u64>;

#[derive(Debug, PartialEq)]
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
    PreviousStateNotInDB,
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
    pub use_dummy_backend: bool,
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

    /// Returns the `Eth1Data` that should be included in a block being produced for the given
    /// `state`.
    pub fn eth1_data_for_block_production(
        &self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<Eth1Data, Error> {
        if self.use_dummy_backend {
            DummyEth1ChainBackend::default().eth1_data(state, spec)
        } else {
            self.backend.eth1_data(state, spec)
        }
    }

    /// Returns a list of `Deposits` that may be included in a block.
    ///
    /// Including all of the returned `Deposits` in a block should _not_ cause it to become
    /// invalid.
    pub fn deposits_for_block_inclusion(
        &self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<Vec<Deposit>, Error> {
        if self.use_dummy_backend {
            DummyEth1ChainBackend::default().queued_deposits(state, spec)
        } else {
            self.backend.queued_deposits(state, spec)
        }
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
        spec: &ChainSpec,
    ) -> Result<Vec<Deposit>, Error>;
}

/// Provides a simple, testing-only backend that generates deterministic, meaningless eth1 data.
///
/// Never creates deposits, therefore the validator set is static.
///
/// This was used in the 2019 Canada interop workshops.
pub struct DummyEth1ChainBackend<T: EthSpec>(PhantomData<T>);

impl<T: EthSpec> Eth1ChainBackend<T> for DummyEth1ChainBackend<T> {
    fn eth1_data(&self, state: &BeaconState<T>, _spec: &ChainSpec) -> Result<Eth1Data, Error> {
        let current_epoch = state.current_epoch();
        let slots_per_voting_period = T::slots_per_eth1_voting_period() as u64;
        let current_voting_period: u64 = current_epoch.as_u64() / slots_per_voting_period;

        let deposit_root = hash(&int_to_bytes32(current_voting_period));
        let block_hash = hash(&deposit_root);

        Ok(Eth1Data {
            deposit_root: Hash256::from_slice(&deposit_root),
            deposit_count: state.eth1_deposit_index,
            block_hash: Hash256::from_slice(&block_hash),
        })
    }

    fn queued_deposits(&self, _: &BeaconState<T>, _: &ChainSpec) -> Result<Vec<Deposit>, Error> {
        Ok(vec![])
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
pub struct CachingEth1Backend<T: EthSpec, S> {
    pub core: HttpService,
    store: Arc<S>,
    log: Logger,
    _phantom: PhantomData<T>,
}

impl<T: EthSpec, S: Store> CachingEth1Backend<T, S> {
    /// Instantiates `self` with empty caches.
    ///
    /// Does not connect to the eth1 node or start any tasks to keep the cache updated.
    pub fn new(config: Eth1Config, log: Logger, store: Arc<S>) -> Self {
        Self {
            core: HttpService::new(config, log.clone()),
            store,
            log,
            _phantom: PhantomData,
        }
    }

    /// Starts the routine which connects to the external eth1 node and updates the caches.
    pub fn start(&self, exit: Exit) -> impl Future<Item = (), Error = ()> {
        self.core.auto_update(exit)
    }

    /// Instantiates `self` from an existing service.
    pub fn from_service(service: HttpService, store: Arc<S>) -> Self {
        Self {
            log: service.log.clone(),
            core: service,
            store,
            _phantom: PhantomData,
        }
    }
}

impl<T: EthSpec, S: Store> Eth1ChainBackend<T> for CachingEth1Backend<T, S> {
    fn eth1_data(&self, state: &BeaconState<T>, spec: &ChainSpec) -> Result<Eth1Data, Error> {
        let prev_eth1_hash = eth1_block_hash_at_start_of_voting_period(self.store.clone(), state)?;

        let blocks = self.core.blocks().read();

        let eth1_data = eth1_data_sets(blocks.iter(), state, prev_eth1_hash, spec)
            .map(|(new_eth1_data, all_eth1_data)| {
                collect_valid_votes(state, new_eth1_data, all_eth1_data)
            })
            .and_then(find_winning_vote)
            .unwrap_or_else(|| {
                crit!(
                    self.log,
                    "Unable to cast valid vote for Eth1Data";
                    "hint" => "check connection to eth1 node",
                    "reason" => "no votes",
                );
                random_eth1_data()
            });

        Ok(eth1_data)
    }

    fn queued_deposits(
        &self,
        state: &BeaconState<T>,
        _spec: &ChainSpec,
    ) -> Result<Vec<Deposit>, Error> {
        let deposit_count = state.eth1_data.deposit_count;
        let deposit_index = state.eth1_deposit_index;

        if deposit_index > deposit_count {
            Err(Error::DepositIndexTooHigh)
        } else if deposit_index == deposit_count {
            Ok(vec![])
        } else {
            let next = deposit_index;
            let last = std::cmp::min(deposit_count, next + T::MaxDeposits::to_u64());

            self.core
                .deposits()
                .read()
                .cache
                .get_deposits(next..last, deposit_count, DEPOSIT_TREE_DEPTH)
                .map_err(|e| Error::BackendError(format!("Failed to get deposits: {:?}", e)))
                .map(|(_deposit_root, deposits)| deposits)
        }
    }
}

/// Produces an `Eth1Data` with all fields sourced from `rand::thread_rng()`.
fn random_eth1_data() -> Eth1Data {
    let mut rng = rand::thread_rng();

    macro_rules! rand_bytes {
        ($num_bytes: expr) => {{
            let mut arr = [0_u8; $num_bytes];
            rng.fill(&mut arr[..]);
            arr
        }};
    }

    // Note: it seems easier to just use `Hash256::random(..)` to get the hash values, however I
    // prefer to be explicit about the source of entropy instead of relying upon the maintainers of
    // `Hash256` to ensure their entropy is suitable for our purposes.

    Eth1Data {
        block_hash: Hash256::from_slice(&rand_bytes!(32)),
        deposit_root: Hash256::from_slice(&rand_bytes!(32)),
        deposit_count: u64::from_le_bytes(rand_bytes!(8)),
    }
}

/// Returns `state.eth1_data.block_hash` at the start of eth1 voting period defined by
/// `state.slot`.
fn eth1_block_hash_at_start_of_voting_period<T: EthSpec, S: Store>(
    store: Arc<S>,
    state: &BeaconState<T>,
) -> Result<Hash256, Error> {
    let period = T::SlotsPerEth1VotingPeriod::to_u64();

    // Find `state.eth1_data.block_hash` for the state at the start of the voting period.
    if state.slot % period < period / 2 {
        // When the state is less than half way through the period we can safely assume that
        // the eth1_data has not changed since the start of the period.
        Ok(state.eth1_data.block_hash)
    } else {
        let slot = (state.slot / period) * period;
        let prev_state_root = state
            .get_state_root(slot)
            .map_err(|e| Error::UnableToGetPreviousStateRoot(e))?;

        store
            .get::<BeaconState<T>>(&prev_state_root)
            .map_err(|e| Error::StoreError(e))?
            .map(|state| state.eth1_data.block_hash)
            .ok_or_else(|| Error::PreviousStateNotInDB)
    }
}

/// Calculates and returns `(new_eth1_data, all_eth1_data)` for the given `state`, based upon the
/// blocks in the `block` iterator.
///
/// `prev_eth1_hash` is the `eth1_data.block_hash` at the start of the voting period defined by
/// `state.slot`.
fn eth1_data_sets<'a, T: EthSpec, I>(
    blocks: I,
    state: &BeaconState<T>,
    prev_eth1_hash: Hash256,
    spec: &ChainSpec,
) -> Option<(Eth1DataBlockNumber, Eth1DataBlockNumber)>
where
    T: EthSpec,
    I: DoubleEndedIterator<Item = &'a Eth1Block> + Clone,
{
    let period = T::SlotsPerEth1VotingPeriod::to_u64();
    let eth1_follow_distance = spec.eth1_follow_distance;
    let voting_period_start_slot = (state.slot / period) * period;
    let voting_period_start_seconds = slot_start_seconds::<T>(
        state.genesis_time,
        spec.milliseconds_per_slot,
        voting_period_start_slot,
    );

    let in_scope_eth1_data = blocks
        .rev()
        .skip_while(|eth1_block| eth1_block.timestamp > voting_period_start_seconds)
        .skip(eth1_follow_distance as usize)
        .filter_map(|block| Some((block.clone().eth1_data()?, block.number)));

    if in_scope_eth1_data
        .clone()
        .any(|(eth1_data, _)| eth1_data.block_hash == prev_eth1_hash)
    {
        let new_eth1_data = in_scope_eth1_data
            .clone()
            .take(eth1_follow_distance as usize);
        let all_eth1_data =
            in_scope_eth1_data.take_while(|(eth1_data, _)| eth1_data.block_hash != prev_eth1_hash);

        Some((
            HashMap::from_iter(new_eth1_data),
            HashMap::from_iter(all_eth1_data),
        ))
    } else {
        None
    }
}

/// Selects and counts the votes in `state.eth1_data_votes`, if they appear in `new_eth1_data` or
/// `all_eth1_data` when it is the voting period tail.
fn collect_valid_votes<T: EthSpec>(
    state: &BeaconState<T>,
    new_eth1_data: Eth1DataBlockNumber,
    all_eth1_data: Eth1DataBlockNumber,
) -> Eth1DataVoteCount {
    let slots_per_eth1_voting_period = T::SlotsPerEth1VotingPeriod::to_u64();

    let mut valid_votes = HashMap::new();

    state
        .eth1_data_votes
        .iter()
        .filter_map(|vote| {
            new_eth1_data
                .get(vote)
                .map(|block_number| (vote.clone(), *block_number))
                .or_else(|| {
                    let slot = state.slot % slots_per_eth1_voting_period;
                    let period_tail = slot >= slots_per_eth1_voting_period.integer_sqrt();

                    if period_tail {
                        all_eth1_data
                            .get(vote)
                            .map(|block_number| (vote.clone(), *block_number))
                    } else {
                        None
                    }
                })
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

/// Returns `int` as little-endian bytes with a length of 32.
fn int_to_bytes32(int: u64) -> Vec<u8> {
    let mut vec = int.to_le_bytes().to_vec();
    vec.resize(32, 0);
    vec
}

/// Returns the unix-epoch seconds at the start of the given `slot`.
fn slot_start_seconds<T: EthSpec>(
    genesis_unix_seconds: u64,
    milliseconds_per_slot: u64,
    slot: Slot,
) -> u64 {
    genesis_unix_seconds + slot.as_u64() * milliseconds_per_slot / 1_000
}

#[cfg(test)]
mod test {
    use super::*;
    use types::{test_utils::DepositTestTask, MinimalEthSpec};

    type E = MinimalEthSpec;

    fn get_eth1_data(i: u64) -> Eth1Data {
        Eth1Data {
            block_hash: Hash256::from_low_u64_be(i),
            deposit_root: Hash256::from_low_u64_be(u64::max_value() - i),
            deposit_count: i,
        }
    }

    #[test]
    fn random_eth1_data_doesnt_panic() {
        random_eth1_data();
    }

    #[test]
    fn slot_start_time() {
        let zero_sec = 0;
        assert_eq!(slot_start_seconds::<E>(100, zero_sec, Slot::new(2)), 100);

        let half_sec = 500;
        assert_eq!(slot_start_seconds::<E>(100, half_sec, Slot::new(0)), 100);
        assert_eq!(slot_start_seconds::<E>(100, half_sec, Slot::new(1)), 100);
        assert_eq!(slot_start_seconds::<E>(100, half_sec, Slot::new(2)), 101);
        assert_eq!(slot_start_seconds::<E>(100, half_sec, Slot::new(3)), 101);

        let one_sec = 1_000;
        assert_eq!(slot_start_seconds::<E>(100, one_sec, Slot::new(0)), 100);
        assert_eq!(slot_start_seconds::<E>(100, one_sec, Slot::new(1)), 101);
        assert_eq!(slot_start_seconds::<E>(100, one_sec, Slot::new(2)), 102);

        let three_sec = 3_000;
        assert_eq!(slot_start_seconds::<E>(100, three_sec, Slot::new(0)), 100);
        assert_eq!(slot_start_seconds::<E>(100, three_sec, Slot::new(1)), 103);
        assert_eq!(slot_start_seconds::<E>(100, three_sec, Slot::new(2)), 106);
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
        use environment::null_logger;
        use eth1::DepositLog;
        use store::MemoryStore;
        use types::test_utils::{generate_deterministic_keypair, TestingDepositBuilder};

        fn get_eth1_chain() -> Eth1Chain<CachingEth1Backend<E, MemoryStore>, E> {
            let eth1_config = Eth1Config {
                ..Eth1Config::default()
            };

            let log = null_logger().unwrap();
            let store = Arc::new(MemoryStore::open());
            Eth1Chain::new(CachingEth1Backend::new(eth1_config, log, store))
        }

        fn get_deposit_log(i: u64, spec: &ChainSpec) -> DepositLog {
            let keypair = generate_deterministic_keypair(i as usize);
            let mut builder =
                TestingDepositBuilder::new(keypair.pk.clone(), spec.max_effective_balance);
            builder.sign(&DepositTestTask::Valid, &keypair, spec);
            let deposit_data = builder.build().data;

            DepositLog {
                deposit_data,
                block_number: i,
                index: i,
            }
        }

        #[test]
        fn deposits_empty_cache() {
            let spec = &E::default_spec();

            let eth1_chain = get_eth1_chain();

            assert_eq!(
                eth1_chain.use_dummy_backend, false,
                "test should not use dummy backend"
            );

            let mut state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), &spec);
            state.eth1_deposit_index = 0;
            state.eth1_data.deposit_count = 0;

            assert!(
                eth1_chain
                    .deposits_for_block_inclusion(&state, spec)
                    .is_ok(),
                "should succeed if cache is empty but no deposits are required"
            );

            state.eth1_data.deposit_count = 1;

            assert!(
                eth1_chain
                    .deposits_for_block_inclusion(&state, spec)
                    .is_err(),
                "should fail to get deposits if required, but cache is empty"
            );
        }

        #[test]
        fn deposits_with_cache() {
            let spec = &E::default_spec();

            let eth1_chain = get_eth1_chain();
            let max_deposits = <E as EthSpec>::MaxDeposits::to_u64();

            assert_eq!(
                eth1_chain.use_dummy_backend, false,
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
                        .expect("should insert log")
                })
                .collect();

            assert_eq!(
                eth1_chain.backend.core.deposits().write().cache.len(),
                deposits.len(),
                "cache should store all logs"
            );

            let mut state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), &spec);
            state.eth1_deposit_index = 0;
            state.eth1_data.deposit_count = 0;

            assert!(
                eth1_chain
                    .deposits_for_block_inclusion(&state, spec)
                    .is_ok(),
                "should succeed if no deposits are required"
            );

            (0..3).for_each(|initial_deposit_index| {
                state.eth1_deposit_index = initial_deposit_index as u64;

                (initial_deposit_index..deposits.len()).for_each(|i| {
                    state.eth1_data.deposit_count = i as u64;

                    let deposits_for_inclusion = eth1_chain
                        .deposits_for_block_inclusion(&state, spec)
                        .expect(&format!("should find deposit for {}", i));

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

            assert_eq!(
                eth1_chain.use_dummy_backend, false,
                "test should not use dummy backend"
            );

            let state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), &spec);

            let a = eth1_chain
                .eth1_data_for_block_production(&state, &spec)
                .expect("should produce first random eth1 data");
            let b = eth1_chain
                .eth1_data_for_block_production(&state, &spec)
                .expect("should produce second random eth1 data");

            assert!(
                a != b,
                "random votes should be returned with an empty cache"
            );
        }

        #[test]
        fn eth1_data_unknown_previous_state() {
            let spec = &E::default_spec();
            let period = <E as EthSpec>::SlotsPerEth1VotingPeriod::to_u64();

            let eth1_chain = get_eth1_chain();
            let store = eth1_chain.backend.store.clone();

            assert_eq!(
                eth1_chain.use_dummy_backend, false,
                "test should not use dummy backend"
            );

            let mut state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), &spec);
            let mut prev_state = state.clone();

            prev_state.slot = Slot::new(period * 1_000);
            state.slot = Slot::new(period * 1_000 + period / 2);

            (0..2048).for_each(|i| {
                eth1_chain
                    .backend
                    .core
                    .blocks()
                    .write()
                    .insert_root_or_child(get_eth1_block(i, i))
                    .expect("should add blocks to cache");
            });

            let expected_root = Hash256::from_low_u64_be(u64::max_value());
            prev_state.eth1_data.block_hash = expected_root;

            assert!(
                prev_state.eth1_data != state.eth1_data,
                "test requires state eth1_data are different"
            );

            store
                .put(
                    &state
                        .get_state_root(prev_state.slot)
                        .expect("should find state root"),
                    &prev_state,
                )
                .expect("should store state");

            let a = eth1_chain
                .eth1_data_for_block_production(&state, &spec)
                .expect("should produce first random eth1 data");
            let b = eth1_chain
                .eth1_data_for_block_production(&state, &spec)
                .expect("should produce second random eth1 data");

            assert!(
                a != b,
                "random votes should be returned if the previous eth1 data block hash is unknown"
            );
        }
    }

    mod prev_block_hash {
        use super::*;
        use store::MemoryStore;

        #[test]
        fn without_store_lookup() {
            let spec = &E::default_spec();
            let store = Arc::new(MemoryStore::open());

            let state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), spec);

            assert_eq!(
                eth1_block_hash_at_start_of_voting_period(store, &state),
                Ok(state.eth1_data.block_hash),
                "should return the states eth1 data in the first half of the period"
            );
        }

        #[test]
        fn with_store_lookup() {
            let spec = &E::default_spec();
            let store = Arc::new(MemoryStore::open());

            let period = <E as EthSpec>::SlotsPerEth1VotingPeriod::to_u64();

            let mut state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), spec);
            let mut prev_state = state.clone();

            state.slot = Slot::new(period / 2);

            let expected_root = Hash256::from_low_u64_be(42);

            prev_state.eth1_data.block_hash = expected_root;

            assert!(
                prev_state.eth1_data != state.eth1_data,
                "test requires state eth1_data are different"
            );

            store
                .put(
                    &state
                        .get_state_root(Slot::new(0))
                        .expect("should find state root"),
                    &prev_state,
                )
                .expect("should store state");

            assert_eq!(
                eth1_block_hash_at_start_of_voting_period(store, &state),
                Ok(expected_root),
                "should return the eth1_data from the previous state"
            );
        }
    }

    mod eth1_data_sets {
        use super::*;

        #[test]
        fn empty_cache() {
            let spec = &E::default_spec();
            let state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), spec);
            let prev_eth1_hash = Hash256::zero();

            let blocks = vec![];

            assert_eq!(
                eth1_data_sets(blocks.iter(), &state, prev_eth1_hash, &spec),
                None
            );
        }

        #[test]
        fn no_known_block_hash() {
            let mut spec = E::default_spec();
            spec.milliseconds_per_slot = 1_000;

            let state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), &spec);
            let prev_eth1_hash = Hash256::from_low_u64_be(42);

            let blocks = vec![get_eth1_block(0, 0)];

            assert_eq!(
                eth1_data_sets(blocks.iter(), &state, prev_eth1_hash, &spec),
                None
            );
        }

        #[test]
        fn ideal_scenario() {
            let mut spec = E::default_spec();
            spec.milliseconds_per_slot = 1_000;

            let slots_per_eth1_voting_period = <E as EthSpec>::SlotsPerEth1VotingPeriod::to_u64();
            let eth1_follow_distance = spec.eth1_follow_distance;

            let mut state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), &spec);
            state.genesis_time = 0;
            state.slot = Slot::from(slots_per_eth1_voting_period * 3);

            let prev_eth1_hash = Hash256::zero();

            let blocks = (0..eth1_follow_distance * 4)
                .map(|i| get_eth1_block(i, i))
                .collect::<Vec<_>>();

            let (new_eth1_data, all_eth1_data) =
                eth1_data_sets(blocks.iter(), &state, prev_eth1_hash, &spec)
                    .expect("should find data");

            assert_eq!(
                all_eth1_data.len(),
                eth1_follow_distance as usize * 2,
                "all_eth1_data should have appropriate length"
            );
            assert_eq!(
                new_eth1_data.len(),
                eth1_follow_distance as usize,
                "new_eth1_data should have appropriate length"
            );

            for (eth1_data, block_number) in &new_eth1_data {
                assert_eq!(
                    all_eth1_data.get(eth1_data),
                    Some(block_number),
                    "all_eth1_data should contain all items in new_eth1_data"
                );
            }

            (1..=eth1_follow_distance * 2)
                .map(|i| get_eth1_block(i, i))
                .for_each(|eth1_block| {
                    assert_eq!(
                        eth1_block.number,
                        *all_eth1_data
                            .get(&eth1_block.clone().eth1_data().unwrap())
                            .expect("all_eth1_data should have expected block")
                    )
                });

            (eth1_follow_distance + 1..=eth1_follow_distance * 2)
                .map(|i| get_eth1_block(i, i))
                .for_each(|eth1_block| {
                    assert_eq!(
                        eth1_block.number,
                        *new_eth1_data
                            .get(&eth1_block.clone().eth1_data().unwrap())
                            .expect(&format!(
                                "new_eth1_data should have expected block #{}",
                                eth1_block.number
                            ))
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

            let all_eth1_data = get_eth1_data_vec(slots, 0);
            let new_eth1_data = all_eth1_data[slots as usize / 2..].to_vec();

            let votes = collect_valid_votes(
                &state,
                HashMap::from_iter(new_eth1_data.clone().into_iter()),
                HashMap::from_iter(all_eth1_data.clone().into_iter()),
            );
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

            let all_eth1_data = get_eth1_data_vec(slots, 0);
            let new_eth1_data = all_eth1_data[slots as usize / 2..].to_vec();

            state.eth1_data_votes = new_eth1_data[0..slots as usize / 4]
                .iter()
                .map(|(eth1_data, _)| eth1_data)
                .cloned()
                .collect::<Vec<_>>()
                .into();

            let votes = collect_valid_votes(
                &state,
                HashMap::from_iter(new_eth1_data.clone().into_iter()),
                HashMap::from_iter(all_eth1_data.clone().into_iter()),
            );
            assert_votes!(
                votes,
                new_eth1_data[0..slots as usize / 4].to_vec(),
                "should find as many votes as were in the state"
            );
        }

        #[test]
        fn duplicate_votes_in_state() {
            let slots = <E as EthSpec>::SlotsPerEth1VotingPeriod::to_u64();
            let spec = &E::default_spec();
            let mut state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), spec);

            let all_eth1_data = get_eth1_data_vec(slots, 0);
            let new_eth1_data = all_eth1_data[slots as usize / 2..].to_vec();

            let duplicate_eth1_data = new_eth1_data
                .last()
                .expect("should have some eth1 data")
                .clone();

            state.eth1_data_votes = vec![duplicate_eth1_data.clone(); 4]
                .iter()
                .map(|(eth1_data, _)| eth1_data)
                .cloned()
                .collect::<Vec<_>>()
                .into();

            let votes = collect_valid_votes(
                &state,
                HashMap::from_iter(new_eth1_data.clone().into_iter()),
                HashMap::from_iter(all_eth1_data.clone().into_iter()),
            );
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

        #[test]
        fn non_period_tail() {
            let slots = <E as EthSpec>::SlotsPerEth1VotingPeriod::to_u64();
            let spec = &E::default_spec();
            let mut state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), spec);
            state.slot = Slot::from(<E as EthSpec>::SlotsPerEpoch::to_u64()) * 10;

            let all_eth1_data = get_eth1_data_vec(slots, 0);
            let new_eth1_data = all_eth1_data[slots as usize / 2..].to_vec();

            let non_new_eth1_data = all_eth1_data
                .first()
                .expect("should have some eth1 data")
                .clone();

            state.eth1_data_votes = vec![non_new_eth1_data.0.clone()].into();

            let votes = collect_valid_votes(
                &state,
                HashMap::from_iter(new_eth1_data.clone().into_iter()),
                HashMap::from_iter(all_eth1_data.clone().into_iter()),
            );

            assert_votes!(
                votes,
                vec![],
                "should not find votes from all_eth1_data when it is not the period tail"
            );
        }

        #[test]
        fn period_tail() {
            let slots_per_eth1_voting_period = <E as EthSpec>::SlotsPerEth1VotingPeriod::to_u64();

            let slots = <E as EthSpec>::SlotsPerEth1VotingPeriod::to_u64();
            let spec = &E::default_spec();
            let mut state: BeaconState<E> = BeaconState::new(0, get_eth1_data(0), spec);

            state.slot = Slot::from(<E as EthSpec>::SlotsPerEpoch::to_u64()) * 10
                + slots_per_eth1_voting_period.integer_sqrt();

            let all_eth1_data = get_eth1_data_vec(slots, 0);
            let new_eth1_data = all_eth1_data[slots as usize / 2..].to_vec();

            let non_new_eth1_data = all_eth1_data
                .first()
                .expect("should have some eth1 data")
                .clone();

            state.eth1_data_votes = vec![non_new_eth1_data.0.clone()].into();

            let votes = collect_valid_votes(
                &state,
                HashMap::from_iter(new_eth1_data.clone().into_iter()),
                HashMap::from_iter(all_eth1_data.clone().into_iter()),
            );

            assert_votes!(
                votes,
                vec![non_new_eth1_data],
                "should find all_eth1_data votes when it is the period tail"
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
                find_winning_vote(Eth1DataVoteCount::from_iter(no_votes.into_iter()))
                    .expect("should find winner")
            );
        }

        #[test]
        fn equal_votes() {
            let votes = vec![vote(0, 1), vote(1, 1), vote(3, 1), vote(2, 1)];

            assert_eq!(
                // Favour the highest block number when there are equal votes.
                vote_data(&votes[2]),
                find_winning_vote(Eth1DataVoteCount::from_iter(votes.into_iter()))
                    .expect("should find winner")
            );
        }

        #[test]
        fn some_votes() {
            let votes = vec![vote(0, 0), vote(1, 1), vote(3, 1), vote(2, 2)];

            assert_eq!(
                // Favour the highest vote over the highest block number.
                vote_data(&votes[3]),
                find_winning_vote(Eth1DataVoteCount::from_iter(votes.into_iter()))
                    .expect("should find winner")
            );
        }

        #[test]
        fn tying_votes() {
            let votes = vec![vote(0, 0), vote(1, 1), vote(2, 2), vote(3, 2)];

            assert_eq!(
                // Favour the highest block number for tying votes.
                vote_data(&votes[3]),
                find_winning_vote(Eth1DataVoteCount::from_iter(votes.into_iter()))
                    .expect("should find winner")
            );
        }

        #[test]
        fn all_tying_votes() {
            let votes = vec![vote(3, 42), vote(2, 42), vote(1, 42), vote(0, 42)];

            assert_eq!(
                // Favour the highest block number for tying votes.
                vote_data(&votes[0]),
                find_winning_vote(Eth1DataVoteCount::from_iter(votes.into_iter()))
                    .expect("should find winner")
            );
        }
    }
}
