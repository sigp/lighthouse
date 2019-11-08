use crate::BeaconChainTypes;
use eth1::{Config as Eth1Config, Eth1Block, Service as HttpService};
use eth2_hashing::hash;
use exit_future::Exit;
use futures::Future;
use integer_sqrt::IntegerSquareRoot;
use slog::Logger;
use std::collections::HashMap;
use std::iter::DoubleEndedIterator;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::sync::Arc;
use store::{Error as StoreError, Store};
use types::{
    BeaconState, BeaconStateError, ChainSpec, Deposit, Eth1Data, EthSpec, Hash256, Slot, Unsigned,
};

const DEPOSIT_TREE_DEPTH: usize = 32;

#[derive(Debug, PartialEq)]
pub enum Error {
    /// Unable to return an Eth1Data for the given epoch.
    EpochUnavailable,
    /// An error from the backend service (e.g., the web3 data fetcher).
    BackendError(String),
    /// The deposit index of the state is higher than the deposit contract. This is a critical
    /// consensus error.
    DepositIndexTooHigh,
    DepositRootMismatch,
    NoEth1Vote,
    UnableToGetPreviousStateRoot(BeaconStateError),
    PreviousStateNotInDB,
    StoreError(StoreError),
}

/// Holds an `Eth1ChainBackend` and serves requests from the `BeaconChain`.
pub struct Eth1Chain<T: BeaconChainTypes> {
    backend: T::Eth1Chain,
    /// When `true`, the backend will be ignored and dummy data from the 2019 Canada interop method
    /// will be used instead.
    pub use_dummy_backend: bool,
}

impl<T: BeaconChainTypes> Eth1Chain<T> {
    pub fn new(backend: T::Eth1Chain) -> Self {
        Self {
            backend,
            use_dummy_backend: false,
        }
    }

    /// Returns the `Eth1Data` that should be included in a block being produced for the given
    /// `state`.
    pub fn eth1_data_for_block_production(
        &self,
        state: &BeaconState<T::EthSpec>,
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
        state: &BeaconState<T::EthSpec>,
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

#[derive(Clone)]
pub struct JsonRpcEth1Backend<T: EthSpec, S> {
    pub core: HttpService,
    store: Arc<S>,
    _phantom: PhantomData<T>,
}

impl<T: EthSpec, S: Store> JsonRpcEth1Backend<T, S> {
    pub fn new(config: Eth1Config, log: Logger, store: Arc<S>) -> Self {
        Self {
            core: HttpService::new(config, log),
            store,
            _phantom: PhantomData,
        }
    }

    pub fn start(&self, exit: Exit) -> impl Future<Item = (), Error = ()> {
        self.core.auto_update(exit)
    }

    /// Instantiates `self` from an existing service.
    pub fn from_service(service: HttpService, store: Arc<S>) -> Self {
        Self {
            core: service,
            store,
            _phantom: PhantomData,
        }
    }
}

impl<T: EthSpec, S: Store> Eth1ChainBackend<T> for JsonRpcEth1Backend<T, S> {
    fn eth1_data(&self, state: &BeaconState<T>, spec: &ChainSpec) -> Result<Eth1Data, Error> {
        let period = T::SlotsPerEth1VotingPeriod::to_u64();

        // Find `state.eth1_data.block_hash` for the state at the start of the voting period.
        let prev_eth1_hash = if state.slot % period < period / 2 {
            // When the state is less than half way through the period we can safely assume that
            // the eth1_data has not changed since the start of the period.
            state.eth1_data.block_hash
        } else {
            let slot = (state.slot / period) * period;
            let prev_state_root = state
                .get_state_root(slot)
                .map_err(|e| Error::UnableToGetPreviousStateRoot(e))?;

            self.store
                .get::<BeaconState<T>>(&prev_state_root)
                .map_err(|e| Error::StoreError(e))?
                .ok_or_else(|| Error::PreviousStateNotInDB)?
                .eth1_data
                .block_hash
        };

        let blocks = self.core.blocks().read();

        let (new_eth1_data, all_eth1_data) =
            eth1_data_sets(blocks.iter(), state, prev_eth1_hash, spec)
                .map_err(|e| Error::BackendError(e))?;
        let valid_votes = collect_valid_votes(state, new_eth1_data, all_eth1_data)
            .map_err(|e| Error::BackendError(e))?;

        // TODO: return random if a vote was not found.
        find_winning_vote(valid_votes).map_err(|e| Error::BackendError(e))
    }

    fn queued_deposits(
        &self,
        state: &BeaconState<T>,
        _spec: &ChainSpec,
    ) -> Result<Vec<Deposit>, Error> {
        let deposit_count = state.eth1_data.deposit_count;

        let next = state.eth1_deposit_index + 1;
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

type BlockNumber = u64;
type Eth1DataBlockNumber = HashMap<Eth1Data, BlockNumber>;
type Eth1DataVoteCount = HashMap<(Eth1Data, BlockNumber), u64>;

fn eth1_data_sets<'a, T: EthSpec, I>(
    blocks: I,
    state: &BeaconState<T>,
    prev_eth1_hash: Hash256,
    spec: &ChainSpec,
) -> Result<(Eth1DataBlockNumber, Eth1DataBlockNumber), String>
where
    T: EthSpec,
    I: DoubleEndedIterator<Item = &'a Eth1Block> + Clone,
{
    let slots_per_eth1_voting_period = T::SlotsPerEth1VotingPeriod::to_u64();
    let eth1_follow_distance = spec.eth1_follow_distance;

    let voting_period_start_slot =
        (state.slot / slots_per_eth1_voting_period) * slots_per_eth1_voting_period;
    let voting_period_start_seconds = slot_start_seconds::<T>(
        state.genesis_time,
        spec.milliseconds_per_slot,
        voting_period_start_slot,
    );

    let voting_period_start_block_number: u64 = blocks
        .clone()
        .rev()
        .find(|block| block.timestamp <= voting_period_start_seconds)
        .map(|block| block.number)
        .ok_or_else(|| "Unable to find eth1 head at start of voting period".to_string())?;

    let previous_eth1_block_number: u64 = blocks
        .clone()
        .find(|block| block.hash == prev_eth1_hash)
        .map(|block| block.number)
        .ok_or_else(|| "Unable to find current eth1 block hash in cache".to_string())?;

    let new_eth1_data = HashMap::from_iter(
        blocks
            .clone()
            .rev()
            .skip_while(|block| {
                block.number > voting_period_start_block_number + eth1_follow_distance
            })
            .take_while(|block| {
                block.number > voting_period_start_block_number + eth1_follow_distance * 2
            })
            // Note: this filter map quietly ignores any block from before the deposit contract
            // was deployed.
            .filter_map(|block| Some((block.clone().eth1_data()?, block.number))),
    );

    let all_eth1_data = HashMap::from_iter(
        blocks
            .clone()
            .rev()
            .skip_while(|block| {
                block.number > voting_period_start_block_number + eth1_follow_distance * 2
            })
            .take_while(|block| block.number >= previous_eth1_block_number)
            // Note: this filter map quietly ignores any block from before the deposit contract
            // was deployed.
            .filter_map(|block| Some((block.clone().eth1_data()?, block.number))),
    );

    Ok((new_eth1_data, all_eth1_data))
}

fn collect_valid_votes<T: EthSpec>(
    state: &BeaconState<T>,
    new_eth1_data: Eth1DataBlockNumber,
    all_eth1_data: Eth1DataBlockNumber,
) -> Result<Eth1DataVoteCount, String> {
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

    Ok(valid_votes)
}

fn find_winning_vote(valid_votes: Eth1DataVoteCount) -> Result<Eth1Data, String> {
    valid_votes
        .iter()
        .max_by_key(|((_eth1_data, block_number), vote_count)| {
            (*vote_count, u64::max_value() - block_number)
        })
        .ok_or_else(|| "Unable to find winning eth1 vote".to_string())
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
    use types::MinimalEthSpec;

    type E = MinimalEthSpec;

    fn get_eth1_data(i: u64) -> Eth1Data {
        Eth1Data {
            block_hash: Hash256::from_low_u64_be(i),
            deposit_root: Hash256::from_low_u64_be(u64::max_value() - i),
            deposit_count: i,
        }
    }

    #[test]
    fn test_slot_start_seconds() {
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
            )
            .expect("should get valid votes");
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
            )
            .expect("should get valid votes");
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
            )
            .expect("should get valid votes");
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
            )
            .expect("should get valid votes");

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
            )
            .expect("should get valid votes");

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
                        deposit_root: Hash256::zero(),
                        deposit_count: 0,
                        block_hash: Hash256::zero(),
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
            let no_votes = vec![vote(0, 1), vote(1, 1), vote(3, 1), vote(2, 1)];

            assert_eq!(
                // Favour the highest block number when there are equal votes.
                vote_data(&no_votes[2]),
                find_winning_vote(Eth1DataVoteCount::from_iter(no_votes.into_iter()))
                    .expect("should find winner")
            );
        }

        #[test]
        fn some_votes() {
            let no_votes = vec![vote(0, 0), vote(1, 1), vote(3, 1), vote(2, 2)];

            assert_eq!(
                // Favour the highest vote over the highest block number.
                vote_data(&no_votes[3]),
                find_winning_vote(Eth1DataVoteCount::from_iter(no_votes.into_iter()))
                    .expect("should find winner")
            );
        }

        #[test]
        fn tying_votes() {
            let no_votes = vec![vote(0, 0), vote(1, 1), vote(3, 2), vote(2, 2)];

            assert_eq!(
                // Favour the highest block number for tying votes.
                vote_data(&no_votes[2]),
                find_winning_vote(Eth1DataVoteCount::from_iter(no_votes.into_iter()))
                    .expect("should find winner")
            );
        }
    }
}
