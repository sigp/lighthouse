use crate::BeaconChainTypes;
use eth1::{Config as Eth1Config, Service as HttpService};
use eth2_hashing::hash;
use exit_future::Exit;
use futures::Future;
use slog::Logger;
use std::marker::PhantomData;
use types::{BeaconState, ChainSpec, Deposit, Eth1Data, EthSpec, Hash256};

/// Holds an `Eth1ChainBackend` and serves requests from the `BeaconChain`.
pub struct Eth1Chain<T: BeaconChainTypes> {
    backend: T::Eth1Chain,
}

impl<T: BeaconChainTypes> Eth1Chain<T> {
    pub fn new(backend: T::Eth1Chain) -> Self {
        Self { backend }
    }

    /// Returns the `Eth1Data` that should be included in a block being produced for the given
    /// `state`.
    pub fn eth1_data_for_block_production(
        &self,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<Eth1Data, Error> {
        self.backend.eth1_data(state)
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
        self.backend.queued_deposits(state, spec)
    }
}

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
}

pub trait Eth1ChainBackend<T: EthSpec>: Sized + Send + Sync {
    fn new(server: String, contract_addr: String, log: &slog::Logger) -> Result<Self, Error>;

    /// Returns the `Eth1Data` that should be included in a block being produced for the given
    /// `state`.
    fn eth1_data(&self, beacon_state: &BeaconState<T>) -> Result<Eth1Data, Error>;

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

pub struct DummyEth1ChainBackend<T: EthSpec> {
    _phantom: PhantomData<T>,
}

impl<T: EthSpec> Eth1ChainBackend<T> for DummyEth1ChainBackend<T> {
    fn new(_server: String, _contract_addr: String, _log: &slog::Logger) -> Result<Self, Error> {
        Ok(Self::default())
    }

    fn eth1_data(&self, state: &BeaconState<T>) -> Result<Eth1Data, Error> {
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
        Self {
            _phantom: PhantomData,
        }
    }
}

#[derive(Clone)]
pub struct JsonRpcEth1Backend<T: EthSpec> {
    pub core: HttpService,
    /// When `true`, the caches in `core` will be ignored and dummy data from the 2019 Canada
    /// interop method will be used instead.
    pub use_dummy_backend: bool,
    _phantom: PhantomData<T>,
}

impl<T: EthSpec> JsonRpcEth1Backend<T> {
    pub fn new(config: Eth1Config, log: Logger) -> Self {
        Self {
            core: HttpService::new(config, log),
            use_dummy_backend: false,
            _phantom: PhantomData,
        }
    }

    pub fn start(&self, exit: Exit) -> impl Future<Item = (), Error = ()> {
        self.core.auto_update(exit)
    }

    /// Instantiates `self` from an existing service.
    pub fn from_service(service: HttpService) -> Self {
        Self {
            core: service,
            use_dummy_backend: false,
            _phantom: PhantomData,
        }
    }

    /*
    /// Returns all the `Eth1Data` starting at the block with the `from` hash, up until the last
    /// cached block with a timestamp that is less than or equal to `to`.
    ///
    /// Blocks are returned in ascending order of block number.
    ///
    /// ## Errors
    ///
    /// - If a block with `from` hash is not found in the cache.
    /// - If any block within the `from` and `to` range was prior to the deployment of the deposit
    /// contract (specified in `Config`).
    pub fn get_eth1_data(&self, from: Hash256, to: Duration) -> Result<Vec<Eth1Data>, String> {
        let cache = self.core.blocks().read();

        let from = cache
            .iter()
            .position(|block| block.hash == from)
            .ok_or_else(|| format!("Block with hash {:?} is not in eth1 block cache", from))?;

        cache
            .iter()
            .skip(from)
            .take_while(|block| Duration::from_secs(block.timestamp) <= to)
            .map(|block| {
                block.clone().eth1_data().ok_or_else(|| {
                    "Attempted to get eth1 from blocks prior to deposit contract deployment"
                        .to_string()
                })
            })
            .collect()
    }

    /// Returns a list of `Deposit` objects, within the given deposit index `range`.
    ///
    /// The `deposit_count` is used to generate the proofs for the `Deposits`. For example, if we
    /// have 100 proofs, but the eth2 chain only acknowledges 50 of them, we must produce our
    /// proofs with respect to a tree size of 50.
    ///
    ///
    /// ## Errors
    ///
    /// - If `deposit_count` is larger than `range.end`.
    /// - There are not sufficient deposits in the tree to generate the proof.
    pub fn get_deposits(
        &self,
        range: Range<u64>,
        deposit_count: u64,
        tree_depth: usize,
    ) -> Result<(Hash256, Vec<Deposit>), String> {
        self.core
            .deposits()
            .read()
            .cache
            .get_deposits(range, deposit_count, tree_depth)
            .map_err(|e| format!("Failed to get deposits: {:?}", e))
    }
    */
}

impl<T: EthSpec> Eth1ChainBackend<T> for JsonRpcEth1Backend<T> {
    fn new(_server: String, _contract_addr: String, _log: &slog::Logger) -> Result<Self, Error> {
        // TODO: ensure dummy values are used.
        panic!()
    }

    fn eth1_data(&self, _state: &BeaconState<T>) -> Result<Eth1Data, Error> {
        // TODO: ensure dummy values are used.
        panic!()
    }

    fn queued_deposits(&self, _: &BeaconState<T>, _: &ChainSpec) -> Result<Vec<Deposit>, Error> {
        // TODO: ensure dummy values are used.
        panic!()
    }
}

/// Returns `int` as little-endian bytes with a length of 32.
fn int_to_bytes32(int: u64) -> Vec<u8> {
    let mut vec = int.to_le_bytes().to_vec();
    vec.resize(32, 0);
    vec
}

/*
/// Returns the unix-epoch seconds at the start of the given `slot`.
fn slot_start_seconds<T: EthSpec>(
    genesis_unix_seconds: u64,
    seconds_per_slot: u64,
    slot: Slot,
) -> u64 {
    genesis_unix_seconds + slot.as_u64() * seconds_per_slot
}
*/
