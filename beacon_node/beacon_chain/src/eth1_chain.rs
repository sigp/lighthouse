use crate::BeaconChainTypes;
use eth1_http::Eth1Cache;
use eth2_hashing::hash;
use std::marker::PhantomData;
use types::{BeaconState, ChainSpec, Deposit, Eth1Data, EthSpec, Hash256, Slot, Unsigned};

type Result<T> = std::result::Result<T, Error>;

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
    ) -> Result<Eth1Data> {
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
    ) -> Result<Vec<Deposit>> {
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
    fn new(server: String, contract_addr: String, log: &slog::Logger) -> Result<Self>;

    /// Returns the `Eth1Data` that should be included in a block being produced for the given
    /// `state`.
    fn eth1_data(&self, beacon_state: &BeaconState<T>) -> Result<Eth1Data>;

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
    ) -> Result<Vec<Deposit>>;
}

pub struct InteropEth1ChainBackend<T: EthSpec> {
    _phantom: PhantomData<T>,
}

impl<T: EthSpec> Eth1ChainBackend<T> for InteropEth1ChainBackend<T> {
    fn new(_server: String, _contract_addr: String, _log: &slog::Logger) -> Result<Self> {
        Ok(Self::default())
    }

    fn eth1_data(&self, state: &BeaconState<T>) -> Result<Eth1Data> {
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

    fn queued_deposits(&self, _: &BeaconState<T>, _: &ChainSpec) -> Result<Vec<Deposit>> {
        Ok(vec![])
    }
}

impl<T: EthSpec> Default for InteropEth1ChainBackend<T> {
    fn default() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

/// Returns `int` as little-endian bytes with a length of 32.
fn int_to_bytes32(int: u64) -> Vec<u8> {
    let mut vec = int.to_le_bytes().to_vec();
    vec.resize(32, 0);
    vec
}

impl<T: EthSpec> Eth1ChainBackend<T> for Eth1Cache {
    fn new(_server: String, _contract_addr: String, _log: &slog::Logger) -> Result<Self> {
        // TODO: fix or perish.
        panic!()
    }

    fn eth1_data(&self, _state: &BeaconState<T>) -> Result<Eth1Data> {
        // TODO: fix or perish.
        panic!()
    }

    fn queued_deposits(&self, state: &BeaconState<T>, spec: &ChainSpec) -> Result<Vec<Deposit>> {
        let deposit_count = state.eth1_data.deposit_count;
        let deposit_index = state.eth1_deposit_index;

        if deposit_index > deposit_count {
            Err(Error::DepositIndexTooHigh)
        } else if deposit_index == deposit_count {
            Ok(vec![])
        } else {
            let count = std::cmp::min(deposit_count - deposit_index, T::MaxDeposits::to_u64());
            let first = deposit_index + 1;
            let (root, deposits) = self
                .get_deposits(
                    first..first + count,
                    deposit_count,
                    spec.deposit_contract_tree_depth as usize,
                )
                .map_err(|e| Error::BackendError(format!("{:?}", e)))?;

            if root == state.eth1_data.deposit_root {
                Ok(deposits)
            } else {
                Err(Error::DepositRootMismatch)
            }
        }
    }
}

/// Returns the unix-epoch seconds at the start of the given `slot`.
fn slot_start_seconds<T: EthSpec>(
    genesis_unix_seconds: u64,
    seconds_per_slot: u64,
    slot: Slot,
) -> u64 {
    genesis_unix_seconds + slot.as_u64() * seconds_per_slot
}
