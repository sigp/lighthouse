use crate::BeaconChainTypes;
use eth2_hashing::hash;
use std::marker::PhantomData;
use types::{BeaconState, Deposit, Eth1Data, EthSpec, Hash256};

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
    ) -> Result<Vec<Deposit>> {
        let deposits = self.backend.queued_deposits(state)?;

        // TODO: truncate deposits if required.

        Ok(deposits)
    }
}

#[derive(Debug, PartialEq)]
pub enum Error {
    /// Unable to return an Eth1Data for the given epoch.
    EpochUnavailable,
    /// An error from the backend service (e.g., the web3 data fetcher).
    BackendError(String),
}

pub trait Eth1ChainBackend<T: EthSpec>: Sized + Send + Sync {
    fn new(server: String) -> Result<Self>;

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
    fn queued_deposits(&self, beacon_state: &BeaconState<T>) -> Result<Vec<Deposit>>;
}

pub struct InteropEth1ChainBackend<T: EthSpec> {
    _phantom: PhantomData<T>,
}

impl<T: EthSpec> Eth1ChainBackend<T> for InteropEth1ChainBackend<T> {
    fn new(_server: String) -> Result<Self> {
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

    fn queued_deposits(&self, _: &BeaconState<T>) -> Result<Vec<Deposit>> {
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
