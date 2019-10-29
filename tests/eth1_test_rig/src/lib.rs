//! Provides utilities for deploying and manipulating the eth2 deposit contract on the eth1 chain.
//!
//! Presently used with [`ganache-cli`](https://github.com/trufflesuite/ganache-cli) to simulate
//! the deposit contract for testing beacon node eth1 integration.
//!
//! Not tested to work with actual clients (e.g., geth). It should work fine, however there may be
//! some initial issues.

use futures::{stream, Future, Stream};
use serde_json::json;
use ssz::Encode;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::{runtime::Runtime, timer::Delay};
use types::DepositData;
use types::{Epoch, EthSpec, Fork, Hash256, Keypair, Signature};
use web3::contract::{Contract, Options};
use web3::transports::{EventLoopHandle, Http};
use web3::types::{Address, U256};
use web3::{api::Eth, Transport, Web3};

const DEPLOYER_ACCOUNTS_INDEX: usize = 0;
const DEPOSIT_ACCOUNTS_INDEX: usize = 1;

const CONFIRMATIONS: usize = 0;
const CONTRACT_DEPLOY_GAS: usize = 1_000_000_000;
const DEPOSIT_GAS: usize = 1_000_000_000;

// Deposit contract
pub const ABI: &'static [u8] = include_bytes!("../contract/v0.8.3_validator_registration.json");
pub const BYTECODE: &'static [u8] =
    include_bytes!("../contract/v0.8.3_validator_registration.bytecode");

pub struct UnsafeBlockingUtils<T> {
    core: T,
    runtime: Runtime,
}

impl UnsafeBlockingUtils<DepositContract> {
    pub fn new(core: DepositContract, runtime: Runtime) -> Self {
        Self { core, runtime }
    }

    fn eth(&self) -> Eth<Http> {
        self.core.web3.eth()
    }

    pub fn block_number(&mut self, runtime: &mut Runtime) -> u64 {
        runtime
            .block_on(self.eth().block_number().map(|v| v.as_u64()))
            .expect("utils should get block number")
    }

    /// Increase the timestamp on future blocks by `increase_by` seconds.
    pub fn increase_time(&mut self, increase_by: u64) {
        self.runtime
            .block_on(
                self.core
                    .web3
                    .transport()
                    .execute("evm_increaseTime", vec![json!(increase_by)])
                    .map(|_json_value| ())
                    .map_err(|e| {
                        format!("Failed to increase time on EVM (is this ganache?): {:?}", e)
                    }),
            )
            .expect("utils should increase time")
    }

    pub fn evm_mine(&mut self) {
        self.runtime
            .block_on(self.core.web3.transport().execute("evm_mine", vec![]))
            .expect("utils should mine new block with evm_mine (only works with ganache-cli!)");
    }

    pub fn get_deposit<E: EthSpec>(
        &self,
        keypair: Keypair,
        withdrawal_credentials: Hash256,
        amount: u64,
    ) -> DepositData {
        let mut deposit = DepositData {
            pubkey: keypair.pk.into(),
            withdrawal_credentials,
            amount,
            signature: Signature::empty_signature().into(),
        };

        deposit.signature = deposit.create_signature(
            &keypair.sk,
            Epoch::new(0),
            &Fork::default(),
            &E::default_spec(),
        );

        deposit
    }
}

#[derive(Clone, Debug)]
pub struct DepositContract {
    event_loop: Arc<EventLoopHandle>,
    web3: Web3<Http>,
    contract: Contract<Http>,
}

impl DepositContract {
    pub fn deploy(runtime: &mut Runtime, endpoint: &str) -> Result<Self, String> {
        let (event_loop, transport) = Http::new(endpoint)
            .map_err(|e| format!("Failed to start websocket transport: {:?}", e))?;
        let web3 = Web3::new(transport);

        let deposit_contract_address = runtime
            .block_on(deploy_deposit_contract(web3.clone()))
            .map_err(|e| {
                format!(
                    "Failed to deploy contract: {}. Is scripts/ganache_tests_node.sh running?.",
                    e
                )
            })?;

        let contract = Contract::from_json(web3.eth(), deposit_contract_address, ABI)
            .map_err(|e| format!("Failed to init contract: {:?}", e))?;

        Ok(Self {
            event_loop: Arc::new(event_loop),
            web3,
            contract: contract,
        })
    }

    /// Increase the timestamp on future blocks by `increase_by` seconds.
    pub fn increase_time(&self, runtime: &mut Runtime, increase_by: u64) -> Result<(), String> {
        runtime.block_on(increase_time(self.web3.clone(), increase_by))
    }

    /// The deposit contract's address in `0x00ab...` format.
    pub fn address(&self) -> String {
        format!("0x{:x}", self.contract.address())
    }

    pub fn unsafe_blocking_utils(&self) -> UnsafeBlockingUtils<Self> {
        UnsafeBlockingUtils {
            core: self.clone(),
            runtime: Runtime::new().expect("Should build UnsafeBlockingUtils runtime"),
        }
    }

    pub fn deposit_helper<E: EthSpec>(
        &self,
        keypair: Keypair,
        withdrawal_credentials: Hash256,
        amount: u64,
    ) -> DepositData {
        let mut deposit = DepositData {
            pubkey: keypair.pk.into(),
            withdrawal_credentials,
            amount,
            signature: Signature::empty_signature().into(),
        };

        deposit.signature = deposit.create_signature(
            &keypair.sk,
            Epoch::new(0),
            &Fork::default(),
            &E::default_spec(),
        );

        deposit
    }

    pub fn deposit_random<E: EthSpec>(&self, runtime: &mut Runtime) -> Result<(), String> {
        let keypair = Keypair::random();

        let mut deposit = DepositData {
            pubkey: keypair.pk.into(),
            withdrawal_credentials: Hash256::zero(),
            amount: 32_000_000_000,
            signature: Signature::empty_signature().into(),
        };

        deposit.signature = deposit.create_signature(
            &keypair.sk,
            Epoch::new(0),
            &Fork::default(),
            &E::default_spec(),
        );

        self.deposit(runtime, deposit)
    }

    pub fn deposit(&self, runtime: &mut Runtime, deposit_data: DepositData) -> Result<(), String> {
        runtime
            .block_on(self.deposit_async(deposit_data))
            .map_err(|e| format!("Deposit failed: {:?}", e))
    }

    pub fn deposit_async(
        &self,
        deposit_data: DepositData,
    ) -> impl Future<Item = (), Error = String> {
        let contract = self.contract.clone();

        self.web3
            .eth()
            .accounts()
            .map_err(|e| format!("Failed to get accounts: {:?}", e))
            .and_then(|accounts| {
                accounts
                    .get(DEPOSIT_ACCOUNTS_INDEX)
                    .cloned()
                    .ok_or_else(|| format!("Insufficient accounts for deposit"))
            })
            .and_then(move |from_address| {
                let params = (
                    deposit_data.pubkey.as_ssz_bytes(),
                    deposit_data.withdrawal_credentials.as_ssz_bytes(),
                    deposit_data.signature.as_ssz_bytes(),
                );
                let options = Options {
                    gas: Some(U256::from(DEPOSIT_GAS)),
                    value: Some(from_gwei(deposit_data.amount)),
                    ..Options::default()
                };
                contract
                    .call("deposit", params, from_address, options)
                    .map_err(|e| format!("Failed to call deposit fn: {:?}", e))
            })
            .map(|_| ())
    }

    pub fn deposit_multiple(
        &self,
        deposits: Vec<DelayThenDeposit>,
    ) -> impl Future<Item = (), Error = String> {
        let s = self.clone();
        stream::unfold(deposits.into_iter(), move |mut deposit_iter| {
            let s = s.clone();
            match deposit_iter.next() {
                Some(deposit) => Some(
                    Delay::new(Instant::now() + deposit.delay)
                        .map_err(|e| format!("Failed to execute delay: {:?}", e))
                        .and_then(move |_| s.deposit_async(deposit.deposit))
                        .map(move |yielded| (yielded, deposit_iter)),
                ),
                None => None,
            }
        })
        .collect()
        .map(|_| ())
    }
}

#[derive(Clone)]
pub struct DelayThenDeposit {
    /// Wait this duration ...
    pub delay: Duration,
    /// ... then submit this deposit.
    pub deposit: DepositData,
}

fn from_gwei(gwei: u64) -> U256 {
    U256::from(gwei) * U256::exp10(9)
}

fn deploy_deposit_contract<T: Transport>(
    web3: Web3<T>,
) -> impl Future<Item = Address, Error = String> {
    let bytecode = String::from_utf8_lossy(&BYTECODE);
    let web3_1 = web3.clone();

    web3.eth()
        .accounts()
        .map_err(|e| format!("Failed to get accounts: {:?}", e))
        .and_then(|accounts| {
            accounts
                .get(DEPLOYER_ACCOUNTS_INDEX)
                .cloned()
                .ok_or_else(|| format!("Insufficient accounts for deployer"))
        })
        .and_then(move |deploy_address| {
            Contract::deploy(web3.eth(), &ABI)
                .map_err(|e| format!("Unable to build contract deployer: {:?}", e))?
                .confirmations(CONFIRMATIONS)
                .options(Options {
                    gas: Some(U256::from(CONTRACT_DEPLOY_GAS)),
                    ..Options::default()
                })
                .execute(bytecode, (), deploy_address)
                .map_err(|e| format!("Failed to execute deployment: {:?}", e))
        })
        .and_then(|pending_contract| {
            pending_contract
                .map(|contract| contract.address())
                .map_err(|e| format!("Unable to resolve pending contract: {:?}", e))
        })
        .and_then(move |address| increase_time(web3_1.clone(), 1).map(move |_| address))
}

/// Increase the timestamp on future blocks by `increase_by` seconds.
fn increase_time<T: Transport>(
    web3: Web3<T>,
    increase_by: u64,
) -> impl Future<Item = (), Error = String> {
    web3.transport()
        .execute("evm_increaseTime", vec![json!(increase_by)])
        .map(|_json_value| ())
        .map_err(|e| format!("Failed to increase time on EVM (is this ganache?): {:?}", e))
}
