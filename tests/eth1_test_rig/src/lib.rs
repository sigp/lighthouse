//! Provides utilities for deploying and manipulating the eth2 deposit contract on the eth1 chain.
//!
//! Presently used with [`ganache-cli`](https://github.com/trufflesuite/ganache-cli) to simulate
//! the deposit contract for testing beacon node eth1 integration.
//!
//! Not tested to work with actual clients (e.g., geth). It should work fine, however there may be
//! some initial issues.

use futures::Future;
use serde_json::json;
use ssz::Encode;
use std::sync::Arc;
use tokio::runtime::Runtime;
use types::DepositData;
use web3::contract::{Contract, Options};
use web3::transports::{EventLoopHandle, Http};
use web3::types::{Address, U256};
use web3::{Transport, Web3};

const DEPLOYER_ACCOUNTS_INDEX: usize = 0;
const DEPOSIT_ACCOUNTS_INDEX: usize = 1;

const CONFIRMATIONS: usize = 0;
const CONTRACT_DEPLOY_GAS: usize = 1_000_000_000;
const DEPOSIT_GAS: usize = 1_000_000_000;

// Deposit contract
pub const ABI: &'static [u8] = include_bytes!("../contract/v0.8.3_validator_registration.json");
pub const BYTECODE: &'static [u8] =
    include_bytes!("../contract/v0.8.3_validator_registration.bytecode");

/// Wrapper around web3 api.
/// Transport hardcoded to ws since its needed for subscribing to logs.
#[derive(Clone, Debug)]
pub struct DepositContract {
    event_loop: Arc<EventLoopHandle>,
    /// Websocket transport object. Needed for logs subscription.
    web3: Web3<Http>,
    /// Deposit Contract
    contract: Contract<Http>,
}

impl DepositContract {
    /// Create a new Web3 object.
    pub fn deploy(endpoint: &str) -> Result<Self, String> {
        let (event_loop, transport) = Http::new(endpoint)
            .map_err(|e| format!("Failed to start websocket transport: {:?}", e))?;
        let web3 = Web3::new(transport);

        let deposit_contract_address = runtime()?
            .block_on(deploy_deposit_contract(web3.clone()))
            .map_err(|e| format!("Failed to deploy contract: {}", e))?;

        let contract = Contract::from_json(web3.eth(), deposit_contract_address, ABI)
            .map_err(|e| format!("Failed to init contract: {:?}", e))?;

        Ok(Self {
            event_loop: Arc::new(event_loop),
            web3,
            contract: contract,
        })
    }

    /// Increase the timestamp on future blocks by `increase_by` seconds.
    pub fn increase_time(&self, increase_by: u64) -> Result<(), String> {
        runtime()?.block_on(increase_time(self.web3.clone(), increase_by))
    }

    /// The deposit contract's address in `0x00ab...` format.
    pub fn address(&self) -> String {
        format!("0x{:x}", self.contract.address())
    }

    pub fn deposit(&self, deposit_data: DepositData) -> Result<(), String> {
        let contract = self.contract.clone();
        let web3_1 = self.web3.clone();

        let future = self
            .web3
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
            // Ensure the next block has a higher timestamp than this.
            .and_then(move |_| increase_time(web3_1.clone(), 1));

        runtime()?
            .block_on(future)
            .map_err(|e| format!("Deposit failed: {:?}", e))
    }
}

fn from_gwei(gwei: u64) -> U256 {
    U256::from(gwei) * U256::exp10(9)
}

fn runtime() -> Result<Runtime, String> {
    Runtime::new().map_err(|e| format!("Failed to start tokio runtime: {}", e))
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
