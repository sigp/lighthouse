//! Provides utilities for deploying and manipulating the eth2 deposit contract on the eth1 chain.
//!
//! Presently used with [`ganache-cli`](https://github.com/trufflesuite/ganache-cli) to simulate
//! the deposit contract for testing beacon node eth1 integration.
//!
//! Not tested to work with actual clients (e.g., geth). It should work fine, however there may be
//! some initial issues.
mod ganache;

use deposit_contract::{
    encode_eth1_tx_data, testnet, ABI, BYTECODE, CONTRACT_DEPLOY_GAS, DEPOSIT_GAS,
};
use ganache::GanacheInstance;
use std::time::Duration;
use tokio::time::sleep;
use types::DepositData;
use types::{test_utils::generate_deterministic_keypair, EthSpec, Hash256, Keypair, Signature};
use web3::contract::{Contract, Options};
use web3::transports::Http;
use web3::types::{Address, TransactionRequest, U256};
use web3::Web3;

pub const DEPLOYER_ACCOUNTS_INDEX: usize = 0;
pub const DEPOSIT_ACCOUNTS_INDEX: usize = 0;

/// Provides a dedicated ganache-cli instance with the deposit contract already deployed.
pub struct GanacheEth1Instance {
    pub ganache: GanacheInstance,
    pub deposit_contract: DepositContract,
}

impl GanacheEth1Instance {
    pub async fn new(network_id: u64, chain_id: u64) -> Result<Self, String> {
        let ganache = GanacheInstance::new(network_id, chain_id)?;
        DepositContract::deploy(ganache.web3.clone(), 0, None)
            .await
            .map(|deposit_contract| Self {
                ganache,
                deposit_contract,
            })
    }

    pub fn endpoint(&self) -> String {
        self.ganache.endpoint()
    }

    pub fn web3(&self) -> Web3<Http> {
        self.ganache.web3.clone()
    }
}

/// Deploys and provides functions for the eth2 deposit contract, deployed on the eth1 chain.
#[derive(Clone, Debug)]
pub struct DepositContract {
    web3: Web3<Http>,
    contract: Contract<Http>,
}

impl DepositContract {
    pub async fn deploy(
        web3: Web3<Http>,
        confirmations: usize,
        password: Option<String>,
    ) -> Result<Self, String> {
        Self::deploy_bytecode(web3, confirmations, BYTECODE, ABI, password).await
    }

    pub async fn deploy_testnet(
        web3: Web3<Http>,
        confirmations: usize,
        password: Option<String>,
    ) -> Result<Self, String> {
        Self::deploy_bytecode(
            web3,
            confirmations,
            testnet::BYTECODE,
            testnet::ABI,
            password,
        )
        .await
    }

    async fn deploy_bytecode(
        web3: Web3<Http>,
        confirmations: usize,
        bytecode: &[u8],
        abi: &[u8],
        password: Option<String>,
    ) -> Result<Self, String> {
        let address = deploy_deposit_contract(
            web3.clone(),
            confirmations,
            bytecode.to_vec(),
            abi.to_vec(),
            password,
        )
        .await
        .map_err(|e| {
            format!(
                "Failed to deploy contract: {}. Is scripts/ganache_tests_node.sh running?.",
                e
            )
        })?;
        Contract::from_json(web3.clone().eth(), address, ABI)
            .map_err(|e| format!("Failed to init contract: {:?}", e))
            .map(move |contract| Self { web3, contract })
    }

    /// The deposit contract's address in `0x00ab...` format.
    pub fn address(&self) -> String {
        format!("0x{:x}", self.contract.address())
    }

    /// A helper to return a fully-formed `DepositData`. Does not submit the deposit data to the
    /// smart contact.
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
            signature: Signature::empty().into(),
        };

        deposit.signature = deposit.create_signature(&keypair.sk, &E::default_spec());

        deposit
    }

    /// Creates a random, valid deposit and submits it to the deposit contract.
    ///
    /// The keypairs are created randomly and destroyed.
    pub async fn deposit_random<E: EthSpec>(&self) -> Result<(), String> {
        let keypair = Keypair::random();

        let mut deposit = DepositData {
            pubkey: keypair.pk.into(),
            withdrawal_credentials: Hash256::zero(),
            amount: 32_000_000_000,
            signature: Signature::empty().into(),
        };

        deposit.signature = deposit.create_signature(&keypair.sk, &E::default_spec());

        self.deposit(deposit).await
    }

    /// Perfoms a blocking deposit.
    pub async fn deposit(&self, deposit_data: DepositData) -> Result<(), String> {
        self.deposit_async(deposit_data)
            .await
            .map_err(|e| format!("Deposit failed: {:?}", e))
    }

    pub async fn deposit_deterministic_async<E: EthSpec>(
        &self,
        keypair_index: usize,
        amount: u64,
    ) -> Result<(), String> {
        let keypair = generate_deterministic_keypair(keypair_index);

        let mut deposit = DepositData {
            pubkey: keypair.pk.into(),
            withdrawal_credentials: Hash256::zero(),
            amount,
            signature: Signature::empty().into(),
        };

        deposit.signature = deposit.create_signature(&keypair.sk, &E::default_spec());

        self.deposit_async(deposit).await
    }

    /// Performs a non-blocking deposit.
    pub async fn deposit_async(&self, deposit_data: DepositData) -> Result<(), String> {
        let from = self
            .web3
            .eth()
            .accounts()
            .await
            .map_err(|e| format!("Failed to get accounts: {:?}", e))
            .and_then(|accounts| {
                accounts
                    .get(DEPOSIT_ACCOUNTS_INDEX)
                    .cloned()
                    .ok_or_else(|| "Insufficient accounts for deposit".to_string())
            })?;
        let tx_request = TransactionRequest {
            from,
            to: Some(self.contract.address()),
            gas: Some(U256::from(DEPOSIT_GAS)),
            gas_price: None,
            value: Some(from_gwei(deposit_data.amount)),
            // Note: the reason we use this `TransactionRequest` instead of just using the
            // function in `self.contract` is so that the `eth1_tx_data` function gets used
            // during testing.
            //
            // It's important that `eth1_tx_data` stays correct and does not suffer from
            // code-rot.
            data: encode_eth1_tx_data(&deposit_data).map(Into::into).ok(),
            nonce: None,
            condition: None,
            transaction_type: None,
            access_list: None,
        };

        self.web3
            .eth()
            .send_transaction(tx_request)
            .await
            .map_err(|e| format!("Failed to call deposit fn: {:?}", e))?;
        Ok(())
    }

    /// Peforms many deposits, each preceded by a delay.
    pub async fn deposit_multiple(&self, deposits: Vec<DelayThenDeposit>) -> Result<(), String> {
        for deposit in deposits.into_iter() {
            sleep(deposit.delay).await;
            self.deposit_async(deposit.deposit).await?;
        }
        Ok(())
    }
}

/// Describes a deposit and a delay that should should precede it's submission to the deposit
/// contract.
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

/// Deploys the deposit contract to the given web3 instance using the account with index
/// `DEPLOYER_ACCOUNTS_INDEX`.
async fn deploy_deposit_contract(
    web3: Web3<Http>,
    confirmations: usize,
    bytecode: Vec<u8>,
    abi: Vec<u8>,
    password_opt: Option<String>,
) -> Result<Address, String> {
    let bytecode = String::from_utf8(bytecode).expect("bytecode must be valid utf8");

    let from_address = web3
        .eth()
        .accounts()
        .await
        .map_err(|e| format!("Failed to get accounts: {:?}", e))
        .and_then(|accounts| {
            accounts
                .get(DEPLOYER_ACCOUNTS_INDEX)
                .cloned()
                .ok_or_else(|| "Insufficient accounts for deployer".to_string())
        })?;

    let deploy_address = if let Some(password) = password_opt {
        let result = web3
            .personal()
            .unlock_account(from_address, &password, None)
            .await;
        match result {
            Ok(true) => return Ok(from_address),
            Ok(false) => return Err("Eth1 node refused to unlock account".to_string()),
            Err(e) => return Err(format!("Eth1 unlock request failed: {:?}", e)),
        };
    } else {
        from_address
    };

    let pending_contract = Contract::deploy(web3.eth(), &abi)
        .map_err(|e| format!("Unable to build contract deployer: {:?}", e))?
        .confirmations(confirmations)
        .options(Options {
            gas: Some(U256::from(CONTRACT_DEPLOY_GAS)),
            ..Options::default()
        })
        .execute(bytecode, (), deploy_address);

    pending_contract
        .await
        .map(|contract| contract.address())
        .map_err(|e| format!("Unable to resolve pending contract: {:?}", e))
}
