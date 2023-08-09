//! Provides utilities for deploying and manipulating the eth2 deposit contract on the eth1 chain.
//!
//! Presently used with [`anvil`](https://github.com/foundry-rs/foundry/tree/master/anvil) to simulate
//! the deposit contract for testing beacon node eth1 integration.
//!
//! Not tested to work with actual clients (e.g., geth). It should work fine, however there may be
//! some initial issues.
mod anvil;

use anvil::AnvilCliInstance;
use deposit_contract::{
    encode_eth1_tx_data, testnet, ABI, BYTECODE, CONTRACT_DEPLOY_GAS, DEPOSIT_GAS,
};
use ethers_contract::Contract;
use ethers_core::{
    abi::Abi,
    types::{transaction::eip2718::TypedTransaction, Address, Bytes, TransactionRequest, U256},
};
pub use ethers_providers::{Http, Middleware, Provider};
use std::time::Duration;
use tokio::time::sleep;
use types::DepositData;
use types::{test_utils::generate_deterministic_keypair, EthSpec, Hash256, Keypair, Signature};

pub const DEPLOYER_ACCOUNTS_INDEX: usize = 0;
pub const DEPOSIT_ACCOUNTS_INDEX: usize = 0;

/// Provides a dedicated anvil instance with the deposit contract already deployed.
pub struct AnvilEth1Instance {
    pub anvil: AnvilCliInstance,
    pub deposit_contract: DepositContract,
}

impl AnvilEth1Instance {
    pub async fn new(chain_id: u64) -> Result<Self, String> {
        let anvil = AnvilCliInstance::new(chain_id)?;
        DepositContract::deploy(anvil.client.clone(), 0, None)
            .await
            .map(|deposit_contract| Self {
                anvil,
                deposit_contract,
            })
    }

    pub fn endpoint(&self) -> String {
        self.anvil.endpoint()
    }

    pub fn json_rpc_client(&self) -> Provider<Http> {
        self.anvil.client.clone()
    }
}

/// Deploys and provides functions for the eth2 deposit contract, deployed on the eth1 chain.
#[derive(Clone, Debug)]
pub struct DepositContract {
    client: Provider<Http>,
    contract: Contract<Provider<Http>>,
}

impl DepositContract {
    pub async fn deploy(
        client: Provider<Http>,
        confirmations: usize,
        password: Option<String>,
    ) -> Result<Self, String> {
        Self::deploy_bytecode(client, confirmations, BYTECODE, ABI, password).await
    }

    pub async fn deploy_testnet(
        client: Provider<Http>,
        confirmations: usize,
        password: Option<String>,
    ) -> Result<Self, String> {
        Self::deploy_bytecode(
            client,
            confirmations,
            testnet::BYTECODE,
            testnet::ABI,
            password,
        )
        .await
    }

    async fn deploy_bytecode(
        client: Provider<Http>,
        confirmations: usize,
        bytecode: &[u8],
        abi: &[u8],
        password: Option<String>,
    ) -> Result<Self, String> {
        let abi = Abi::load(abi).map_err(|e| format!("Invalid deposit contract abi: {:?}", e))?;
        let address =
            deploy_deposit_contract(client.clone(), confirmations, bytecode.to_vec(), password)
                .await
                .map_err(|e| {
                    format!(
                        "Failed to deploy contract: {}. Is scripts/anvil_tests_node.sh running?.",
                        e
                    )
                })?;

        let contract = Contract::new(address, abi, client.clone());
        Ok(Self { client, contract })
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
            .client
            .get_accounts()
            .await
            .map_err(|e| format!("Failed to get accounts: {:?}", e))
            .and_then(|accounts| {
                accounts
                    .get(DEPOSIT_ACCOUNTS_INDEX)
                    .cloned()
                    .ok_or_else(|| "Insufficient accounts for deposit".to_string())
            })?;
        // Note: the reason we use this `TransactionRequest` instead of just using the
        // function in `self.contract` is so that the `eth1_tx_data` function gets used
        // during testing.
        //
        // It's important that `eth1_tx_data` stays correct and does not suffer from
        // code-rot.
        let tx_request = TransactionRequest::new()
            .from(from)
            .to(self.contract.address())
            .gas(DEPOSIT_GAS)
            .value(from_gwei(deposit_data.amount))
            .data(Bytes::from(encode_eth1_tx_data(&deposit_data).map_err(
                |e| format!("Failed to encode deposit data: {:?}", e),
            )?));

        let pending_tx = self
            .client
            .send_transaction(tx_request, None)
            .await
            .map_err(|e| format!("Failed to call deposit fn: {:?}", e))?;

        pending_tx
            .interval(Duration::from_millis(10))
            .confirmations(0)
            .await
            .map_err(|e| format!("Transaction failed to resolve: {:?}", e))?
            .ok_or_else(|| "Transaction dropped from mempool".to_string())?;
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
    client: Provider<Http>,
    confirmations: usize,
    bytecode: Vec<u8>,
    password_opt: Option<String>,
) -> Result<Address, String> {
    let from_address = client
        .get_accounts()
        .await
        .map_err(|e| format!("Failed to get accounts: {:?}", e))
        .and_then(|accounts| {
            accounts
                .get(DEPLOYER_ACCOUNTS_INDEX)
                .cloned()
                .ok_or_else(|| "Insufficient accounts for deployer".to_string())
        })?;

    let deploy_address = if let Some(password) = password_opt {
        let result = client
            .request(
                "personal_unlockAccount",
                vec![from_address.to_string(), password],
            )
            .await;

        match result {
            Ok(true) => from_address,
            Ok(false) => return Err("Eth1 node refused to unlock account".to_string()),
            Err(e) => return Err(format!("Eth1 unlock request failed: {:?}", e)),
        }
    } else {
        from_address
    };

    let mut bytecode = String::from_utf8(bytecode).unwrap();
    bytecode.retain(|c| c.is_ascii_hexdigit());
    let bytecode = hex::decode(&bytecode[1..]).unwrap();

    let deploy_tx: TypedTransaction = TransactionRequest::new()
        .from(deploy_address)
        .data(Bytes::from(bytecode))
        .gas(CONTRACT_DEPLOY_GAS)
        .into();

    let pending_tx = client
        .send_transaction(deploy_tx, None)
        .await
        .map_err(|e| format!("Failed to send tx: {:?}", e))?;

    let tx = pending_tx
        .interval(Duration::from_millis(500))
        .confirmations(confirmations)
        .await
        .map_err(|e| format!("Failed to fetch tx receipt: {:?}", e))?;
    tx.and_then(|tx| tx.contract_address)
        .ok_or_else(|| "Deposit contract not deployed successfully".to_string())
}
