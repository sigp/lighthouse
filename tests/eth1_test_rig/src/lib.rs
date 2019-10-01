use futures::Future;
use std::sync::Arc;
use web3::contract::{Contract, Options};
use web3::transports::{EventLoopHandle, Http};
use web3::types::{Address, U256};
use web3::{Transport, Web3};

const DEPLOYER_ACCOUNTS_INDEX: usize = 1;

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

        let deposit_contract_address = tokio::runtime::Runtime::new()
            .map_err(|e| format!("Failed to start tokio runtime: {}", e))?
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

    /// The deposit contract's address.
    pub fn address(&self) -> String {
        self.contract.address().to_string()
    }
}

fn deploy_deposit_contract<T: Transport>(
    web3: Web3<T>,
) -> impl Future<Item = Address, Error = String> {
    let bytecode = String::from_utf8_lossy(&BYTECODE);

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
                .confirmations(0)
                .options(Options {
                    gas: Some(U256::from(1_000_000_000)),
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
}
