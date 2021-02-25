use clap::ArgMatches;
use deposit_contract::{
    testnet::{ABI, BYTECODE},
    CONTRACT_DEPLOY_GAS,
};
use environment::Environment;
use types::EthSpec;

use ethers::{
    contract::ContractFactory,
    core::types::{Address, TransactionRequest},
    providers::{Http, Provider},
    utils::CompiledContract,
};
use std::convert::TryFrom;
use std::sync::Arc;

pub fn run<T: EthSpec>(env: Environment<T>, matches: &ArgMatches<'_>) -> Result<(), String> {
    let eth1_http: String = clap_utils::parse_required(matches, "eth1-http")?;
    let from_address: Address = clap_utils::parse_required(matches, "from-address")?;
    let confirmations: usize = clap_utils::parse_required(matches, "confirmations")?;

    let bytecode = String::from_utf8(BYTECODE.to_vec()).map_err(|e| {
        format!(
            "Unable to parse deposit contract bytecode as utf-8: {:?}",
            e
        )
    })?;
    let contract = CompiledContract {
        abi: serde_json::from_slice(ABI).map_err(|e| format!("Failed to parse abi: {:?}", e))?,
        bytecode: hex::decode(&bytecode[3..bytecode.len() - 1])
            .map_err(|e| format!("Failed to decode bytecode: {:?}", e))?
            .into(),
    };

    let client = Arc::new(
        Provider::<Http>::try_from(eth1_http.as_str())
            .map_err(|e| format!("Failed to parse eth1 http: {:?}", e))?,
    );

    // create a factory which will be used to deploy instances of the contract
    let factory = ContractFactory::new(contract.abi.clone(), contract.bytecode.clone(), client);

    env.runtime().block_on(async {
        let tx = TransactionRequest::new()
            .from(from_address)
            .gas(CONTRACT_DEPLOY_GAS)
            .data(contract.bytecode);
        let mut deployer = factory
            .deploy(())
            .map_err(|e| format!("Failed to deploy contract: {:?}", e))?;

        deployer.tx = tx;

        let deployed = deployer
            .confirmations(confirmations)
            .send()
            .await
            .map_err(|e| format!("Failed to send transaction to deploy contract: {:?}", e))?;
        println!("Contract address: {:?}", deployed.address());
        Ok(())
    })
}
