use clap::ArgMatches;
use clap_utils;
use deposit_contract::{
    testnet::{ABI, BYTECODE},
    CONTRACT_DEPLOY_GAS,
};
use environment::Environment;
use futures::{Future, IntoFuture};
use std::path::PathBuf;
use types::EthSpec;
use web3::{
    contract::{Contract, Options},
    transports::Ipc,
    types::{Address, U256},
    Web3,
};

pub fn run<T: EthSpec>(mut env: Environment<T>, matches: &ArgMatches) -> Result<(), String> {
    let eth1_ipc_path: PathBuf = clap_utils::parse_required(matches, "eth1-ipc")?;
    let from_address: Address = clap_utils::parse_required(matches, "from-address")?;
    let confirmations: usize = clap_utils::parse_required(matches, "confirmations")?;

    let (_event_loop_handle, transport) =
        Ipc::new(eth1_ipc_path).map_err(|e| format!("Unable to connect to eth1 IPC: {:?}", e))?;
    let web3 = Web3::new(transport);

    let bytecode = String::from_utf8(BYTECODE.to_vec()).map_err(|e| {
        format!(
            "Unable to parse deposit contract bytecode as utf-8: {:?}",
            e
        )
    })?;

    // It's unlikely that this will be the _actual_ deployment block, however it'll be close
    // enough to serve our purposes.
    //
    // We only need the deposit block to put a lower bound on the block number we need to search
    // for deposit logs.
    let deploy_block = env
        .runtime()
        .block_on(web3.eth().block_number())
        .map_err(|e| format!("Failed to get block number: {}", e))?;

    let address = env.runtime().block_on(
        Contract::deploy(web3.eth(), &ABI)
            .map_err(|e| format!("Unable to build contract deployer: {:?}", e))?
            .confirmations(confirmations)
            .options(Options {
                gas: Some(U256::from(CONTRACT_DEPLOY_GAS)),
                ..Options::default()
            })
            .execute(bytecode, (), from_address)
            .into_future()
            .map_err(|e| format!("Unable to execute deployment: {:?}", e))
            .and_then(|pending| {
                pending.map_err(|e| format!("Unable to await pending contract: {:?}", e))
            })
            .map(|tx_receipt| tx_receipt.address())
            .map_err(|e| format!("Failed to execute deployment: {:?}", e)),
    )?;

    println!("deposit_contract_address: {:?}", address);
    println!("deposit_contract_deploy_block: {}", deploy_block);

    Ok(())
}
