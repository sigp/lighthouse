use clap::ArgMatches;
use environment::Environment;
use futures::Future;
use std::path::PathBuf;
use types::EthSpec;
use web3::{
    transports::Ipc,
    types::{Address, TransactionRequest, U256},
    Web3,
};

/// `keccak("steal()")[0..4]`
pub const STEAL_FN_SIGNATURE: &[u8] = &[0xcf, 0x7a, 0x89, 0x65];

pub fn run<T: EthSpec>(mut env: Environment<T>, matches: &ArgMatches) -> Result<(), String> {
    let eth1_ipc_path: PathBuf = clap_utils::parse_required(matches, "eth1-ipc")?;
    let from: Address = clap_utils::parse_required(matches, "from-address")?;
    let contract_address: Address = clap_utils::parse_required(matches, "contract-address")?;

    let (_event_loop_handle, transport) =
        Ipc::new(eth1_ipc_path).map_err(|e| format!("Unable to connect to eth1 IPC: {:?}", e))?;
    let web3 = Web3::new(transport);

    env.runtime().block_on(
        web3.eth()
            .send_transaction(TransactionRequest {
                from,
                to: Some(contract_address),
                gas: Some(U256::from(400_000)),
                gas_price: None,
                value: Some(U256::zero()),
                data: Some(STEAL_FN_SIGNATURE.into()),
                nonce: None,
                condition: None,
            })
            .map_err(|e| format!("Failed to call deposit fn: {:?}", e)),
    )?;

    Ok(())
}
