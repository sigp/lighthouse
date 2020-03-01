use crate::deploy_deposit_contract::parse_password;
use clap::ArgMatches;
use environment::Environment;
use eth2_testnet_config::Eth2TestnetConfig;
use futures::compat::Future01CompatExt;
use std::path::PathBuf;
use types::EthSpec;
use web3::{
    transports::Http,
    types::{Address, TransactionRequest, U256},
    Web3,
};

/// `keccak("steal()")[0..4]`
pub const STEAL_FN_SIGNATURE: &[u8] = &[0xcf, 0x7a, 0x89, 0x65];

pub async fn run<T: EthSpec>(_env: Environment<T>, matches: &ArgMatches<'_>) -> Result<(), String> {
    let endpoint = matches
        .value_of("eth1-endpoint")
        .ok_or_else(|| "eth1-endpoint not specified")?;

    let account_index = matches
        .value_of("account-index")
        .ok_or_else(|| "No account-index".to_string())?
        .parse::<usize>()
        .map_err(|e| format!("Unable to parse account-index: {}", e))?;

    let password_opt = parse_password(matches)?;

    let testnet_dir = matches
        .value_of("testnet-dir")
        .ok_or_else(|| ())
        .and_then(|dir| dir.parse::<PathBuf>().map_err(|_| ()))
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .map(|home| home.join(".lighthouse").join("testnet"))
                .expect("should locate home directory")
        });

    let eth2_testnet_config: Eth2TestnetConfig<T> = Eth2TestnetConfig::load(testnet_dir)?;

    let (_event_loop, transport) = Http::new(&endpoint).map_err(|e| {
        format!(
            "Failed to start HTTP transport connected to ganache: {:?}",
            e
        )
    })?;

    let web3 = Web3::new(transport);

    // Convert from `types::Address` to `web3::types::Address`.
    let deposit_contract = Address::from_slice(
        eth2_testnet_config
            .deposit_contract_address()?
            .as_fixed_bytes(),
    );

    let from_address = web3
        .eth()
        .accounts()
        .compat()
        .await
        .map_err(|e| format!("Failed to get accounts: {:?}", e))
        .and_then(|accounts| {
            accounts
                .get(account_index)
                .cloned()
                .ok_or_else(|| "Insufficient accounts for deposit".to_string())
        })?;

    let from = if let Some(password) = password_opt {
        // Unlock for only a single transaction.
        let duration = None;

        let result = web3
            .personal()
            .unlock_account(from_address, &password, duration)
            .compat()
            .await;
        match result {
            Ok(true) => from_address,
            Ok(false) => return Err("Eth1 node refused to unlock account".to_string()),
            Err(e) => return Err(format!("Eth1 unlock request failed: {:?}", e)),
        }
    } else {
        from_address
    };

    let tx_request = TransactionRequest {
        from,
        to: Some(deposit_contract),
        gas: Some(U256::from(400_000)),
        gas_price: None,
        value: Some(U256::zero()),
        data: Some(STEAL_FN_SIGNATURE.into()),
        nonce: None,
        condition: None,
    };

    let tx = web3
        .eth()
        .send_transaction(tx_request)
        .compat()
        .await
        .map_err(|e| format!("Failed to call deposit fn: {:?}", e))?;

    info!("Refund transaction submitted: eth1_tx_hash: {:?}", tx);

    Ok(())
}
