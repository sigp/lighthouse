use crate::VALIDATOR_DIR_FLAG;
use clap::{App, Arg, ArgMatches};
use deposit_contract::DEPOSIT_GAS;
use environment::Environment;
use futures::{
    compat::Future01CompatExt,
    stream::{FuturesUnordered, StreamExt},
};
use slog::{info, Logger};
use state_processing::per_block_processing::verify_deposit_signature;
use std::path::PathBuf;
use tokio::time::{delay_until, Duration, Instant};
use types::EthSpec;
use validator_dir::{Eth1DepositData, Manager as ValidatorManager, ValidatorDir};
use web3::{
    transports::Http,
    transports::Ipc,
    types::{Address, SyncInfo, SyncState, TransactionRequest, U256},
    Transport, Web3,
};

pub const CMD: &str = "deposit";
pub const VALIDATOR_FLAG: &str = "validator";
pub const ETH1_IPC_FLAG: &str = "eth1-ipc";
pub const ETH1_HTTP_FLAG: &str = "eth1-http";
pub const FROM_ADDRESS_FLAG: &str = "from-address";
pub const CONFIRMATION_COUNT_FLAG: &str = "confirmation-count";
pub const CONFIRMATION_BATCH_SIZE_FLAG: &str = "confirmation-batch-size";

const GWEI: u64 = 1_000_000_000;

const SYNCING_STATE_RETRY_DELAY: Duration = Duration::from_secs(2);

const CONFIRMATIONS_POLL_TIME: Duration = Duration::from_secs(2);

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("deposit")
        .about(
            "Submits a deposit to an Eth1 validator registration contract via an IPC endpoint \
            of an Eth1 client (e.g., Geth, OpenEthereum, etc.). The validators must already \
            have been created and exist on the file-system. The process will exit immediately \
            with an error if any error occurs. After each deposit is submitted to the Eth1 \
            node, a file will be saved in the validator directory with the transaction hash. \
            If confirmations are set to non-zero then the application will wait for confirmations \
            before saving the transaction hash and moving onto the next batch of deposits. \
            The deposit contract address will be determined by the --testnet-dir flag on the \
            primary Lighthouse binary.",
        )
        .arg(
            Arg::with_name(VALIDATOR_DIR_FLAG)
                .long(VALIDATOR_DIR_FLAG)
                .value_name("VALIDATOR_DIRECTORY")
                .help(
                    "The path to the validator client data directory. \
                    Defaults to ~/.lighthouse/validators",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name(VALIDATOR_FLAG)
                .long(VALIDATOR_FLAG)
                .value_name("VALIDATOR_NAME")
                .help(
                    "The name of the directory in --data-dir for which to deposit. \
                    Set to 'all' to deposit all validators in the --data-dir.",
                )
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name(ETH1_IPC_FLAG)
                .long(ETH1_IPC_FLAG)
                .value_name("ETH1_IPC_PATH")
                .help("Path to an Eth1 JSON-RPC IPC endpoint")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name(ETH1_HTTP_FLAG)
                .long(ETH1_HTTP_FLAG)
                .value_name("ETH1_HTTP_URL")
                .help("URL to an Eth1 JSON-RPC endpoint")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name(FROM_ADDRESS_FLAG)
                .long(FROM_ADDRESS_FLAG)
                .value_name("FROM_ETH1_ADDRESS")
                .help(
                    "The address that will submit the eth1 deposit. \
                    Must be unlocked on the node at --eth1-ipc.",
                )
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name(CONFIRMATION_COUNT_FLAG)
                .long(CONFIRMATION_COUNT_FLAG)
                .value_name("CONFIRMATION_COUNT")
                .help(
                    "The number of Eth1 block confirmations required \
                    before a transaction is considered complete. Set to \
                    0 for no confirmations.",
                )
                .takes_value(true)
                .default_value("1"),
        )
        .arg(
            Arg::with_name(CONFIRMATION_BATCH_SIZE_FLAG)
                .long(CONFIRMATION_BATCH_SIZE_FLAG)
                .value_name("BATCH_SIZE")
                .help(
                    "Perform BATCH_SIZE deposits and wait for confirmations \
                    in parallel. Useful for achieving faster bulk deposits.",
                )
                .takes_value(true)
                .default_value("10"),
        )
}

#[allow(clippy::too_many_arguments)]
fn send_deposit_transactions<T1, T2: 'static>(
    mut env: Environment<T1>,
    log: Logger,
    mut eth1_deposit_datas: Vec<(ValidatorDir, Eth1DepositData)>,
    from_address: Address,
    deposit_contract: Address,
    transport: T2,
    confirmation_count: usize,
    confirmation_batch_size: usize,
) -> Result<(), String>
where
    T1: EthSpec,
    T2: Transport + std::marker::Send,
    <T2 as web3::Transport>::Out: std::marker::Send,
{
    let web3 = Web3::new(transport);
    let spec = env.eth2_config.spec.clone();

    let deposits_fut = async {
        poll_until_synced(web3.clone(), log.clone()).await?;

        for chunk in eth1_deposit_datas.chunks_mut(confirmation_batch_size) {
            let futures = FuturesUnordered::default();

            for (ref mut validator_dir, eth1_deposit_data) in chunk.iter_mut() {
                verify_deposit_signature(&eth1_deposit_data.deposit_data, &spec).map_err(|e| {
                    format!(
                        "Deposit for {:?} fails verification, \
                         are you using the correct testnet configuration?\nError: {:?}",
                        eth1_deposit_data.deposit_data.pubkey, e
                    )
                })?;

                let web3 = web3.clone();
                let log = log.clone();
                futures.push(async move {
                    let tx_hash = web3
                        .send_transaction_with_confirmation(
                            TransactionRequest {
                                from: from_address,
                                to: Some(deposit_contract),
                                gas: Some(DEPOSIT_GAS.into()),
                                gas_price: None,
                                value: Some(from_gwei(eth1_deposit_data.deposit_data.amount)),
                                data: Some(eth1_deposit_data.rlp.clone().into()),
                                nonce: None,
                                condition: None,
                            },
                            CONFIRMATIONS_POLL_TIME,
                            confirmation_count,
                        )
                        .compat()
                        .await
                        .map_err(|e| format!("Failed to send transaction: {:?}", e))?;

                    info!(
                        log,
                        "Submitted deposit";
                        "tx_hash" => format!("{:?}", tx_hash),
                    );

                    validator_dir
                        .save_eth1_deposit_tx_hash(&format!("{:?}", tx_hash))
                        .map_err(|e| {
                            format!("Failed to save tx hash {:?} to disk: {:?}", tx_hash, e)
                        })?;

                    Ok::<(), String>(())
                });
            }

            futures
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .collect::<Result<_, _>>()?;
        }

        Ok::<(), String>(())
    };

    env.runtime().block_on(deposits_fut)?;

    Ok(())
}

pub fn cli_run<T: EthSpec>(
    matches: &ArgMatches<'_>,
    mut env: Environment<T>,
) -> Result<(), String> {
    let log = env.core_context().log().clone();

    let data_dir = clap_utils::parse_path_with_default_in_home_dir(
        matches,
        VALIDATOR_DIR_FLAG,
        PathBuf::new().join(".lighthouse").join("validators"),
    )?;
    let validator: String = clap_utils::parse_required(matches, VALIDATOR_FLAG)?;
    let eth1_ipc_path: Option<PathBuf> = clap_utils::parse_optional(matches, ETH1_IPC_FLAG)?;
    let eth1_http_url: Option<String> = clap_utils::parse_optional(matches, ETH1_HTTP_FLAG)?;
    let from_address: Address = clap_utils::parse_required(matches, FROM_ADDRESS_FLAG)?;
    let confirmation_count: usize = clap_utils::parse_required(matches, CONFIRMATION_COUNT_FLAG)?;
    let confirmation_batch_size: usize =
        clap_utils::parse_required(matches, CONFIRMATION_BATCH_SIZE_FLAG)?;

    let manager = ValidatorManager::open(&data_dir)
        .map_err(|e| format!("Unable to read --{}: {:?}", VALIDATOR_DIR_FLAG, e))?;

    let validators = match validator.as_ref() {
        "all" => manager
            .open_all_validators()
            .map_err(|e| format!("Unable to read all validators: {:?}", e)),
        name => {
            let path = manager
                .directory_names()
                .map_err(|e| {
                    format!(
                        "Unable to read --{} directory names: {:?}",
                        VALIDATOR_DIR_FLAG, e
                    )
                })?
                .get(name)
                .ok_or_else(|| format!("Unknown validator:  {}", name))?
                .clone();

            manager
                .open_validator(&path)
                .map_err(|e| format!("Unable to open {}: {:?}", name, e))
                .map(|v| vec![v])
        }
    }?;

    let eth1_deposit_datas = validators
        .into_iter()
        .filter(|v| !v.eth1_deposit_tx_hash_exists())
        .map(|v| match v.eth1_deposit_data() {
            Ok(Some(data)) => Ok((v, data)),
            Ok(None) => Err(format!(
                "Validator is missing deposit data file: {:?}",
                v.dir()
            )),
            Err(e) => Err(format!(
                "Unable to read deposit data for {:?}: {:?}",
                v.dir(),
                e
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;

    let total_gwei: u64 = eth1_deposit_datas
        .iter()
        .map(|(_, d)| d.deposit_data.amount)
        .sum();

    if eth1_deposit_datas.is_empty() {
        info!(log, "No validators to deposit");

        return Ok(());
    }

    info!(
        log,
        "Starting deposits";
        "deposit_count" => eth1_deposit_datas.len(),
        "total_eth" => total_gwei / GWEI,
    );

    let deposit_contract = env
        .testnet
        .as_ref()
        .ok_or_else(|| "Unable to run account manager without a testnet dir".to_string())?
        .deposit_contract_address()
        .map_err(|e| format!("Unable to parse deposit contract address: {}", e))?;

    if deposit_contract == Address::zero() {
        return Err("Refusing to deposit to the zero address. Check testnet configuration.".into());
    }

    match (eth1_ipc_path, eth1_http_url) {
        (Some(_), Some(_)) => Err(format!(
            "error: Cannot supply both --{} and --{}",
            ETH1_IPC_FLAG, ETH1_HTTP_FLAG
        )),
        (None, None) => Err(format!(
            "error: Must supply one of --{} or --{}",
            ETH1_IPC_FLAG, ETH1_HTTP_FLAG
        )),
        (Some(ipc_path), None) => {
            let (_event_loop_handle, ipc_transport) = Ipc::new(ipc_path)
                .map_err(|e| format!("Unable to connect to eth1 IPC: {:?}", e))?;
            send_deposit_transactions(
                env,
                log,
                eth1_deposit_datas,
                from_address,
                deposit_contract,
                ipc_transport,
                confirmation_count,
                confirmation_batch_size,
            )
        }
        (None, Some(http_url)) => {
            let (_event_loop_handle, http_transport) = Http::new(http_url.as_str())
                .map_err(|e| format!("Unable to connect to eth1 http RPC: {:?}", e))?;
            send_deposit_transactions(
                env,
                log,
                eth1_deposit_datas,
                from_address,
                deposit_contract,
                http_transport,
                confirmation_count,
                confirmation_batch_size,
            )
        }
    }
}

/// Converts gwei to wei.
fn from_gwei(gwei: u64) -> U256 {
    U256::from(gwei) * U256::exp10(9)
}

/// Run a poll on the `eth_syncing` endpoint, blocking until the node is synced.
async fn poll_until_synced<T>(web3: Web3<T>, log: Logger) -> Result<(), String>
where
    T: Transport + Send + 'static,
    <T as Transport>::Out: Send,
{
    loop {
        let sync_state = web3
            .clone()
            .eth()
            .syncing()
            .compat()
            .await
            .map_err(|e| format!("Unable to read syncing state from eth1 node: {:?}", e))?;

        match sync_state {
            SyncState::Syncing(SyncInfo {
                current_block,
                highest_block,
                ..
            }) => {
                info!(
                    log,
                    "Waiting for eth1 node to sync";
                    "est_highest_block" => format!("{}", highest_block),
                    "current_block" => format!("{}", current_block),
                );

                delay_until(Instant::now() + SYNCING_STATE_RETRY_DELAY).await;
            }
            SyncState::NotSyncing => {
                let block_number = web3
                    .clone()
                    .eth()
                    .block_number()
                    .compat()
                    .await
                    .map_err(|e| format!("Unable to read block number from eth1 node: {:?}", e))?;

                if block_number > 0.into() {
                    info!(
                        log,
                        "Eth1 node is synced";
                        "head_block" => format!("{}", block_number),
                    );
                    break;
                } else {
                    delay_until(Instant::now() + SYNCING_STATE_RETRY_DELAY).await;
                    info!(
                        log,
                        "Waiting for eth1 node to sync";
                        "current_block" => 0,
                    );
                }
            }
        }
    }

    Ok(())
}
