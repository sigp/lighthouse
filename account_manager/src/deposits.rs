use clap::{App, Arg, ArgMatches};
use clap_utils;
use environment::Environment;
use futures::compat::Future01CompatExt;
use slog::{info, Logger};
use std::fs;
use std::path::PathBuf;
use tokio::time::{delay_until, Duration, Instant};
use types::EthSpec;
use validator_client::validator_directory::ValidatorDirectoryBuilder;
use web3::{
    transports::Ipc,
    types::{Address, SyncInfo, SyncState},
    Transport, Web3,
};

const SYNCING_STATE_RETRY_DELAY: Duration = Duration::from_secs(2);

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("deposited")
        .about("Creates new Lighthouse validator keys and directories. Each newly-created validator
        will have a deposit transaction formed and submitted to the deposit contract via
        --eth1-ipc. This application will only write each validator keys to disk if the deposit
        transaction returns successfully from the eth1 node. The process exits immediately if any
        Eth1 tx fails. Does not wait for Eth1 confirmation blocks, so there is no guarantee that a
        deposit will be accepted in the Eth1 chain. Before key generation starts, this application
        will wait until the eth1 indicates that it is not syncing via the eth_syncing endpoint")
        .arg(
            Arg::with_name("validator-dir")
                .long("validator-dir")
                .value_name("VALIDATOR_DIRECTORY")
                .help("The path where the validator directories will be created. Defaults to ~/.lighthouse/validators")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("eth1-ipc")
                .long("eth1-ipc")
                .value_name("ETH1_IPC_PATH")
                .help("Path to an Eth1 JSON-RPC IPC endpoint")
                .takes_value(true)
                .required(true)
        )
        .arg(
            Arg::with_name("from-address")
                .long("from-address")
                .value_name("FROM_ETH1_ADDRESS")
                .help("The address that will submit the eth1 deposit. Must be unlocked on the node
                    at --eth1-ipc.")
                .takes_value(true)
                .required(true)
        )
        .arg(
            Arg::with_name("deposit-gwei")
                .long("deposit-gwei")
                .value_name("DEPOSIT_GWEI")
                .help("The GWEI value of the deposit amount. Defaults to the minimum amount
                    required for an active validator (MAX_EFFECTIVE_BALANCE.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("count")
                .long("count")
                .value_name("DEPOSIT_COUNT")
                .help("The number of deposits to create, regardless of how many already exist")
                .conflicts_with("limit")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("at-most")
                .long("at-most")
                .value_name("VALIDATOR_COUNT")
                .help("Observe the number of validators in --validator-dir, only creating enough to
                ensure reach the given count. Never deletes an existing validator.")
                .conflicts_with("count")
                .takes_value(true),
        )
}

pub fn cli_run<T: EthSpec>(
    matches: &ArgMatches<'_>,
    mut env: Environment<T>,
) -> Result<(), String> {
    let spec = env.core_context().eth2_config.spec;
    let log = env.core_context().log;

    let validator_dir = clap_utils::parse_path_with_default_in_home_dir(
        matches,
        "validator_dir",
        PathBuf::new().join(".lighthouse").join("validators"),
    )?;
    let eth1_ipc_path: PathBuf = clap_utils::parse_required(matches, "eth1-ipc")?;
    let from_address: Address = clap_utils::parse_required(matches, "from-address")?;
    let deposit_gwei = clap_utils::parse_optional(matches, "deposit-gwei")?
        .unwrap_or_else(|| spec.max_effective_balance);
    let count: Option<usize> = clap_utils::parse_optional(matches, "count")?;
    let at_most: Option<usize> = clap_utils::parse_optional(matches, "at-most")?;

    let starting_validator_count = existing_validator_count(&validator_dir)?;

    let n = match (count, at_most) {
        (Some(_), Some(_)) => Err("Cannot supply --count and --at-most".to_string()),
        (None, None) => Err("Must supply either --count or --at-most".to_string()),
        (Some(count), None) => Ok(count),
        (None, Some(at_most)) => Ok(at_most.saturating_sub(starting_validator_count)),
    }?;

    if n == 0 {
        info!(
            log,
            "No need to produce and validators, exiting";
            "--count" => count,
            "--at-most" => at_most,
            "existing_validators" => starting_validator_count,
        );
        return Ok(());
    }

    let deposit_contract = env
        .testnet
        .as_ref()
        .ok_or_else(|| "Unable to run account manager without a testnet dir".to_string())?
        .deposit_contract_address()
        .map_err(|e| format!("Unable to parse deposit contract address: {}", e))?;

    if deposit_contract == Address::zero() {
        return Err("Refusing to deposit to the zero address. Check testnet configuration.".into());
    }

    let (_event_loop_handle, transport) =
        Ipc::new(eth1_ipc_path).map_err(|e| format!("Unable to connect to eth1 IPC: {:?}", e))?;
    let web3 = Web3::new(transport);

    env.runtime()
        .block_on(poll_until_synced(web3.clone(), log.clone()))?;

    for i in 0..n {
        let tx_hash_log = log.clone();

        env.runtime()
            .block_on(async {
                ValidatorDirectoryBuilder::default()
                    .spec(spec.clone())
                    .custom_deposit_amount(deposit_gwei)
                    .thread_random_keypairs()
                    .submit_eth1_deposit(web3.clone(), from_address, deposit_contract)
                    .await
                    .map(move |(builder, tx_hash)| {
                        info!(
                            tx_hash_log,
                            "Validator deposited";
                            "eth1_tx_hash" => format!("{:?}", tx_hash),
                            "index" => format!("{}/{}", i + 1, n),
                        );
                        builder
                    })
            })?
            .create_directory(validator_dir.clone())?
            .write_keypair_files()?
            .write_eth1_data_file()?
            .build()?;
    }

    let ending_validator_count = existing_validator_count(&validator_dir)?;
    let delta = ending_validator_count.saturating_sub(starting_validator_count);

    info!(
        log,
        "Success";
        "validators_created_and_deposited" => delta,
    );

    Ok(())
}

/// Returns the number of validators that exist in the given `validator_dir`.
///
/// This function just assumes any file is a validator directory, making it likely to return a
/// higher number than accurate but never a lower one.
fn existing_validator_count(validator_dir: &PathBuf) -> Result<usize, String> {
    fs::read_dir(&validator_dir)
        .map(|iter| iter.count())
        .map_err(|e| format!("Unable to read {:?}: {}", validator_dir, e))
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
