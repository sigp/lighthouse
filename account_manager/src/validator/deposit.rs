use crate::validator::eth1_utils::send_deposit_transactions;
use crate::{SECRETS_DIR_FLAG, VALIDATOR_DIR_FLAG};
use clap::{App, Arg, ArgMatches};
use directory::{parse_path_or_default_with_flag, DEFAULT_SECRET_DIR};
use environment::Environment;
use slog::info;
use std::path::PathBuf;
use types::EthSpec;
use validator_dir::Manager as ValidatorManager;
use web3::{transports::Http, transports::Ipc, types::Address};

pub const CMD: &str = "deposit";
pub const VALIDATOR_FLAG: &str = "validator";
pub const ETH1_IPC_FLAG: &str = "eth1-ipc";
pub const ETH1_HTTP_FLAG: &str = "eth1-http";
pub const FROM_ADDRESS_FLAG: &str = "from-address";
pub const CONFIRMATION_COUNT_FLAG: &str = "confirmation-count";
pub const CONFIRMATION_BATCH_SIZE_FLAG: &str = "confirmation-batch-size";
pub const TOPUP_FLAG: &str = "topup";
pub const TOPUP_AMOUNT: &str = "topup-amount";

const GWEI: u64 = 1_000_000_000;

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
        .arg(
            Arg::with_name(TOPUP_FLAG)
                .long(TOPUP_FLAG)
                .value_name("TOPUP-FLAG")
                .help("Topup existing validator")
                .takes_value(false)
                .requires(TOPUP_AMOUNT),
        )
        .arg(
            Arg::with_name(TOPUP_AMOUNT)
                .long(TOPUP_AMOUNT)
                .value_name("TOPUP-AMOUNT")
                .help("Amount that you want to topup the given validator with in GWEI")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(SECRETS_DIR_FLAG)
                .long(SECRETS_DIR_FLAG)
                .value_name("SECRETS_DIR")
                .help(
                    "The path where the validator keystore passwords will be stored. \
                    Defaults to ~/.lighthouse/{testnet}/secrets",
                )
                .conflicts_with("datadir")
                .takes_value(true),
        )
}

pub fn cli_run<T: EthSpec>(
    matches: &ArgMatches<'_>,
    mut env: Environment<T>,
    validator_dir: PathBuf,
) -> Result<(), String> {
    let log = env.core_context().log().clone();

    let validator: String = clap_utils::parse_required(matches, VALIDATOR_FLAG)?;
    let eth1_ipc_path: Option<PathBuf> = clap_utils::parse_optional(matches, ETH1_IPC_FLAG)?;
    let eth1_http_url: Option<String> = clap_utils::parse_optional(matches, ETH1_HTTP_FLAG)?;
    let from_address: Address = clap_utils::parse_required(matches, FROM_ADDRESS_FLAG)?;
    let confirmation_count: usize = clap_utils::parse_required(matches, CONFIRMATION_COUNT_FLAG)?;
    let confirmation_batch_size: usize =
        clap_utils::parse_required(matches, CONFIRMATION_BATCH_SIZE_FLAG)?;

    let manager = ValidatorManager::open(&validator_dir)
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

    let is_topup = matches.is_present(TOPUP_FLAG);
    let secrets_dir = if matches.value_of("datadir").is_some() {
        let path: PathBuf = clap_utils::parse_required(matches, "datadir")?;
        path.join(DEFAULT_SECRET_DIR)
    } else {
        parse_path_or_default_with_flag(matches, SECRETS_DIR_FLAG, DEFAULT_SECRET_DIR)?
    };

    let eth1_deposit_datas = validators
        .into_iter()
        .filter(|v| is_topup || !v.eth1_deposit_tx_hash_exists())
        .map(|v| {
            if is_topup {
                let topup_amount: u64 = clap_utils::parse_required(matches, TOPUP_AMOUNT)?;
                let voting_keypair = v
                    .voting_keypair(&secrets_dir)
                    .map_err(|e| format!("Failed to load voting keypair: {:?}", e))?;
                let withdrawal_keypair = v
                    .withdrawal_keypair(&secrets_dir)
                    .map_err(|e| format!("Failed to load withdrawal keypair: {:?}", e))?;

                match v.eth1_deposit_data_topup(
                    topup_amount,
                    &voting_keypair,
                    &withdrawal_keypair,
                    &T::default_spec(),
                ) {
                    Ok(data) => Ok((v, data)),
                    Err(e) => Err(format!(
                        "Failed to create topup deposit data for {:?}: {:?}",
                        v.dir(),
                        e
                    )),
                }
            } else {
                match v.eth1_deposit_data() {
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
                }
            }
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
        "total_eth" => total_gwei as f64 / GWEI as f64,
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
