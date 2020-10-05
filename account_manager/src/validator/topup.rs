use crate::validator::eth1_utils::send_deposit_transactions;
use crate::wallet::create::STDIN_INPUTS_FLAG;
use crate::{SECRETS_DIR_FLAG, VALIDATOR_DIR_FLAG};
use bls::{Keypair, PublicKey};
use clap::{App, Arg, ArgMatches};
use directory::{parse_path_or_default_with_flag, DEFAULT_SECRET_DIR};
use environment::Environment;
use eth2::reqwest::Url;
use eth2::{
    types::{StateId, ValidatorData, ValidatorId, ValidatorStatus::*},
    BeaconNodeHttpClient,
};
use slog::info;
use std::path::PathBuf;
use types::{ChainSpec, EthSpec, Hash256};
use validator_dir::Manager as ValidatorManager;
use validator_dir::{Eth1DepositData, ValidatorDir};
use web3::{transports::Http, transports::Ipc, types::Address};

pub const CMD: &str = "topup";
pub const PASSWORD_PROMPT: &str = "Enter the keystore password: ";
pub const VALIDATOR_FLAG: &str = "validator";
pub const ETH1_IPC_FLAG: &str = "eth1-ipc";
pub const ETH1_HTTP_FLAG: &str = "eth1-http";
pub const FROM_ADDRESS_FLAG: &str = "from-address";
pub const CONFIRMATION_COUNT_FLAG: &str = "confirmation-count";
pub const CONFIRMATION_BATCH_SIZE_FLAG: &str = "confirmation-batch-size";
pub const TOPUP_AMOUNT: &str = "topup-amount";
pub const BEACON_SERVER: &str = "beacon-node";
pub const DEFAULT_BEACON_NODE: &str = "http://localhost:5052/";

const GWEI: u64 = 1_000_000_000;

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("topup")
        .about(
            "Submits a deposit to topup an existing validator's balance to an Eth1 validator registration contract via an \
            IPC/HTTP endpoint of an Eth1 client (e.g., Geth, OpenEthereum, etc.). The validators must already have \
            been created, exist on the file-system and must have a valid deposit on the beacon chain. \
            The process will exit immediately with an error if any error occurs. If confirmations are set to non-zero \
            then the application will wait for confirmations before moving onto the next batch of deposits. The deposit \
            contract address will be determined by the --testnet-dir flag on the primary Lighthouse binary.",
        )
        .arg(
            Arg::with_name(VALIDATOR_FLAG)
                .long(VALIDATOR_FLAG)
                .value_name("VALIDATOR_NAME")
                .help(
                    "The name of the directory in --data-dir for which to topup. \
                    Set to 'all' to topup all validators in the --data-dir.",
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
                    "The address that will submit the eth1 topup deposit. \
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
            Arg::with_name(TOPUP_AMOUNT)
                .long(TOPUP_AMOUNT)
                .value_name("TOPUP-AMOUNT")
                .help(
                    "Amount that you want to topup the given validator with in ETH.\
                    Minimum value is `MIN_DEPOSIT_AMOUNT` in the spec",
                )
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name(BEACON_SERVER)
                .long(BEACON_SERVER)
                .value_name("NETWORK_ADDRESS")
                .help("Address to a beacon node HTTP API. Default value is http://localhost:5052/")
                .default_value(&DEFAULT_BEACON_NODE)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(STDIN_INPUTS_FLAG)
                .long(STDIN_INPUTS_FLAG)
                .help("If present, read all user inputs from stdin instead of tty."),
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
    let stdin_inputs = matches.is_present(STDIN_INPUTS_FLAG);

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

    let secrets_dir = if matches.value_of("datadir").is_some() {
        let path: PathBuf = clap_utils::parse_required(matches, "datadir")?;
        path.join(DEFAULT_SECRET_DIR)
    } else {
        parse_path_or_default_with_flag(matches, SECRETS_DIR_FLAG, DEFAULT_SECRET_DIR)?
    };

    let server_url: String = clap_utils::parse_required(matches, BEACON_SERVER)?;
    let client = BeaconNodeHttpClient::new(
        Url::parse(&server_url)
            .map_err(|e| format!("Failed to parse beacon http server: {:?}", e))?,
    );
    let topup_amount: u64 = clap_utils::parse_required(matches, TOPUP_AMOUNT)?;
    let topup_amount_gwei = topup_amount * GWEI;
    let spec = env.core_context().eth2_config.spec;

    let eth1_deposit_datas = env.runtime().block_on(generate_deposit_datas(
        validators
            .into_iter()
            .map(|v| {
                let voting_keypair = load_voting_keypair(&v, &secrets_dir, stdin_inputs)?;
                Ok((v, voting_keypair))
            })
            .collect::<Result<Vec<_>, String>>()?,
        topup_amount_gwei,
        &client,
        &spec,
        stdin_inputs,
    ))?;

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
                false,
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
                false,
            )
        }
    }
}

/// Generate deposit data for a list of validators.
async fn generate_deposit_datas(
    data: Vec<(ValidatorDir, Keypair)>,
    amount: u64,
    client: &BeaconNodeHttpClient,
    spec: &ChainSpec,
    stdin_inputs: bool,
) -> Result<Vec<(ValidatorDir, Eth1DepositData)>, String> {
    let mut res = vec![];
    for d in data {
        // Return an error if any of the deposit data generation returns an error
        if let Some(deposit_data) =
            generate_deposit_data(d.0, &d.1, amount, client, spec, stdin_inputs).await?
        {
            res.push(deposit_data);
        }
    }
    Ok(res)
}

/// Generate deposit data for a single validator.
async fn generate_deposit_data(
    dir: ValidatorDir,
    voting_keypair: &Keypair,
    amount: u64,
    client: &BeaconNodeHttpClient,
    spec: &ChainSpec,
    stdin_inputs: bool,
) -> Result<Option<(ValidatorDir, Eth1DepositData)>, String> {
    let withdrawal_credentials = get_withdrawal_credentials(&voting_keypair.pk, &client).await?;
    eprintln!(
        "Withdrawal credentials for validator pubkey {} is {:?}",
        voting_keypair.pk, withdrawal_credentials
    );
    eprintln!("Please verify the withdrawal credentials. Enter (y/Y) to continue or anything else to abort: ");
    let confirmation = account_utils::read_input_from_user(stdin_inputs)?;
    if confirmation == "y" || confirmation == "Y" {
        match ValidatorDir::eth1_deposit_data_topup(
            amount,
            &voting_keypair,
            withdrawal_credentials,
            spec,
        ) {
            Ok(data) => Ok(Some((dir, data))),
            Err(e) => Err(format!(
                "Unable to generate deposit data for validator topup {:?}: {:?}",
                dir.dir(),
                e
            )),
        }
    } else {
        Ok(None)
    }
}

/// Get the withdrawal credentials for the given `validator_pubkey`
pub async fn get_withdrawal_credentials(
    validator_pubkey: &PublicKey,
    client: &BeaconNodeHttpClient,
) -> Result<Hash256, String> {
    let response: ValidatorData = client
        .get_beacon_states_validator_id(
            StateId::Head,
            &ValidatorId::PublicKey(validator_pubkey.into()),
        )
        .await
        .map_err(|e| format!("Failed to get validator details: {:?}", e))?
        .ok_or_else(|| {
            format!(
                "Validator {} is not present in the beacon state. Please ensure that your beacon node is synced",
                validator_pubkey
            )
        })?
        .data;

    match response.status {
        // TODO(pawan): check that this is true. May need to add more valid states.
        // Note: we return withdrawal credentials only in cases where topping up the balance will
        // have some useful effect. Topping up the validator balance after the validator has exited/withdrawn
        // is waste of money.
        WaitingForEligibility
        | WaitingForFinality
        | WaitingInQueue
        | StandbyForActive(_)
        | Active
        | ActiveAwaitingVoluntaryExit(_)
        | ActiveAwaitingSlashedExit(_) => Ok(response.validator.withdrawal_credentials),
        status => Err(format!(
            "Topping this validator is of no use. Status: {:?}",
            status
        )),
    }
}

/// Load the voting keypair by loading the keystore and decrypting the keystore
///
/// First attempt to load the password for the validator from the `secrets_dir`, if not
/// present, prompt user for the password.
fn load_voting_keypair(
    validator_dir: &ValidatorDir,
    secrets_dir: &PathBuf,
    stdin_inputs: bool,
) -> Result<Keypair, String> {
    let mut voting_keystore_path: Option<PathBuf> = None;
    read_voting_keystore_path(validator_dir.dir(), &mut voting_keystore_path).map_err(|e| {
        format!(
            "Failed to find a valid keystore file in validator_dir {:?}: {:?}",
            validator_dir.dir(),
            e
        )
    })?;

    let voting_keystore_path = voting_keystore_path.ok_or_else(|| {
        format!(
            "Failed to find a valid keystore file in validator_dir {:?}",
            validator_dir.dir(),
        )
    })?;
    match validator_dir::unlock_keypair(&voting_keystore_path, &secrets_dir) {
        Ok(keypair) => Ok(keypair),
        Err(validator_dir::Error::UnableToReadPassword(_)) => {
            let keystore =
                eth2_keystore::Keystore::from_json_file(&voting_keystore_path).map_err(|e| {
                    format!(
                        "Unable to read keystore JSON {:?}: {:?}",
                        voting_keystore_path, e
                    )
                })?;

            // There is no password file for the given validator, prompt password from user.
            eprintln!("");
            eprintln!(
                "{} for validator in {:?}",
                PASSWORD_PROMPT,
                validator_dir.dir()
            );
            let password = account_utils::read_password_from_user(stdin_inputs)?;
            match keystore.decrypt_keypair(password.as_ref()) {
                Ok(keypair) => {
                    eprintln!("Password is correct.");
                    eprintln!("");
                    std::thread::sleep(std::time::Duration::from_secs(1)); // Provides nicer UX.
                    Ok(keypair)
                }
                Err(eth2_keystore::Error::InvalidPassword) => Err("Invalid password".to_string()),
                Err(e) => Err(format!("Error while decrypting keypair: {:?}", e)),
            }
        }
        Err(e) => Err(format!(
            "Failed to load voting keypair for {:?}: {:?}",
            validator_dir.dir(),
            e
        )),
    }
}

/// Reads a `validator_dir` and returns the first valid keystore path found in the directory.
fn read_voting_keystore_path(
    path: &PathBuf,
    voting_keystore_path: &mut Option<PathBuf>,
) -> Result<(), std::io::Error> {
    std::fs::read_dir(path)?.try_for_each(|dir_entry| {
        let dir_entry = dir_entry?;
        let file_type = dir_entry.file_type()?;
        if file_type.is_file()
            && dir_entry.file_name().to_str().map_or(
                false,
                account_utils::validator_definitions::is_voting_keystore,
            )
        {
            *voting_keystore_path = Some(dir_entry.path());
        }
        Ok(())
    })
}
