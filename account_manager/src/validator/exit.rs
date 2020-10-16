use crate::wallet::create::STDIN_INPUTS_FLAG;
use crate::{SECRETS_DIR_FLAG, VALIDATOR_DIR_FLAG};
use bls::{Keypair, PublicKey};
use clap::{App, Arg, ArgMatches};
use directory::{parse_path_or_default_with_flag, DEFAULT_SECRET_DIR};
use environment::Environment;
use eth2::{
    types::{GenesisData, StateId, ValidatorId},
    BeaconNodeHttpClient, Url,
};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use types::{ChainSpec, Epoch, EthSpec, Fork, Slot, VoluntaryExit};
use validator_dir::{Manager as ValidatorManager, ValidatorDir};

pub const CMD: &str = "exit";
pub const VALIDATOR_FLAG: &str = "validator";
pub const BEACON_SERVER_FLAG: &str = "beacon-node";
pub const REUSE_PASSWORD_FLAG: &str = "reuse-password";
pub const PASSWORD_PROMPT: &str = "Enter the keystore password: ";

pub const DEFAULT_BEACON_NODE: &str = "http://localhost:5052/";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("exit")
        .about("Submits a VoluntaryExit to the beacon chain for a given validator(s).")
        .arg(
            Arg::with_name(VALIDATOR_FLAG)
                .long(VALIDATOR_FLAG)
                .value_name("VALIDATOR_NAME")
                .help(
                    "The name of the directory in --data-dir for which to send a VoluntaryExit. \
                    Set to 'all' to exit all validators in the --data-dir.",
                )
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name(BEACON_SERVER_FLAG)
                .long(BEACON_SERVER_FLAG)
                .value_name("NETWORK_ADDRESS")
                .help("Address to a beacon node HTTP API")
                .default_value(&DEFAULT_BEACON_NODE)
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
                .takes_value(true)
                .requires(VALIDATOR_DIR_FLAG)
                .conflicts_with("datadir"),
        )
        .arg(
            Arg::with_name(STDIN_INPUTS_FLAG)
                .long(STDIN_INPUTS_FLAG)
                .help("If present, read all user inputs from stdin instead of tty."),
        )
        .arg(
            Arg::with_name(REUSE_PASSWORD_FLAG)
                .long(REUSE_PASSWORD_FLAG)
                .help("If present, the same password will be used for all imported keystores."),
        )
}

pub fn cli_run<E: EthSpec>(
    matches: &ArgMatches,
    mut env: Environment<E>,
    validator_dir: PathBuf,
) -> Result<(), String> {
    let validator: String = clap_utils::parse_required(matches, VALIDATOR_FLAG)?;
    let secrets_dir = if matches.value_of("datadir").is_some() {
        let path: PathBuf = clap_utils::parse_required(matches, "datadir")?;
        path.join(DEFAULT_SECRET_DIR)
    } else {
        parse_path_or_default_with_flag(matches, SECRETS_DIR_FLAG, DEFAULT_SECRET_DIR)?
    };
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

    let spec = env.eth2_config().spec.clone();
    let server_url: String = clap_utils::parse_required(matches, BEACON_SERVER_FLAG)?;
    let client = BeaconNodeHttpClient::new(
        Url::parse(&server_url)
            .map_err(|e| format!("Failed to parse beacon http server: {:?}", e))?,
    );
    env.runtime().block_on(publish_voluntary_exits::<E>(
        validators,
        &secrets_dir,
        &client,
        &spec,
        stdin_inputs,
    ))?;

    return Ok(());
}

/// Gets the associated keypair for a validator and calls `publish_voluntary_exit` on it.
async fn publish_voluntary_exits<E: EthSpec>(
    validator_dirs: Vec<ValidatorDir>,
    secrets_dir: &PathBuf,
    client: &BeaconNodeHttpClient,
    spec: &ChainSpec,
    stdin_inputs: bool,
) -> Result<(), String> {
    for validator_dir in validator_dirs {
        let keypair = load_voting_keypair(&validator_dir, secrets_dir, stdin_inputs)?;
        if let Err(e) = publish_voluntary_exit::<E>(&keypair, client, spec).await {
            eprintln!(
                "Failed to publish voluntary exit for validator {:?}, error: {}",
                validator_dir.dir(),
                e
            );
        }
    }
    Ok(())
}

/// Constructs a `VoluntaryExit` object for a given validator and signs it using the given bls keypair.
/// Publishes the voluntary exit to the beacon chain using the beacon node endpoint.
async fn publish_voluntary_exit<E: EthSpec>(
    keypair: &Keypair,
    client: &BeaconNodeHttpClient,
    spec: &ChainSpec,
) -> Result<(), String> {
    let genesis_data = get_geneisis_data(client).await?;
    let voluntary_exit = VoluntaryExit {
        epoch: get_current_epoch::<E>(genesis_data.genesis_time, spec)?,
        validator_index: get_validator_index(client, &keypair.pk).await?,
    };

    let fork = get_beacon_state_fork(client).await?;

    let signed_voluntary_exit = voluntary_exit.sign(
        &keypair.sk,
        &fork,
        genesis_data.genesis_validators_root,
        spec,
    );

    // TODO(pawan): prompt user to verify deets

    // Publish the voluntary exit to network
    client
        .post_beacon_pool_voluntary_exits(&signed_voluntary_exit)
        .await
        .map_err(|e| format!("Failed to publish voluntary exit: {}", e))
}

/// Get the validator index given the validator public key by querying the beacon node endpoint.
async fn get_validator_index(
    client: &BeaconNodeHttpClient,
    validator_pubkey: &PublicKey,
) -> Result<u64, String> {
    Ok(client
        .get_beacon_states_validator_id(
            StateId::Head, //TODO(pawan): should we query StateId::Finalized?
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
        .data.index)
}

/// Get genesis data by querying the beacon node client.
async fn get_geneisis_data(client: &BeaconNodeHttpClient) -> Result<GenesisData, String> {
    Ok(client
        .get_beacon_genesis()
        .await
        .map_err(|e| format!("Failed to get beacon genesis: {}", e))?
        .data)
}

async fn get_beacon_state_fork(client: &BeaconNodeHttpClient) -> Result<Fork, String> {
    Ok(client
        .get_beacon_states_fork(StateId::Finalized)
        .await
        .map_err(|e| format!("Failed to get get fork: {:?}", e))?
        .ok_or_else(|| "Failed to get fork, state not found".to_string())?
        .data)
}

/// Calculates the current epoch from the genesis time and current time.
fn get_current_epoch<E: EthSpec>(genesis_time: u64, spec: &ChainSpec) -> Result<Epoch, String> {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("Failed to get current time: {}", e))?
        .as_secs();

    // TODO(pawan): Do safe math here
    let elapsed = current_time - genesis_time;
    let seconds_per_slot = spec.milliseconds_per_slot / 1000;

    let current_slot = Slot::new(elapsed / seconds_per_slot);
    Ok(current_slot.epoch(E::slots_per_epoch()))
}

/// Load the voting keypair by loading the keystore and decrypting the keystore
///
/// First attempts to load the password for the validator from the `secrets_dir`, if not
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
