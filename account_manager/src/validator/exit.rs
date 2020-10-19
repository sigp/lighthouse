use crate::wallet::create::STDIN_INPUTS_FLAG;
use crate::{SECRETS_DIR_FLAG, VALIDATOR_DIR_FLAG};
use bls::{Keypair, PublicKey};
use clap::{App, Arg, ArgMatches};
use directory::{parse_path_or_default_with_flag, DEFAULT_SECRET_DIR};
use environment::Environment;
use eth2::{
    types::{GenesisData, StateId, ValidatorId, ValidatorStatus},
    BeaconNodeHttpClient, Url,
};
use eth2_testnet_config::Eth2TestnetConfig;
use safe_arith::{ArithError, SafeArith};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use types::{ChainSpec, Epoch, EthSpec, Fork, Hash256, Slot, VoluntaryExit};
use validator_dir::{Manager as ValidatorManager, ValidatorDir};

pub const CMD: &str = "exit";
pub const VALIDATOR_FLAG: &str = "validator";
pub const BEACON_SERVER_FLAG: &str = "beacon-node";
pub const PASSWORD_PROMPT: &str = "Enter the keystore password";

pub const DEFAULT_BEACON_NODE: &str = "http://localhost:5052/";
pub const CONFIRMATION_PHRASE: &str = "Exit my validator";
pub const WEBSITE_URL: &str = "https://lighthouse-book.sigmaprime.io/voluntary-exit.html";
pub const PROMPT: &str =
    "WARNING: WITHDRAWING STAKED ETH WILL NOT BE POSSIBLE UNTIL ETH1/ETH2 MERGE";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("exit")
        .about("Submits a VoluntaryExit to the beacon chain for a given validator(s).")
        .arg(
            Arg::with_name(VALIDATOR_FLAG)
                .long(VALIDATOR_FLAG)
                .value_name("VALIDATOR_NAME")
                .help(
                    "The name of the directory in validators directory for which to send a VoluntaryExit. \
                    Set to 'all' to exit all validators in the validators directory.",
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

    let testnet_config = env
        .testnet
        .clone()
        .expect("network should have a valid config");

    env.runtime().block_on(publish_voluntary_exits::<E>(
        validators,
        &secrets_dir,
        &client,
        &spec,
        stdin_inputs,
        &testnet_config,
    ))?;

    Ok(())
}

/// Gets the associated keypair for a validator and calls `publish_voluntary_exit` on it.
async fn publish_voluntary_exits<E: EthSpec>(
    validator_dirs: Vec<ValidatorDir>,
    secrets_dir: &PathBuf,
    client: &BeaconNodeHttpClient,
    spec: &ChainSpec,
    stdin_inputs: bool,
    testnet_config: &Eth2TestnetConfig<E>,
) -> Result<(), String> {
    let genesis_data = get_geneisis_data(client).await?;
    let testnet_genesis_root = testnet_config
        .genesis_state
        .as_ref()
        .expect("network should have valid genesis state")
        .genesis_validators_root;

    // Verify that the beacon node and validator being exited are on the same network.
    if genesis_data.genesis_validators_root != testnet_genesis_root {
        return Err(
            "Invalid genesis state. Please ensure that your beacon node is on the same network \
                 as the validator you are publishing an exit for"
                .to_string(),
        );
    }
    let epoch = get_current_epoch::<E>(genesis_data.genesis_time, spec)
        .map_err(|e| format!("Failed to get current epoch: {:?}", e))?;
    let fork = get_beacon_state_fork(client).await?;

    for validator_dir in validator_dirs {
        let keypair = load_voting_keypair(&validator_dir, secrets_dir, stdin_inputs)?;
        let validator_index = get_validator_index::<E>(client, &keypair.pk, epoch, spec).await;

        match validator_index {
            Ok(index) => {
                if let Err(e) = publish_voluntary_exit::<E>(
                    &keypair,
                    client,
                    spec,
                    stdin_inputs,
                    epoch,
                    index,
                    &fork,
                    genesis_data.genesis_validators_root,
                )
                .await
                {
                    eprintln!(
                        "Failed to publish voluntary exit for validator {:?}, error: {}",
                        validator_dir.dir(),
                        e
                    );
                }
            }
            Err(e) => eprintln!("{}", e),
        }
    }
    Ok(())
}

/// Constructs a `VoluntaryExit` object for a given validator and signs it using the given bls keypair.
/// Publishes the voluntary exit to the beacon chain using the beacon node endpoint.
#[allow(clippy::too_many_arguments)]
async fn publish_voluntary_exit<E: EthSpec>(
    keypair: &Keypair,
    client: &BeaconNodeHttpClient,
    spec: &ChainSpec,
    stdin_inputs: bool,
    epoch: Epoch,
    validator_index: u64,
    fork: &Fork,
    genesis_validators_root: Hash256,
) -> Result<(), String> {
    let voluntary_exit = VoluntaryExit {
        epoch,
        validator_index,
    };

    let signed_voluntary_exit =
        voluntary_exit.sign(&keypair.sk, &fork, genesis_validators_root, spec);

    dbg!(&signed_voluntary_exit);
    eprintln!(
        "Publishing a voluntary exit for validator: {} \n",
        keypair.pk
    );
    eprintln!("WARNING: THIS IS AN IRREVERSIBLE OPERATION\n");
    eprintln!("{}\n", PROMPT);
    eprintln!(
        "PLEASE VISIT {} TO MAKE SURE YOU UNDERSTAND THE IMPLICATIONS OF A VOLUNTARY EXIT.",
        WEBSITE_URL
    );
    eprintln!("Enter the exit phrase from the above URL to confirm the voluntary exit: ");

    let confirmation = account_utils::read_input_from_user(stdin_inputs)?;
    if confirmation == CONFIRMATION_PHRASE {
        // Verify and publish the voluntary exit to network
        client
            .post_beacon_pool_voluntary_exits(&signed_voluntary_exit)
            .await
            .map_err(|e| format!("Failed to publish voluntary exit: {}", e))?;
        eprintln!(
            "Successfully validated and published voluntary exit for validator {}",
            keypair.pk
        );
    } else {
        eprintln!(
            "Did not publish voluntary exit for validator {}. Please check that you entered the correct passphrase.",
            keypair.pk
        );
    }
    Ok(())
}

/// Get the validator index af given the validator public key by querying the beacon node endpoint.
/// Returns an error if the beacon endpoint returns an error or given validator is not eligible for an exit.
async fn get_validator_index<E: EthSpec>(
    client: &BeaconNodeHttpClient,
    validator_pubkey: &PublicKey,
    epoch: Epoch,
    spec: &ChainSpec,
) -> Result<u64, String> {
    let validator_data = client
        .get_beacon_states_validator_id(
            // TODO: verify this is the state that we want to query.
            StateId::Slot(epoch.start_slot(E::slots_per_epoch())),
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

    match validator_data.status {
        ValidatorStatus::Active => {
            let eligible_epoch =
                validator_data.validator.activation_epoch + spec.shard_committee_period;
            if epoch >= eligible_epoch {
                Ok(validator_data.index)
            } else {
                Err(format!(
                    "Validator {:?} is not eligible for exit. It will become eligible on epoch {}",
                    validator_pubkey, eligible_epoch
                ))
            }
        }
        status => Err(format!(
            "Validator {:?} is not eligible for voluntary exit. Validator status: {:?}",
            validator_pubkey, status
        )),
    }
}

/// Get genesis data by querying the beacon node client.
async fn get_geneisis_data(client: &BeaconNodeHttpClient) -> Result<GenesisData, String> {
    Ok(client
        .get_beacon_genesis()
        .await
        .map_err(|e| format!("Failed to get beacon genesis: {}", e))?
        .data)
}

/// Get fork object for the current state by querying the beacon node client.
async fn get_beacon_state_fork(client: &BeaconNodeHttpClient) -> Result<Fork, String> {
    Ok(client
        .get_beacon_states_fork(StateId::Finalized) //TODO(pawan): should we use finalized?
        .await
        .map_err(|e| format!("Failed to get get fork: {:?}", e))?
        .ok_or_else(|| "Failed to get fork, state not found".to_string())?
        .data)
}

/// Calculates the current epoch from the genesis time and current time.
fn get_current_epoch<E: EthSpec>(genesis_time: u64, spec: &ChainSpec) -> Result<Epoch, ArithError> {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("UNIX EPOCH should always be lower than current time")
        .as_secs();

    let elapsed = current_time.safe_sub(genesis_time)?;
    let seconds_per_slot = spec.milliseconds_per_slot.safe_div(1000)?;

    let current_slot = Slot::new(elapsed.safe_div(seconds_per_slot)?);
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
                "{} for validator in {:?}: ",
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

#[cfg(test)]
mod tests {
    use super::*;
    use slot_clock::{SlotClock, SystemTimeSlotClock};
    use std::time::Duration;
    use types::MinimalEthSpec;

    type E = MinimalEthSpec;
    const GENESIS_TIME: u64 = 1602504013;

    #[test]
    fn test_get_current_epoch() {
        let spec = E::default_spec();

        let slot_clock = SystemTimeSlotClock::new(
            spec.genesis_slot,
            Duration::from_secs(GENESIS_TIME),
            Duration::from_millis(spec.milliseconds_per_slot),
        );
        let expected_epoch = slot_clock
            .now()
            .map(|s| s.epoch(E::slots_per_epoch()))
            .unwrap();
        let epoch = get_current_epoch::<E>(GENESIS_TIME, &spec).unwrap();

        assert_eq!(expected_epoch, epoch);
    }
}
