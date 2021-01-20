use crate::wallet::create::STDIN_INPUTS_FLAG;
use bls::{Keypair, PublicKey};
use clap::{App, Arg, ArgMatches};
use environment::Environment;
use eth2::{
    types::{GenesisData, StateId, ValidatorId, ValidatorStatus},
    BeaconNodeHttpClient, Url,
};
use eth2_keystore::Keystore;
use eth2_network_config::Eth2NetworkConfig;
use safe_arith::SafeArith;
use slot_clock::{SlotClock, SystemTimeSlotClock};
use std::path::PathBuf;
use std::time::Duration;
use tokio_compat_02::FutureExt;
use types::{ChainSpec, Epoch, EthSpec, Fork, VoluntaryExit};

pub const CMD: &str = "exit";
pub const KEYSTORE_FLAG: &str = "keystore";
pub const PASSWORD_FILE_FLAG: &str = "password-file";
pub const BEACON_SERVER_FLAG: &str = "beacon-node";
pub const PASSWORD_PROMPT: &str = "Enter the keystore password";

pub const DEFAULT_BEACON_NODE: &str = "http://localhost:5052/";
pub const CONFIRMATION_PHRASE: &str = "Exit my validator";
pub const WEBSITE_URL: &str = "https://lighthouse-book.sigmaprime.io/voluntary-exit.html";
pub const PROMPT: &str = "WARNING: WITHDRAWING STAKED ETH IS NOT CURRENTLY POSSIBLE";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("exit")
        .about("Submits a VoluntaryExit to the beacon chain for a given validator keystore.")
        .arg(
            Arg::with_name(KEYSTORE_FLAG)
                .long(KEYSTORE_FLAG)
                .value_name("KEYSTORE_PATH")
                .help("The path to the EIP-2335 voting keystore for the validator")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name(PASSWORD_FILE_FLAG)
                .long(PASSWORD_FILE_FLAG)
                .value_name("PASSWORD_FILE_PATH")
                .help("The path to the password file which unlocks the validator voting keystore")
                .takes_value(true),
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
            Arg::with_name(STDIN_INPUTS_FLAG)
                .long(STDIN_INPUTS_FLAG)
                .help("If present, read all user inputs from stdin instead of tty."),
        )
}

pub fn cli_run<E: EthSpec>(matches: &ArgMatches, env: Environment<E>) -> Result<(), String> {
    let keystore_path: PathBuf = clap_utils::parse_required(matches, KEYSTORE_FLAG)?;
    let password_file_path: Option<PathBuf> =
        clap_utils::parse_optional(matches, PASSWORD_FILE_FLAG)?;
    let stdin_inputs = matches.is_present(STDIN_INPUTS_FLAG);

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

    env.runtime().block_on(
        publish_voluntary_exit::<E>(
            &keystore_path,
            password_file_path.as_ref(),
            &client,
            &spec,
            stdin_inputs,
            &testnet_config,
        )
        .compat(),
    )?;

    Ok(())
}

/// Gets the keypair and validator_index for every validator and calls `publish_voluntary_exit` on it.
async fn publish_voluntary_exit<E: EthSpec>(
    keystore_path: &PathBuf,
    password_file_path: Option<&PathBuf>,
    client: &BeaconNodeHttpClient,
    spec: &ChainSpec,
    stdin_inputs: bool,
    testnet_config: &Eth2NetworkConfig,
) -> Result<(), String> {
    let genesis_data = get_geneisis_data(client).await?;
    let testnet_genesis_root = testnet_config
        .beacon_state::<E>()
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

    // Return immediately if beacon node is not synced
    if is_syncing(client).await? {
        return Err("Beacon node is still syncing".to_string());
    }

    let keypair = load_voting_keypair(keystore_path, password_file_path, stdin_inputs)?;

    let epoch = get_current_epoch::<E>(genesis_data.genesis_time, spec)
        .ok_or("Failed to get current epoch. Please check your system time")?;
    let validator_index = get_validator_index_for_exit(client, &keypair.pk, epoch, spec).await?;

    let fork = get_beacon_state_fork(client).await?;
    let voluntary_exit = VoluntaryExit {
        epoch,
        validator_index,
    };

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
        // Sign and publish the voluntary exit to network
        let signed_voluntary_exit = voluntary_exit.sign(
            &keypair.sk,
            &fork,
            genesis_data.genesis_validators_root,
            spec,
        );
        client
            .post_beacon_pool_voluntary_exits(&signed_voluntary_exit)
            .await
            .map_err(|e| format!("Failed to publish voluntary exit: {}", e))?;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await; // Provides nicer UX.
        eprintln!(
            "Successfully validated and published voluntary exit for validator {}",
            keypair.pk
        );
    } else {
        eprintln!(
            "Did not publish voluntary exit for validator {}. Please check that you entered the correct exit phrase.",
            keypair.pk
        );
    }

    Ok(())
}

/// Get the validator index of a given the validator public key by querying the beacon node endpoint.
///
/// Returns an error if the beacon endpoint returns an error or given validator is not eligible for an exit.
async fn get_validator_index_for_exit(
    client: &BeaconNodeHttpClient,
    validator_pubkey: &PublicKey,
    epoch: Epoch,
    spec: &ChainSpec,
) -> Result<u64, String> {
    let validator_data = client
        .get_beacon_states_validator_id(
            StateId::Head,
            &ValidatorId::PublicKey(validator_pubkey.into()),
        )
        .await
        .map_err(|e| format!("Failed to get validator details: {:?}", e))?
        .ok_or_else(|| {
            format!(
                "Validator {} is not present in the beacon state. \
                Please ensure that your beacon node is synced and the validator has been deposited.",
                validator_pubkey
            )
        })?
        .data;

    match validator_data.status {
        ValidatorStatus::Active => {
            let eligible_epoch = validator_data
                .validator
                .activation_epoch
                .safe_add(spec.shard_committee_period)
                .map_err(|e| format!("Failed to calculate eligible epoch, validator activation epoch too high: {:?}", e))?;

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

/// Gets syncing status from beacon node client and returns true if syncing and false otherwise.
async fn is_syncing(client: &BeaconNodeHttpClient) -> Result<bool, String> {
    Ok(client
        .get_node_syncing()
        .await
        .map_err(|e| format!("Failed to get sync status: {:?}", e))?
        .data
        .is_syncing)
}

/// Get fork object for the current state by querying the beacon node client.
async fn get_beacon_state_fork(client: &BeaconNodeHttpClient) -> Result<Fork, String> {
    Ok(client
        .get_beacon_states_fork(StateId::Head)
        .await
        .map_err(|e| format!("Failed to get get fork: {:?}", e))?
        .ok_or("Failed to get fork, state not found")?
        .data)
}

/// Calculates the current epoch from the genesis time and current time.
fn get_current_epoch<E: EthSpec>(genesis_time: u64, spec: &ChainSpec) -> Option<Epoch> {
    let slot_clock = SystemTimeSlotClock::new(
        spec.genesis_slot,
        Duration::from_secs(genesis_time),
        Duration::from_secs(spec.seconds_per_slot),
    );
    slot_clock.now().map(|s| s.epoch(E::slots_per_epoch()))
}

/// Load the voting keypair by loading and decrypting the keystore.
///
/// If the `password_file_path` is Some, unlock keystore using password in given file
/// otherwise, prompts user for a password to unlock the keystore.
fn load_voting_keypair(
    voting_keystore_path: &PathBuf,
    password_file_path: Option<&PathBuf>,
    stdin_inputs: bool,
) -> Result<Keypair, String> {
    let keystore = Keystore::from_json_file(&voting_keystore_path).map_err(|e| {
        format!(
            "Unable to read keystore JSON {:?}: {:?}",
            voting_keystore_path, e
        )
    })?;

    // Get password from password file.
    if let Some(password_file) = password_file_path {
        validator_dir::unlock_keypair_from_password_path(voting_keystore_path, password_file)
            .map_err(|e| format!("Error while decrypting keypair: {:?}", e))
    } else {
        // Prompt password from user.
        eprintln!("");
        eprintln!(
            "{} for validator in {:?}: ",
            PASSWORD_PROMPT, voting_keystore_path
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
}

#[cfg(test)]
#[cfg(not(debug_assertions))]
mod tests {
    use super::*;
    use eth2_keystore::KeystoreBuilder;
    use std::fs::File;
    use std::io::Write;
    use tempfile::{tempdir, TempDir};

    const PASSWORD: &str = "cats";
    const KEYSTORE_NAME: &str = "keystore-m_12381_3600_0_0_0-1595406747.json";
    const PASSWORD_FILE: &str = "password.pass";

    fn create_and_save_keystore(dir: &TempDir, save_password: bool) -> PublicKey {
        let keypair = Keypair::random();
        let keystore = KeystoreBuilder::new(&keypair, PASSWORD.as_bytes(), "".into())
            .unwrap()
            .build()
            .unwrap();

        // Create a keystore.
        File::create(dir.path().join(KEYSTORE_NAME))
            .map(|mut file| keystore.to_json_writer(&mut file).unwrap())
            .unwrap();
        if save_password {
            File::create(dir.path().join(PASSWORD_FILE))
                .map(|mut file| file.write_all(PASSWORD.as_bytes()).unwrap())
                .unwrap();
        }
        keystore.public_key().unwrap()
    }

    #[test]
    fn test_load_keypair_password_file() {
        let dir = tempdir().unwrap();
        let expected_pk = create_and_save_keystore(&dir, true);

        let kp = load_voting_keypair(
            &dir.path().join(KEYSTORE_NAME),
            Some(&dir.path().join(PASSWORD_FILE)),
            false,
        )
        .unwrap();

        assert_eq!(expected_pk, kp.pk.into());
    }
}
