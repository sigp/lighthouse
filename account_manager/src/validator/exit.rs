use crate::wallet::create::STDIN_INPUTS_FLAG;
use crate::{SECRETS_DIR_FLAG, VALIDATOR_DIR_FLAG};
use bls::{Keypair, PublicKey};
use clap::{App, Arg, ArgMatches};
use environment::Environment;
use eth2::{
    types::{GenesisData, StateId, ValidatorId},
    BeaconNodeHttpClient,
};
use slog::{info, Logger};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use types::{ChainSpec, Epoch, EthSpec, Fork, SignedVoluntaryExit, Slot, VoluntaryExit};
use validator_dir::{Manager as ValidatorManager, ValidatorDir};

pub const CMD: &str = "exit";
pub const VALIDATOR_FLAG: &str = "validator";
pub const BEACON_SERVER_FLAG: &str = "beacon-node";
pub const REUSE_PASSWORD_FLAG: &str = "reuse-password";

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

pub fn cli_run<T: EthSpec>(
    matches: &ArgMatches,
    mut env: Environment<T>,
    validator_dir: PathBuf,
) -> Result<(), String> {
    let log = env.core_context().log().clone();

    let validator: String = clap_utils::parse_required(matches, VALIDATOR_FLAG)?;

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

    return Ok(());
}

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
