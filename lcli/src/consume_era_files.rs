use beacon_chain::era::consumer::{EraFileDir, EraImportTrust};
use beacon_chain::era::store_init::init_genesis_store;
use clap::ArgMatches;
use clap_utils::parse_required;
use environment::Environment;
use eth2_network_config::Eth2NetworkConfig;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use store::database::interface::BeaconNodeBackend;
use store::{HotColdDB, StoreConfig};
use tracing::info;
use types::{EthSpec, Hash256};

pub fn run<E: EthSpec>(
    env: Environment<E>,
    network_config: Eth2NetworkConfig,
    matches: &ArgMatches,
) -> Result<(), String> {
    let datadir: PathBuf = parse_required(matches, "datadir")?;
    let era_dir: PathBuf = parse_required(matches, "era-dir")?;

    let hot_path = datadir.join("chain_db");
    let cold_path = datadir.join("freezer_db");
    let blobs_path = datadir.join("blobs_db");

    let spec = env.eth2_config.spec.clone();

    info!(
        hot_path = %hot_path.display(),
        cold_path = %cold_path.display(),
        era_dir = %era_dir.display(),
        "Opening database"
    );

    std::fs::create_dir_all(&hot_path).map_err(|e| format!("Failed to create hot db dir: {e}"))?;
    std::fs::create_dir_all(&cold_path)
        .map_err(|e| format!("Failed to create cold db dir: {e}"))?;
    std::fs::create_dir_all(&blobs_path)
        .map_err(|e| format!("Failed to create blobs db dir: {e}"))?;

    let db = Arc::new(
        HotColdDB::<E, BeaconNodeBackend<E>, BeaconNodeBackend<E>>::open(
            &hot_path,
            &cold_path,
            &blobs_path,
            |_, _, _| Ok(()),
            StoreConfig::default(),
            spec.clone(),
        )
        .map_err(|e| format!("Failed to open database: {e:?}"))?,
    );

    let mut genesis_state = env
        .runtime()
        .block_on(network_config.genesis_state::<E>(None, Duration::from_secs(120)))
        .map_err(|e| format!("Failed to load genesis state: {e}"))?
        .ok_or("No genesis state available for this network")?;

    let genesis_validators_root = genesis_state.genesis_validators_root();

    // Initialize genesis store only on first run. On crash-resume the store is already
    // initialized and import_all will resume from the last ERA import pointer.
    let already_initialized = db
        .get_era_import_pointer()
        .map_err(|e| format!("Failed to read ERA import pointer: {e:?}"))?
        .is_some();

    if !already_initialized {
        init_genesis_store(&db, &mut genesis_state, &spec)
            .map_err(|e| format!("Failed to initialize store from genesis: {e}"))?;
    } else {
        info!("Resuming ERA import from previous run");
    }

    let trust = match matches.get_one::<String>("era-trusted-state") {
        Some(value) => {
            let (era_str, root_hex) = value
                .split_once(':')
                .ok_or("--era-trusted-state must be ERA_NUMBER:STATE_ROOT")?;
            let era_number: u64 = era_str
                .parse()
                .map_err(|e| format!("invalid era number in --era-trusted-state: {e}"))?;
            let root = root_hex
                .strip_prefix("0x")
                .unwrap_or(root_hex)
                .parse::<Hash256>()
                .map_err(|e| format!("invalid state root in --era-trusted-state: {e}"))?;
            EraImportTrust::TrustedStateRoot(era_number, root)
        }
        None => EraImportTrust::Untrusted,
    };

    let era_file_dir = EraFileDir::new::<E>(&era_dir, genesis_validators_root, trust, &spec)
        .map_err(|e| format!("Failed to open ERA dir: {e}"))?;

    era_file_dir.import_all(&db, &spec)?;

    Ok(())
}
