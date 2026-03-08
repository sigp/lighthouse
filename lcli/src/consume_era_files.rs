use beacon_chain::era::consumer::EraFileDir;
use clap::ArgMatches;
use clap_utils::parse_required;
use environment::Environment;
use eth2_network_config::Eth2NetworkConfig;
use std::path::PathBuf;
use std::time::Duration;
use store::database::interface::BeaconNodeBackend;
use store::{HotColdDB, StoreConfig};
use tracing::info;
use types::EthSpec;

fn is_dir_non_empty(path: &PathBuf) -> bool {
    path.exists()
        && std::fs::read_dir(path)
            .map(|mut entries| entries.next().is_some())
            .unwrap_or(false)
}

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

    // Fail fast if database directories already contain data
    if is_dir_non_empty(&hot_path) || is_dir_non_empty(&cold_path) {
        return Err(format!(
            "Database directories are not empty: {} / {}. \
             This command expects a fresh datadir.",
            hot_path.display(),
            cold_path.display(),
        ));
    }

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

    let db = HotColdDB::<E, BeaconNodeBackend<E>, BeaconNodeBackend<E>>::open(
        &hot_path,
        &cold_path,
        &blobs_path,
        |_, _, _| Ok(()),
        StoreConfig::default(),
        spec.clone(),
    )
    .map_err(|e| format!("Failed to open database: {e:?}"))?;

    // Load genesis state from the network config
    let mut genesis_state = env
        .runtime()
        .block_on(network_config.genesis_state::<E>(None, Duration::from_secs(120)))
        .map_err(|e| format!("Failed to load genesis state: {e}"))?
        .ok_or("No genesis state available for this network")?;

    // Open ERA files directory and validate against genesis
    let era_file_dir = EraFileDir::new::<E>(&era_dir, &spec)
        .map_err(|e| format!("Failed to open ERA dir: {e}"))?;

    // Verify ERA files match the network's genesis
    if era_file_dir.genesis_validators_root() != genesis_state.genesis_validators_root() {
        return Err(format!(
            "ERA files genesis_validators_root ({:?}) does not match network genesis ({:?}). \
             Are the ERA files from the correct network?",
            era_file_dir.genesis_validators_root(),
            genesis_state.genesis_validators_root(),
        ));
    }

    info!(
        genesis_validators_root = %genesis_state.genesis_validators_root(),
        "Storing genesis state"
    );

    let genesis_root = genesis_state
        .canonical_root()
        .map_err(|e| format!("Failed to hash genesis state: {e:?}"))?;
    db.put_cold_state(&genesis_root, &genesis_state)
        .map_err(|e| format!("Failed to store genesis state: {e:?}"))?;

    let max_era = era_file_dir.max_era();
    info!(max_era, "Importing ERA files");

    let start = std::time::Instant::now();
    for era_number in 1..=max_era {
        era_file_dir
            .import_era_file(&db, era_number, &spec, None)
            .map_err(|e| format!("Failed to import ERA {era_number}: {e}"))?;

        if era_number % 100 == 0 || era_number == max_era {
            let elapsed = start.elapsed();
            let rate = era_number as f64 / elapsed.as_secs_f64();
            info!(
                era_number,
                max_era,
                ?elapsed,
                rate = format!("{rate:.1} era/s"),
                "Progress"
            );
        }
    }

    info!(
        max_era,
        elapsed = ?start.elapsed(),
        "ERA file import complete. Database is ready."
    );

    Ok(())
}
