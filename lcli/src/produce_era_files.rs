use beacon_chain::era::producer;
use clap::ArgMatches;
use clap_utils::parse_required;
use environment::Environment;
use std::path::PathBuf;
use store::database::interface::BeaconNodeBackend;
use store::{HotColdDB, StoreConfig};
use tracing::info;
use types::EthSpec;

pub fn run<E: EthSpec>(env: Environment<E>, matches: &ArgMatches) -> Result<(), String> {
    let datadir: PathBuf = parse_required(matches, "datadir")?;
    let output_dir: PathBuf = parse_required(matches, "output-dir")?;

    let hot_path = datadir.join("chain_db");
    let cold_path = datadir.join("freezer_db");
    let blobs_path = datadir.join("blobs_db");

    let spec = env.eth2_config.spec.clone();

    info!(
        hot_path = %hot_path.display(),
        cold_path = %cold_path.display(),
        output_dir = %output_dir.display(),
        "Opening database"
    );

    let db = HotColdDB::<E, BeaconNodeBackend<E>, BeaconNodeBackend<E>>::open(
        &hot_path,
        &cold_path,
        &blobs_path,
        |_, _, _| Ok(()),
        StoreConfig::default(),
        spec,
    )
    .map_err(|e| format!("Failed to open database: {e:?}"))?;

    let anchor = db.get_anchor_info();
    let split = db.get_split_info();

    info!(
        anchor_slot = %anchor.anchor_slot,
        state_lower_limit = %anchor.state_lower_limit,
        state_upper_limit = %anchor.state_upper_limit,
        oldest_block_slot = %anchor.oldest_block_slot,
        split_slot = %split.slot,
        "Database info"
    );

    // Verify reconstruction is complete: state_lower_limit should equal state_upper_limit
    if !anchor.all_historic_states_stored() {
        return Err(format!(
            "State reconstruction is not complete. \
             state_lower_limit={}, state_upper_limit={}. \
             Run with --reconstruct-historic-states first.",
            anchor.state_lower_limit, anchor.state_upper_limit,
        ));
    }

    // Verify block backfill is complete
    if anchor.oldest_block_slot > 0 {
        return Err(format!(
            "Block backfill is not complete. oldest_block_slot={}. \
             Complete backfill sync first.",
            anchor.oldest_block_slot,
        ));
    }

    let slots_per_historical_root = E::slots_per_historical_root() as u64;
    // An ERA can only be created if its end slot <= split slot (finalized boundary)
    let max_era = split.slot.as_u64() / slots_per_historical_root;

    info!(max_era, "Producing ERA files from 0 to max_era");

    std::fs::create_dir_all(&output_dir)
        .map_err(|e| format!("Failed to create output directory: {e}"))?;

    for era_number in 0..=max_era {
        producer::create_era_file(&db, era_number, &output_dir)
            .map_err(|e| format!("Failed to produce ERA file {era_number}: {e}"))?;

        if (era_number + 1) % 100 == 0 || era_number == max_era {
            info!(era_number, max_era, "Progress");
        }
    }

    info!(max_era, "ERA file production complete");

    Ok(())
}
