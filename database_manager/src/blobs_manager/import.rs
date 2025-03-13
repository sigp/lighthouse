use crate::blobs_manager::{cli::ImportBlobs, ensure_node_synced};
use eth2::{types::EthSpec, BeaconNodeHttpClient, Timeouts};
use sensitive_url::SensitiveUrl;
use slog::{info, warn, Logger};
use std::time::Duration;

pub async fn import_blobs<E: EthSpec>(config: &ImportBlobs, log: Logger) -> Result<(), String> {
    let beacon_node = SensitiveUrl::parse(&config.beacon_node)
        .map_err(|e| format!("Unable to parse beacon node url: {e:?}"))?;

    let client = BeaconNodeHttpClient::new(beacon_node, Timeouts::set_all(Duration::from_secs(12)));

    let (_, is_synced) = ensure_node_synced(&client).await?;
    if !is_synced {
        if config.allow_unsynced {
            warn!(log, "Beacon node is not synced");
        } else {
            return Err("Beacon node is not synced".to_string());
        }
    }

    let blobs_ssz = std::fs::read(&config.input_file)
        .map_err(|e| format!("Failed to read input file: {e:?}"))?;

    // TODO(blob_manager): We could _technically_ parse the slot numbers from the SSZ file
    // generated during export.

    info!(log, "Beginning blob import");

    if config.skip_verification {
        warn!(log, "Skipping blob verification");
    }

    client
        .post_lighthouse_database_import_blobs_ssz(blobs_ssz.into(), config.skip_verification)
        .await
        .map_err(|e| format!("Failed to import blobs: {e:?}"))?;

    if !config.skip_verification {
        info!(log, "All blobs successfully verified");
    }
    info!(log, "Completed blob import");

    Ok(())
}
