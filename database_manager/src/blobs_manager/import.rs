use crate::blobs_manager::{cli::ImportBlobs, ensure_node_synced, DEFAULT_BEACON_NODE};
use eth2::{types::EthSpec, BeaconNodeHttpClient, Timeouts};
use sensitive_url::SensitiveUrl;
use ssz::{Decode, Encode};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};
use types::BlobSidecar;

pub async fn import_blobs<E: EthSpec>(config: &ImportBlobs) -> Result<(), String> {
    let beacon_node = SensitiveUrl::parse(
        &config
            .beacon_node
            .clone()
            .unwrap_or(DEFAULT_BEACON_NODE.to_string()),
    )
    .map_err(|e| format!("Unable to parse beacon node url: {e:?}"))?;

    let client = BeaconNodeHttpClient::new(beacon_node, Timeouts::set_all(Duration::from_secs(12)));

    if !config.allow_unsynced {
        let (_, is_synced) = ensure_node_synced(&client).await?;
        if !is_synced {
            return Err(
                "Beacon node is not synced. Use --allow-unsynced to skip this check.".to_string(),
            );
        }
    }

    let blobs_ssz = std::fs::read(&config.input_file)
        .map_err(|e| format!("Failed to read input file: {e:?}"))?;

    info!("Beginning blob import");

    let verify = !config.skip_verification;

    if !verify {
        warn!("Skipping blob verification")
    }

    let blobs_vec = Vec::<Vec<Arc<BlobSidecar<E>>>>::from_ssz_bytes(&blobs_ssz)
        .map_err(|e| format!("Failed to decode blobs: {e:?}"))?;

    let chunks = blobs_vec.chunks(config.chunk_size_slots);

    for chunk in chunks {
        match client
            .post_lighthouse_database_import_blobs_ssz(
                chunk.iter().collect::<Vec<_>>().as_ssz_bytes().into(),
                Some(!config.skip_verification),
            )
            .await
            .map_err(|e| format!("Failed to import blobs: {e:?}"))
        {
            Ok(_) => {}
            Err(e) => {
                error!("Some or all blobs failed to import. Please check the input file and try again.");
                return Err(e);
            }
        }
    }

    if !config.skip_verification {
        info!("All blobs successfully verified");
    }
    info!("Completed blob import");

    Ok(())
}
