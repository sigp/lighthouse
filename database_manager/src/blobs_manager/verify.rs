use crate::blobs_manager::{cli::VerifyBlobs, ensure_node_synced, DEFAULT_BEACON_NODE};
use eth2::{
    lighthouse::BlobsVerificationData,
    types::{ChainSpec, EthSpec, Slot},
    BeaconNodeHttpClient, SensitiveUrl, Timeouts,
};
use std::time::Duration;
use tracing::{info, warn};

pub async fn verify_blobs<E: EthSpec>(
    config: &VerifyBlobs,
    spec: &ChainSpec,
) -> Result<(), String> {
    let beacon_node = SensitiveUrl::parse(
        &config
            .beacon_node
            .clone()
            .unwrap_or(DEFAULT_BEACON_NODE.to_string()),
    )
    .map_err(|e| format!("Unable to parse beacon node url: {e:?}"))?;
    let client = BeaconNodeHttpClient::new(beacon_node, Timeouts::set_all(Duration::from_secs(12)));

    let (_head_slot, is_synced) = ensure_node_synced(&client).await?;
    if !is_synced {
        if config.allow_unsynced {
            warn!("Beacon node is not synced");
        } else {
            return Err("Beacon node is not synced".to_string());
        }
    }

    let _min_epochs_for_blob_sidecars_requests = spec.min_epochs_for_blob_sidecars_requests;

    let _slots_verified = 0;

    let verification_data: Vec<BlobsVerificationData> = client
        .get_lighthouse_database_verify_blobs(
            config.start_slot.map(Slot::from),
            config.end_slot.map(Slot::from),
        )
        .await
        .map_err(|e| format!("Failed to verify blobs: {e:?}"))?;

    let mut missing_slots = vec![];
    for data in verification_data {
        if data.blobs_exist && !data.blobs_stored {
            missing_slots.push(data.slot);
        }
    }

    info!(missing_slots = missing_slots.len(), "Slots missing");

    Ok(())
}
