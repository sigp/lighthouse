use crate::blobs_manager::{cli::ExportBlobs, ensure_node_synced};
use eth2::{
    types::{BlobSidecarList, BlockId, EthSpec, Slot},
    BeaconNodeHttpClient, Timeouts,
};
use sensitive_url::SensitiveUrl;
use slog::{info, warn, Logger};
use ssz::Encode;
use std::time::Duration;

pub async fn export_blobs<E: EthSpec>(config: &ExportBlobs, log: Logger) -> Result<(), String> {
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

    let start_slot = config.start_slot;
    let end_slot = config.end_slot;

    if !config.output_dir.is_dir() {
        return Err("Please set `--output-dir` to a valid directory.".to_string());
    }

    let filename = config
        .output_dir
        .join(format!("{start_slot}_{end_slot}.ssz"));

    // TODO(blob_manager): Ensure node is synced for start_slot -> end_slot.

    let mut blobs_to_export: Vec<BlobSidecarList<E>> = vec![];

    info!(log, "Beginning blob export"; "end_slot" => end_slot, "start_slot" => start_slot, "output_dir" => ?config.output_dir);

    for slot in start_slot..=end_slot {
        if let Some(blobs) = client
            .get_blobs::<E>(BlockId::Slot(Slot::from(slot)), None)
            .await
            .map_err(|e| format!("Failed to export blobs: {e:?}"))?
        {
            let blob_sidecar_list = blobs.data;
            if !blob_sidecar_list.is_empty() {
                blobs_to_export.push(blob_sidecar_list);
            }
        } else {
            // No blobs exist for this slot.
            continue;
        }
    }

    let ssz_bytes = blobs_to_export.as_ssz_bytes();

    // Check blobs exist so we don't create an empty file.
    if !blobs_to_export.is_empty() {
        std::fs::write(&filename, ssz_bytes)
            .map_err(|e| format!("Failed to write blob file: {}", e))?;
        info!(log, "Completed blob export"; "blobs_exported" => blobs_to_export.len());
    } else {
        warn!(log, "No blobs were found for this slot range");
    }

    Ok(())
}
