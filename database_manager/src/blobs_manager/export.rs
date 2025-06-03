use crate::blobs_manager::{cli::ExportBlobs, ensure_node_synced};
use eth2::{
    types::{BlobSidecarList, BlockId, ChainSpec, Epoch, EthSpec, Slot},
    BeaconNodeHttpClient, Timeouts,
};
use sensitive_url::SensitiveUrl;
use ssz::Encode;
use std::time::Duration;
use tracing::{info, warn};

#[derive(PartialEq, Eq)]
enum ExportMode {
    Epochs,
    Slots,
}

impl std::fmt::Display for ExportMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportMode::Epochs => write!(f, "epoch"),
            ExportMode::Slots => write!(f, "slot"),
        }
    }
}

pub async fn export_blobs<E: EthSpec>(
    config: &ExportBlobs,
    spec: &ChainSpec,
) -> Result<(), String> {
    let beacon_node = SensitiveUrl::parse(&config.beacon_node)
        .map_err(|e| format!("Unable to parse beacon node url: {e:?}"))?;

    let client = BeaconNodeHttpClient::new(beacon_node, Timeouts::set_all(Duration::from_secs(12)));

    let (_, is_synced) = ensure_node_synced(&client).await?;
    if !is_synced {
        if config.allow_unsynced {
            warn!("Beacon node is not synced");
        } else {
            return Err("Beacon node is not synced".to_string());
        }
    }

    // Ensure Deneb fork is enabled.
    let deneb_fork_epoch = if let Some(deneb_fork_epoch) = spec.deneb_fork_epoch {
        deneb_fork_epoch.as_u64()
    } else {
        return Err("Deneb fork epoch not set in chain spec".to_string());
    };

    let mut export_mode = ExportMode::Epochs;

    // Export either epochs or slots. Defaults to epochs.
    let start = if let Some(start_epoch) = config.start_epoch {
        start_epoch
    } else if let Some(start_slot) = config.start_slot {
        // Since start_slot and start_epoch are mutually exclusive, we can safely assume that we are in slot mode.
        export_mode = ExportMode::Slots;
        start_slot
    } else {
        deneb_fork_epoch
    };

    let end = if let Some(end_epoch) = config.end_epoch {
        end_epoch
    } else if let Some(end_slot) = config.end_slot {
        end_slot
    } else {
        return Err(format!("End {export_mode} not set"));
    };

    if end <= start {
        return Err(format!(
            "End {export_mode} must be greater than start {export_mode}"
        ));
    }

    // Ensure start is at or after Deneb fork
    if export_mode == ExportMode::Epochs {
        if start < deneb_fork_epoch {
            return Err(format!(
                "Start epoch {} is before Deneb fork epoch {}",
                start, deneb_fork_epoch
            ));
        }
    } else {
        let deneb_start_slot = Epoch::new(deneb_fork_epoch)
            .start_slot(E::slots_per_epoch())
            .as_u64();
        if start < deneb_start_slot {
            return Err(format!(
                "Start slot {} is before Deneb fork start slot {}",
                start, deneb_start_slot
            ));
        }
    }

    if !config.output_dir.is_dir() {
        return Err("Please set `--output-dir` to a valid directory.".to_string());
    }

    let filename = config.output_dir.join(format!("{start}_{end}.ssz"));

    // TODO(blob_manager): Ensure node is synced for start_slot -> end_slot.

    let mut blobs_to_export: Vec<BlobSidecarList<E>> = vec![];

    // Generate start and end slots for each mode.
    let (start_slot, end_slot) = if export_mode == ExportMode::Epochs {
        info!(start_epoch = start, end_epoch = end, output_dir = ?config.output_dir, "Beginning blob export");
        (
            Epoch::new(start).start_slot(E::slots_per_epoch()).as_u64(),
            Epoch::new(end).end_slot(E::slots_per_epoch()).as_u64(),
        )
    } else {
        info!(start_slot = start, end_slot = end, output_dir = ?config.output_dir, "Beginning blob export");
        (start, end)
    };

    for slot in start_slot..=end_slot {
        if let Some(blobs) = client
            .get_blobs::<E>(BlockId::Slot(Slot::from(slot)), None, spec)
            .await
            .map_err(|e| format!("Failed to export blobs: {e:?}"))?
        {
            let blob_sidecar_list = blobs.into_data();
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
        info!(
            blobs_exported = blobs_to_export.len(),
            "Completed blob export"
        );
    } else {
        warn!("No blobs were found for this {} range", export_mode);
    }

    Ok(())
}
