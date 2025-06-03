use crate::blobs_manager::{cli::VerifyBlobs, ensure_node_synced, DEFAULT_BEACON_NODE};
use eth2::{
    types::{ChainSpec, EthSpec, Slot},
    BeaconNodeHttpClient, SensitiveUrl, Timeouts,
};
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Debug, PartialEq, Eq)]
enum BlobErrorType {
    Invalid,
    Missing,
}

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

    let (head_slot, is_synced) = ensure_node_synced(&client).await?;
    if !is_synced {
        if config.allow_unsynced {
            warn!("Beacon node is not synced");
        } else {
            return Err("Beacon node is not synced".to_string());
        }
    }

    let deneb_start_slot = if let Some(deneb_fork_epoch) = spec.deneb_fork_epoch {
        deneb_fork_epoch.start_slot(E::slots_per_epoch())
    } else {
        return Err("Deneb fork not set in spec".to_string());
    };

    // I believe this is the blob expiry window.
    let _min_epochs_for_blob_sidecars_requests = spec.min_epochs_for_blob_sidecars_requests;

    // Get start and end slots depending on config,
    let start_slot = config
        .start_slot
        .map(Slot::from)
        .unwrap_or(deneb_start_slot);
    let end_slot = config.end_slot.map(Slot::from).unwrap_or(head_slot);

    let verify = !config.skip_verification;

    if !verify {
        warn!("Skipping verification")
    }

    info!(
        start_slot = start_slot.as_u64(),
        end_slot = end_slot.as_u64(),
        verify,
        "Checking blobs in range"
    );

    let blobs_verification_data = client
        .get_lighthouse_database_verify_blobs(start_slot, end_slot, Some(verify))
        .await
        .map_err(|e| format!("Failed to verify blobs: {e:?}"))?;

    // Total number of individual blobs found (including invalid ones).
    let blob_count = blobs_verification_data.blob_count;
    // Number of slots which contain missing blobs.
    let blobs_missing = blobs_verification_data.blobs_missing.len();
    // Number of slots which contain invalid blobs.
    let blobs_invalid = blobs_verification_data.blobs_invalid.len();

    log_slot_ranges(
        blobs_verification_data.blobs_missing,
        BlobErrorType::Missing,
    );
    log_slot_ranges(
        blobs_verification_data.blobs_invalid,
        BlobErrorType::Invalid,
    );

    info!("Checks complete.");
    info!(
        "Slot range: {}-{}, Number of blobs: {}",
        start_slot.as_u64(),
        end_slot.as_u64(),
        blob_count
    );

    if verify {
        info!("Verification complete.");
        if blobs_invalid == 0 {
            info!("All blobs verified");
        } else {
            error!("Invalid blobs: {}", blobs_invalid);
        }
    }

    if blobs_missing > 0 {
        warn!("Missing blobs: {}", blobs_missing);
    }

    Ok(())
}

fn log_slot_ranges(slots: Vec<u64>, error_type: BlobErrorType) {
    if slots.is_empty() {
        return;
    }

    // This may be unnecessary.
    let mut sorted_slots = slots;
    sorted_slots.sort();

    let mut range_start = sorted_slots[0];
    let mut range_end = sorted_slots[0];

    for &slot in sorted_slots.iter().skip(1) {
        if slot == range_end + 1 {
            range_end = slot;
        } else {
            if range_start == range_end {
                if error_type == BlobErrorType::Invalid {
                    error!("{:?} slot: {}", error_type, range_start);
                } else {
                    warn!("{:?} slot: {}", error_type, range_start);
                }
            } else if error_type == BlobErrorType::Invalid {
                error!("{:?} slot range: {}-{}", error_type, range_start, range_end);
            } else {
                warn!("{:?} slot range: {}-{}", error_type, range_start, range_end);
            }
            range_start = slot;
            range_end = slot;
        }
    }

    // Log the final range.
    if range_start == range_end {
        if error_type == BlobErrorType::Invalid {
            error!("{:?} slot: {}", error_type, range_start);
        } else {
            warn!("{:?} slot: {}", error_type, range_start);
        }
    } else if error_type == BlobErrorType::Invalid {
        error!("{:?} slot range: {}-{}", error_type, range_start, range_end);
    } else {
        warn!("{:?} slot range: {}-{}", error_type, range_start, range_end);
    }
}
