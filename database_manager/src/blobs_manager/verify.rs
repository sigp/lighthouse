use crate::blobs_manager::{cli::VerifyBlobs, DEFAULT_BEACON_NODE};
use beacon_node::ClientConfig;
use eth2::{
    types::{ChainSpec, EthSpec, Slot},
    BeaconNodeHttpClient, SensitiveUrl, Timeouts,
};
use slog::Logger;
use std::time::Duration;

pub async fn verify_blobs<E: EthSpec>(
    config: &VerifyBlobs,
    spec: &ChainSpec,
    log: Logger,
) -> Result<(), String> {
    let beacon_node = SensitiveUrl::parse(
        &config
            .beacon_node
            .clone()
            .unwrap_or(DEFAULT_BEACON_NODE.to_string()),
    )
    .map_err(|e| format!("Unable to parse beacon node url: {e:?}"))?;
    let client = BeaconNodeHttpClient::new(beacon_node, Timeouts::set_all(Duration::from_secs(12)));

    let deneb_start_slot = spec
        .deneb_fork_epoch
        .unwrap() // todo
        .start_slot(E::slots_per_epoch())
        .as_u64();
    let start_slot = config.start_slot.unwrap_or(deneb_start_slot);
    let end_slot = config.end_slot.unwrap();

    if start_slot < deneb_start_slot {
        return Err("Start slot cannot be pre-Deneb".to_string());
    }
    if end_slot < start_slot {
        return Err("End slot cannot be earlier than start slot".to_string());
    }

    let min_epochs_for_blob_sidecars_requests = spec.min_epochs_for_blob_sidecars_requests;

    let slots_verified = 0;

    let response = client
        .get_lighthouse_database_verify_blobs(Slot::from(start_slot), Slot::from(end_slot))
        .await
        .map_err(|e| format!("Failed to verify blobs: {e:?}"))?;

    eprintln!("Response: {:?}", response);

    Ok(())
}
