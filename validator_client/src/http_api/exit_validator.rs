use crate::beacon_node_fallback::{BeaconNodeFallback, OfflineOnFailure, RequireSynced};
use crate::validator_store::ValidatorStore;
use bls::PublicKeyBytes;
use eth2::types::GenesisData;
use slog::{info, Logger};
use slot_clock::{SlotClock, SystemTimeSlotClock};
use std::sync::Arc;
use std::time::Duration;
use types::{ChainSpec, Epoch, EthSpec, VoluntaryExit};

pub async fn publish_voluntary_exit<T: 'static + SlotClock + Clone, E: EthSpec>(
    pubkey: PublicKeyBytes,
    validator_store: Arc<ValidatorStore<T, E>>,
    beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    spec: Arc<ChainSpec>,
    log: Logger,
) -> Result<(), warp::Rejection> {
    let genesis_data = get_genesis_data(&beacon_nodes).await?;

    // TODO: (jimmy) Verify that the beacon node and validator being exited are on the same network.

    let epoch = get_current_epoch::<E>(genesis_data.genesis_time, spec).ok_or_else(|| {
        warp_utils::reject::custom_server_error("Unable to determine current epoch".to_string())
    })?;

    let validator_index = validator_store.validator_index(&pubkey).ok_or_else(|| {
        warp_utils::reject::custom_server_error(format!(
            "Unable to find validator with public key: {}",
            pubkey.as_hex_string()
        ))
    })?;

    let voluntary_exit = VoluntaryExit {
        epoch,
        validator_index,
    };

    let signed_voluntary_exit = validator_store
        .sign_voluntary_exit(pubkey, voluntary_exit)
        .await
        .map_err(|e| {
            warp_utils::reject::custom_server_error(format!(
                "Failed to sign voluntary exit: {:?}",
                e
            ))
        })?;

    info!(log, "Publishing voluntary exit"; "validator" => pubkey.as_hex_string());

    beacon_nodes
        .first_success(RequireSynced::Yes, OfflineOnFailure::No, |client| async {
            client
                .post_beacon_pool_voluntary_exits(&signed_voluntary_exit)
                .await
        })
        .await
        .map_err(|e| {
            warp_utils::reject::custom_server_error(format!(
                "Failed to publish voluntary exit: {}",
                e
            ))
        })?;

    // TODO: (jimmy) Do we want to wait until the exit to be accepted into the beacon chain?
    // i.e. `validator_status == ActiveExiting`, and return `(current_epoch, exit_epoch, withdrawal_epoch)` to the user?

    Ok(())
}

/// Get genesis data by querying the beacon node client.
async fn get_genesis_data<T: 'static + SlotClock + Clone, E: EthSpec>(
    beacon_nodes: &Arc<BeaconNodeFallback<T, E>>,
) -> Result<GenesisData, warp::Rejection> {
    let genesis_data = beacon_nodes
        .first_success(
            RequireSynced::No,
            OfflineOnFailure::Yes,
            |client| async move { client.get_beacon_genesis().await },
        )
        .await
        .map_err(|e| {
            warp_utils::reject::custom_server_error(format!("Failed to get beacon genesis: {}", e))
        })?
        .data;
    Ok(genesis_data)
}

/// Calculates the current epoch from the genesis time and current time.
fn get_current_epoch<E: EthSpec>(genesis_time: u64, spec: Arc<ChainSpec>) -> Option<Epoch> {
    let slot_clock = SystemTimeSlotClock::new(
        spec.genesis_slot,
        Duration::from_secs(genesis_time),
        Duration::from_secs(spec.seconds_per_slot),
    );
    slot_clock.now().map(|s| s.epoch(E::slots_per_epoch()))
}
