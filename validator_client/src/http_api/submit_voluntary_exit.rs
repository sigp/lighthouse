use crate::beacon_node_fallback::{BeaconNodeFallback, OfflineOnFailure, RequireSynced};
use crate::validator_store::ValidatorStore;
use bls::{PublicKey, PublicKeyBytes};
use slog::{info, Logger};
use slot_clock::{SlotClock, SystemTimeSlotClock};
use std::sync::Arc;
use std::time::Duration;
use types::{ChainSpec, Epoch, EthSpec, VoluntaryExit};

pub async fn submit_voluntary_exit<T: 'static + SlotClock + Clone, E: EthSpec>(
    pubkey: PublicKey,
    maybe_epoch: Option<Epoch>,
    validator_store: Arc<ValidatorStore<T, E>>,
    spec: Arc<ChainSpec>,
    beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    genesis_time: u64,
    log: Logger,
) -> Result<(), warp::Rejection> {
    let epoch = match maybe_epoch {
        Some(epoch) => epoch,
        None => get_current_epoch::<E>(genesis_time, spec).ok_or_else(|| {
            warp_utils::reject::custom_server_error("Unable to determine current epoch".to_string())
        })?,
    };

    let pubkey_bytes = PublicKeyBytes::from(pubkey);
    let validator_index = validator_store
        .validator_index(&pubkey_bytes)
        .ok_or_else(|| {
            warp_utils::reject::custom_server_error(format!(
                "Unable to find validator with public key: {}",
                pubkey_bytes.as_hex_string()
            ))
        })?;

    let voluntary_exit = VoluntaryExit {
        epoch,
        validator_index,
    };

    let signed_voluntary_exit = validator_store
        .sign_voluntary_exit(pubkey_bytes, voluntary_exit)
        .await
        .map_err(|e| {
            warp_utils::reject::custom_server_error(format!(
                "Failed to sign voluntary exit: {:?}",
                e
            ))
        })?;

    info!(log, "Publishing voluntary exit"; "validator" => pubkey_bytes.as_hex_string());

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

    Ok(())
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
