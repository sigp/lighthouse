use crate::validator_store::ValidatorStore;
use bls::{PublicKey, PublicKeyBytes};
use slog::{info, Logger};
use slot_clock::SlotClock;
use std::sync::Arc;
use types::{Epoch, EthSpec, SignedVoluntaryExit, VoluntaryExit};

pub async fn create_signed_voluntary_exit<T: 'static + SlotClock + Clone, E: EthSpec>(
    pubkey: PublicKey,
    epoch: Epoch,
    validator_store: Arc<ValidatorStore<T, E>>,
    log: Logger,
) -> Result<SignedVoluntaryExit, warp::Rejection> {
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

    info!(log, "Signing voluntary exit"; "validator" => pubkey_bytes.as_hex_string());

    let signed_voluntary_exit = validator_store
        .sign_voluntary_exit(pubkey_bytes, voluntary_exit)
        .await
        .map_err(|e| {
            warp_utils::reject::custom_server_error(format!(
                "Failed to sign voluntary exit: {:?}",
                e
            ))
        })?;

    Ok(signed_voluntary_exit)
}
