use crate::validator_store::ValidatorStore;
use bls::{PublicKey, PublicKeyBytes};
use eth2::types::GenericResponse;
use slog::{info, Logger};
use slot_clock::SlotClock;
use std::sync::Arc;
use types::{EthSpec, Graffiti};

pub async fn get_graffiti<T: 'static + SlotClock + Clone, E: EthSpec>(
    pubkey: PublicKey,
    validator_store: Arc<ValidatorStore<T, E>>,
    log: Logger,
) -> Result<Graffiti, warp::Rejection> {
    let Some(graffiti) = validator_store.graffiti(&pubkey.into()) else {
        return Err(warp_utils::reject::custom_server_error(
            "Lighthouse shutting down".into(),
        ));
    };
    Ok(graffiti)
}
