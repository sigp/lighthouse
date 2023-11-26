use crate::validator_store::ValidatorStore;
use bls::PublicKey;
use slog::Logger;
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

pub async fn set_graffiti<T: 'static + SlotClock + Clone, E: EthSpec>(
    pubkey: PublicKey,
    graffiti: Graffiti,
    validator_store: Arc<ValidatorStore<T, E>>,
    log: Logger,
) -> Result<(), warp::Rejection> {
    let validators_rw_lock = validator_store.initialized_validators();
    let mut validators = validators_rw_lock.write();
    validators.set_graffiti(&pubkey, graffiti).unwrap();
    Ok(())
}

pub async fn delete_graffiti<T: 'static + SlotClock + Clone, E: EthSpec>(
    pubkey: PublicKey,
    validator_store: Arc<ValidatorStore<T, E>>,
    log: Logger,
) -> Result<(), warp::Rejection> {
    let validators_rw_lock = validator_store.initialized_validators();
    let mut validators = validators_rw_lock.write();
    validators.delete_graffiti(&pubkey).unwrap();
    Ok(())
}
