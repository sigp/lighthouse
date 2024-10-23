use bls::PublicKey;
use slot_clock::SlotClock;
use std::sync::Arc;
use types::{graffiti::GraffitiString, EthSpec, Graffiti};
use validator_store::ValidatorStore;

pub fn get_graffiti<T: 'static + SlotClock + Clone, E: EthSpec>(
    validator_pubkey: PublicKey,
    validator_store: Arc<ValidatorStore<T, E>>,
    graffiti_flag: Option<Graffiti>,
) -> Result<Graffiti, warp::Rejection> {
    let initialized_validators_rw_lock = validator_store.initialized_validators();
    let initialized_validators = initialized_validators_rw_lock.read();
    match initialized_validators.validator(&validator_pubkey.compress()) {
        None => Err(warp_utils::reject::custom_not_found(
            "The key was not found on the server".to_string(),
        )),
        Some(_) => {
            let Some(graffiti) = initialized_validators.graffiti(&validator_pubkey.into()) else {
                return graffiti_flag.ok_or(warp_utils::reject::custom_server_error(
                    "No graffiti found, unable to return the process-wide default".to_string(),
                ));
            };
            Ok(graffiti)
        }
    }
}

pub fn set_graffiti<T: 'static + SlotClock + Clone, E: EthSpec>(
    validator_pubkey: PublicKey,
    graffiti: GraffitiString,
    validator_store: Arc<ValidatorStore<T, E>>,
) -> Result<(), warp::Rejection> {
    let initialized_validators_rw_lock = validator_store.initialized_validators();
    let mut initialized_validators = initialized_validators_rw_lock.write();
    match initialized_validators.validator(&validator_pubkey.compress()) {
        None => Err(warp_utils::reject::custom_not_found(
            "The key was not found on the server, nothing to update".to_string(),
        )),
        Some(initialized_validator) => {
            if initialized_validator.get_graffiti() == Some(graffiti.clone().into()) {
                Ok(())
            } else {
                initialized_validators
                    .set_graffiti(&validator_pubkey, graffiti)
                    .map_err(|_| {
                        warp_utils::reject::custom_server_error(
                            "A graffiti was found, but failed to be updated.".to_string(),
                        )
                    })
            }
        }
    }
}

pub fn delete_graffiti<T: 'static + SlotClock + Clone, E: EthSpec>(
    validator_pubkey: PublicKey,
    validator_store: Arc<ValidatorStore<T, E>>,
) -> Result<(), warp::Rejection> {
    let initialized_validators_rw_lock = validator_store.initialized_validators();
    let mut initialized_validators = initialized_validators_rw_lock.write();
    match initialized_validators.validator(&validator_pubkey.compress()) {
        None => Err(warp_utils::reject::custom_not_found(
            "The key was not found on the server, nothing to delete".to_string(),
        )),
        Some(initialized_validator) => {
            if initialized_validator.get_graffiti().is_none() {
                Ok(())
            } else {
                initialized_validators
                    .delete_graffiti(&validator_pubkey)
                    .map_err(|_| {
                        warp_utils::reject::custom_server_error(
                            "A graffiti was found, but failed to be removed.".to_string(),
                        )
                    })
            }
        }
    }
}
