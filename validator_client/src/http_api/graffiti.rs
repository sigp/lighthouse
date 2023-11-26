use crate::validator_store::ValidatorStore;
use bls::{PublicKey, PublicKeyBytes};
use eth2::types::GenericResponse;
use futures::TryFutureExt;
use serde_json::from_str;
use slog::{info, Logger};
use slot_clock::SlotClock;
use std::{str::FromStr, sync::Arc};
use types::{graffiti::GraffitiString, EthSpec, Graffiti};

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
) -> Result<Graffiti, warp::Rejection> {
    let validators_rw_lock = validator_store.initialized_validators();
    let mut write_validators = validators_rw_lock.write();
    let read_validators = validators_rw_lock.read();

    match (
        read_validators.is_enabled(&pubkey),
        read_validators.validator(&pubkey.compress()),
    ) {
        (None, _) | (Some(_), None) => {
            return Err(warp_utils::reject::custom_not_found(format!(
                "no validator for {:?}",
                pubkey
            )))
        }
        (Some(is_enabled), Some(initialized_validator)) => {
            // TODO unwrap
            write_validators
                .set_validator_definition_fields(
                    initialized_validator.voting_public_key(),
                    Some(is_enabled),
                    initialized_validator.get_gas_limit(),
                    initialized_validator.get_builder_proposals(),
                    Some(GraffitiString::from_str(&graffiti.to_string()).unwrap()),
                )
                .await
                .unwrap();

            return Ok(graffiti);
        }
    };
}
