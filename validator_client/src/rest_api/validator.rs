use super::errors::{ApiError, ApiResult};
use super::response_builder::ResponseBuilder;
use crate::ValidatorStore;
use bls::{PublicKey, PublicKeyBytes, Signature};
use hyper::{body, Body, Request};
use remote_beacon_node::{PublishStatus, RemoteBeaconNode};
use serde_derive::{Deserialize, Serialize};
use slot_clock::SlotClock;
use std::path::PathBuf;
use std::sync::Arc;
use types::{EthSpec, SignedVoluntaryExit, VoluntaryExit};

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct ValidatorRequest {
    pub validator: PublicKey,
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct AddValidatorRequest {
    pub deposit_amount: u64,
    pub directory: Option<PathBuf>,
}

/// Get Validator info of all managed validators.
pub async fn get_validators<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: Arc<ValidatorStore<T, E>>,
    beacon_node: RemoteBeaconNode<E>,
) -> ApiResult {
    let response_builder = ResponseBuilder::new(&req);
    let validators = validator_store.voting_pubkeys();
    beacon_node
        .http
        .beacon()
        .get_validators(validators, None)
        .await
        .map_err(|e| {
            ApiError::ServerError(format!(
                "Failed to get validator info from beacon node: {:?}",
                e
            ))
        })
        .and_then(move |validator_response| response_builder?.body(&validator_response))
}

/// Generates a new validator to the list of managed validators.
/// Takes the deposit amount as a parameter.
/// Returns the voting public keys of the generated validator.
pub async fn add_new_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    let response_builder = ResponseBuilder::new(&req);
    body::to_bytes(req.into_body())
        .await
        .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}", e)))
        .and_then(|chunks| {
            serde_json::from_slice::<AddValidatorRequest>(&chunks).map_err(|e| {
                ApiError::BadRequest(format!(
                    "Unable to parse JSON into ValidatorRequest: {:?}",
                    e
                ))
            })
        })
        .and_then(move |body| {
            let deposit_amount = body.deposit_amount;
            let directory = body.directory;
            todo!("add to validator store")
            /*
            validator_store
                .add_validator(deposit_amount, directory)
                .map_err(|e| ApiError::ServerError(format!("Failed to generate validator: {}", e)))
            */
        })
        .and_then(|pubkey: PublicKey| response_builder?.body(&pubkey))
}

/// Remove a validator from the list of managed validators.
pub async fn remove_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    let response_builder = ResponseBuilder::new(&req);
    body::to_bytes(req.into_body())
        .await
        .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}", e)))
        .and_then(|chunks| {
            serde_json::from_slice::<ValidatorRequest>(&chunks).map_err(|e| {
                ApiError::BadRequest(format!(
                    "Unable to parse JSON into ValidatorRequest: {:?}",
                    e
                ))
            })
        })
        .and_then(move |body| {
            let validator_pubkey = body.validator;
            todo!("remove validator");
            /*
            validator_store
                .remove_validator(&validator_pubkey)
                .ok_or_else(|| ApiError::ServerError("Validator pubkey not present".into()))
            */
        })
        .and_then(|()| response_builder?.body_empty())
}

/// Starts proposing/attesting for the given validator.
/// The validator must already be known by the validator client
pub async fn start_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    let response_builder = ResponseBuilder::new(&req);
    body::to_bytes(req.into_body())
        .await
        .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}", e)))
        .and_then(|chunks| {
            serde_json::from_slice::<ValidatorRequest>(&chunks).map_err(|e| {
                ApiError::BadRequest(format!(
                    "Unable to parse JSON into ValidatorRequest: {:?}",
                    e
                ))
            })
        })
        .and_then(move |body| {
            let validator_pubkey = body.validator;
            todo!("start validator");
            /*
            validator_store
                .set_validator_status(&validator_pubkey, true)
                .ok_or_else(|| ApiError::ServerError("Validator pubkey not present".into()))
            */
        })
        .and_then(|()| response_builder?.body_empty())
}

/// Stops proposing/attesting for the given validator.
/// The validator must already be known by the validator client.
pub async fn stop_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    let response_builder = ResponseBuilder::new(&req);
    body::to_bytes(req.into_body())
        .await
        .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}", e)))
        .and_then(|chunks| {
            serde_json::from_slice::<ValidatorRequest>(&chunks).map_err(|e| {
                ApiError::BadRequest(format!(
                    "Unable to parse JSON into ValidatorRequest: {:?}",
                    e
                ))
            })
        })
        .and_then(move |body| {
            let validator_pubkey = body.validator;
            todo!("stop validator");
            /*
            validator_store
                .set_validator_status(&validator_pubkey, false)
                .ok_or_else(|| ApiError::ServerError("Validator pubkey not present".into()))
            */
        })
        .and_then(|()| response_builder?.body_empty())
}

/// Generates a `VoluntaryExit` message for a given validator and
/// publishes it to the network.
pub async fn exit_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: Arc<ValidatorStore<T, E>>,
    beacon_node: RemoteBeaconNode<E>,
) -> ApiResult {
    let response_builder = ResponseBuilder::new(&req);
    let body = body::to_bytes(req.into_body())
        .await
        .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}", e)))
        .and_then(|chunks| {
            serde_json::from_slice::<ValidatorRequest>(&chunks).map_err(|e| {
                ApiError::BadRequest(format!(
                    "Unable to parse JSON into ValidatorRequest: {:?}",
                    e
                ))
            })
        })?;

    let pk = body.validator;
    let validator_response = beacon_node
        .http
        .beacon()
        .get_validators(vec![pk.clone()], None)
        .await
        .map_err(|e| {
            ApiError::ServerError(format!(
                "Failed to get validator info from beacon node: {:?}",
                e
            ))
        })?;

    let signed_exit = if let Some(validator) = validator_response.first() {
        // Verify public key matches
        let pk_bytes: PublicKeyBytes = pk.clone().into();
        if pk_bytes != validator.pubkey {
            Err(ApiError::ServerError(
                "Invalid public key returned from beacon chain api".into(),
            ))
        }
        // Verify that validator is currently activated
        else if validator.validator_index.is_none() {
            Err(ApiError::ServerError(
                "Validator not active on beacon chain".into(),
            ))
        } else {
            let exit = SignedVoluntaryExit {
                message: VoluntaryExit {
                    epoch: E::default_spec().far_future_epoch,
                    validator_index: validator.validator_index.expect("Should have a value") as u64,
                },
                signature: Signature::empty_signature(),
            };
            let signed_exit = validator_store
                .sign_voluntary_exit(&pk, exit)
                .ok_or_else(|| {
                    ApiError::ProcessingError("Failed to sign voluntary exit message".into())
                })?;
            Ok(signed_exit)
        }
    } else {
        Err(ApiError::ServerError(
            "Invalid public key returned from beacon chain api".into(),
        ))
    }?;

    beacon_node
        .http
        .validator()
        .publish_voluntary_exit(signed_exit)
        .await
        .map(|status| match status {
            PublishStatus::Valid => Ok(()),
            PublishStatus::Invalid(e) => Err(ApiError::ServerError(format!(
                "Failed to publish voluntary exit: {}",
                e
            ))),
            PublishStatus::Unknown => Err(ApiError::ServerError(
                "Failed to publish voluntary exit. Publish status unknown".into(),
            )),
        })
        .map_err(|e| ApiError::ServerError(format!("RemoteBeaconNode api error: {:?}", e)))??;

    response_builder?.body_empty()
}

pub fn _withdraw_validator<T: SlotClock + 'static, E: EthSpec>(
    _req: Request<Body>,
    _validator_store: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    unimplemented!()
}
