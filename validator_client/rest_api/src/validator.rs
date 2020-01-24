use super::errors::{ApiError, ApiResult, BoxFut};
use super::response_builder::ResponseBuilder;
use bls::{PublicKey, PublicKeyBytes, Signature};
use futures::future::Future;
use futures::stream::Stream;
use hyper::{Body, Request};
use remote_beacon_node::{PublishStatus, RemoteBeaconNode};
use serde_derive::{Deserialize, Serialize};
use slot_clock::SlotClock;
use std::sync::Arc;
use types::{EthSpec, VoluntaryExit};
use validator_store::ValidatorStore;

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct ValidatorRequest {
    pub validator: PublicKey,
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct AddValidatorRequest {
    pub deposit_amount: u64,
}

/// Get Validator info of all managed validators.
pub fn get_validators<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: Arc<ValidatorStore<T, E>>,
    beacon_node: Arc<RemoteBeaconNode<E>>,
) -> BoxFut {
    let response_builder = ResponseBuilder::new(&req);
    let validators = validator_store.voting_pubkeys();
    let future = beacon_node
        .http
        .beacon()
        .get_validators(validators, None)
        .map_err(|e| {
            ApiError::ServerError(format!(
                "Failed to get validator info from beacon node: {:?}",
                e
            ))
        })
        .and_then(move |validator_response| response_builder?.body(&validator_response));
    Box::new(future)
}

/// Generates a new validator to the list of managed validators.
/// Takes the deposit amount as a parameter.
/// Returns the voting public keys of the generated validator.
pub fn add_new_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: Arc<ValidatorStore<T, E>>,
) -> BoxFut {
    let response_builder = ResponseBuilder::new(&req);
    let future = req
        .into_body()
        .concat2()
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
            validator_store
                .add_validator(deposit_amount)
                .map_err(|e| ApiError::ServerError(format!("Failed to generate validator: {}", e)))
        })
        .and_then(|pubkey| response_builder?.body(&pubkey));
    Box::new(future)
}

/// Remove a validator from the list of managed validators.
pub fn remove_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: Arc<ValidatorStore<T, E>>,
) -> BoxFut {
    let response_builder = ResponseBuilder::new(&req);
    let future = req
        .into_body()
        .concat2()
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
            validator_store
                .remove_validator(&validator_pubkey)
                .ok_or(ApiError::ServerError(format!(
                    "Validator pubkey not present"
                )))
        })
        .and_then(|_| response_builder?.body_empty());
    Box::new(future)
}

/// Starts proposing/attesting for the given validator.
/// The validator must already be known by the validator client
pub fn start_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: Arc<ValidatorStore<T, E>>,
) -> BoxFut {
    let response_builder = ResponseBuilder::new(&req);
    let future = req
        .into_body()
        .concat2()
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
            validator_store
                .set_validator_status(&validator_pubkey, true)
                .ok_or(ApiError::ServerError(format!(
                    "Validator pubkey not present"
                )))
        })
        .and_then(|_| response_builder?.body_empty());
    Box::new(future)
}

/// Stops proposing/attesting for the given validator.
/// The validator must already be known by the validator client.
pub fn stop_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: Arc<ValidatorStore<T, E>>,
) -> BoxFut {
    let response_builder = ResponseBuilder::new(&req);
    let future = req
        .into_body()
        .concat2()
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
            validator_store
                .set_validator_status(&validator_pubkey, false)
                .ok_or(ApiError::ServerError(format!(
                    "Validator pubkey not present"
                )))
        })
        .and_then(|_| response_builder?.body_empty());
    Box::new(future)
}

pub fn exit_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: Arc<ValidatorStore<T, E>>,
    beacon_node: Arc<RemoteBeaconNode<E>>,
) -> BoxFut {
    let response_builder = ResponseBuilder::new(&req);
    let bn1 = beacon_node.clone();
    let bn2 = beacon_node.clone();
    let future = req
        .into_body()
        .concat2()
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
            let validator_pubkey = body.validator.clone();
            bn1.http
                .beacon()
                .get_validators(vec![validator_pubkey.clone()], None)
                .map(|resp| (resp, validator_pubkey))
                .map_err(|e| {
                    ApiError::ServerError(format!(
                        "Failed to get validator info from beacon node: {:?}",
                        e
                    ))
                })
        })
        .and_then(move |(validator_response, pk)| {
            if let Some(validator) = validator_response.first() {
                // Verify public key matches
                let pk_bytes: PublicKeyBytes = pk.clone().into();
                if pk_bytes != validator.pubkey {
                    Err(ApiError::ServerError(format!(
                        "Invalid public key returned from beacon chain api"
                    )))
                }
                // Verify that validator is currently activated
                else if validator.validator_index.is_none() {
                    Err(ApiError::ServerError(format!(
                        "Validator not active on beacon chain"
                    )))
                } else {
                    let exit = VoluntaryExit {
                        epoch: E::default_spec().far_future_epoch,
                        validator_index: validator.validator_index.expect("Should have a value")
                            as u64,
                        signature: Signature::empty_signature(),
                    };
                    let signed_exit = validator_store.sign_voluntary_exit(&pk, exit).ok_or(
                        ApiError::ProcessingError(format!("Failed to sign voluntary exit message")),
                    )?;
                    Ok(signed_exit)
                }
            } else {
                Err(ApiError::ServerError(format!(
                    "Invalid public key returned from beacon chain api"
                )))
            }
        })
        .and_then(move |signed_exit| {
            bn2.http
                .validator()
                .publish_voluntary_exit(signed_exit)
                .map(|status| match status {
                    PublishStatus::Valid => Ok(()),
                    PublishStatus::Invalid(e) => Err(ApiError::ServerError(format!(
                        "Failed to publish voluntary exit: {}",
                        e
                    ))),
                    PublishStatus::Unknown => Err(ApiError::ServerError(format!(
                        "Failed to publish voluntary exit. Publish status unknown"
                    ))),
                })
                .map_err(|e| ApiError::ServerError(format!("RemoteBeaconNode api error: {:?}", e)))
        })
        .and_then(|_| response_builder?.body_empty());
    Box::new(future)
}

pub fn withdraw_validator<T: SlotClock + 'static, E: EthSpec>(
    _req: Request<Body>,
    _validator_store: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    unimplemented!()
}
