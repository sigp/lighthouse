use super::{success_response, ApiResult};
use crate::{helpers::*, ApiError, UrlQuery};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use bls::PublicKey;
use hyper::{Body, Request};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use store::Store;
use types::{BeaconBlock, BeaconState, Epoch};

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorDuty {
    /// The validator's BLS public key, uniquely identifying them. _48-bytes, hex encoded with 0x prefix, case insensitive._
    #[serde(rename = "validator_pubkey")]
    pub validator_pubkey: String,
    /// The slot at which the validator must attest.
    #[serde(rename = "attestation_slot")]
    pub attestation_slot: Option<i32>,
    /// The shard in which the validator must attest.
    #[serde(rename = "attestation_shard")]
    pub attestation_shard: Option<i32>,
    /// The slot in which a validator must propose a block, or `null` if block production is not required.
    #[serde(rename = "block_proposal_slot")]
    pub block_proposal_slot: Option<i32>,
}

impl ValidatorDuty {
    pub fn new() -> ValidatorDuty {
        ValidatorDuty {
            validator_pubkey: "".to_string(),
            attestation_slot: None,
            attestation_shard: None,
            block_proposal_slot: None,
        }
    }
}

/// HTTP Handler to retrieve a the duties for a set of validators during a particular epoch
pub fn get_validator_duties<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    // Get beacon state
    let beacon_chain = req
        .extensions()
        .get::<Arc<BeaconChain<T>>>()
        .ok_or_else(|| ApiError::ServerError("Beacon chain extension missing".to_string()))?;
    let head_state = &beacon_chain.head().beacon_state;

    // Parse and check query parameters
    let query = UrlQuery::from_request(&req)?;
    let queried_epoch = match query.first_of(&["epoch"]) {
        Ok((k, v)) => Epoch::new(v.parse::<u64>().map_err(|e| {
            ApiError::InvalidQueryParams(format!("Invalid epoch parameter, must be a u64. {:?}", e))
        })?),
        Err(e) => {
            // epoch not supplied, use the current epoch
            beacon_chain.head().beacon_state.current_epoch()
        }
    };
    //TODO: Handle an array of validators, currently only takes one
    let mut queried_validators = match query.first_of(&["validator_pubkeys"]) {
        Ok((k, v)) => parse_pubkey(&v)?,
        Err(e) => {
            return Err(e);
        }
    };
    let mut validators = vec![queried_validators];
    let mut duties: Vec<ValidatorDuty> = Vec::new();

    // Look up duties for each validator
    for val_pk in validators {
        let mut duty = ValidatorDuty::new();

        let val_index_opt = match head_state.get_validator_index(&val_pk) {
            Ok(i) => i,
            Err(e) => {
                return Err(ApiError::ServerError(format!(
                    "Unable to read validator index cache. {:?}",
                    e
                )));
            }
        };

        //TODO add the 0x again?
        duty.validator_pubkey = hex::encode(val_pk.as_bytes());

        duties.append(&mut vec![duty]);
    }
    let body = Body::from(
        serde_json::to_string(&duties)
            .expect("We should always be able to serialize the duties we created."),
    );
    Ok(success_response(body))
}
