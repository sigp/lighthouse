use super::{success_response, ApiResult};
use crate::{helpers::*, ApiError, UrlQuery};
use beacon_chain::BeaconChainTypes;
use bls::{AggregateSignature, PublicKey, Signature};
use hyper::{Body, Request};
use serde::{Deserialize, Serialize};
use types::beacon_state::EthSpec;
use types::{Attestation, BitList, Epoch, RelativeEpoch, Shard, Slot};

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorDuty {
    /// The validator's BLS public key, uniquely identifying them. _48-bytes, hex encoded with 0x prefix, case insensitive._
    pub validator_pubkey: String,
    /// The slot at which the validator must attest.
    pub attestation_slot: Option<Slot>,
    /// The shard in which the validator must attest.
    pub attestation_shard: Option<Shard>,
    /// The slot in which a validator must propose a block, or `null` if block production is not required.
    pub block_proposal_slot: Option<Slot>,
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
    let beacon_chain = get_beacon_chain_from_request::<T>(&req)?;
    let head_state = &beacon_chain.head().beacon_state;

    // Parse and check query parameters
    let query = UrlQuery::from_request(&req)?;
    let current_epoch = head_state.current_epoch();
    let epoch = match query.first_of(&["epoch"]) {
        Ok((_, v)) => Epoch::new(v.parse::<u64>().map_err(|e| {
            ApiError::InvalidQueryParams(format!("Invalid epoch parameter, must be a u64. {:?}", e))
        })?),
        Err(_) => {
            // epoch not supplied, use the current epoch
            current_epoch
        }
    };
    let relative_epoch = RelativeEpoch::from_epoch(current_epoch, epoch).map_err(|e| {
        ApiError::InvalidQueryParams(format!(
            "Cannot get RelativeEpoch, epoch out of range: {:?}",
            e
        ))
    })?;
    let validators: Vec<PublicKey> = match query.all_of("validator_pubkeys") {
        Ok(v) => v
            .iter()
            .map(|pk| parse_pubkey(pk))
            .collect::<Result<Vec<_>, _>>()?,
        Err(e) => {
            return Err(e);
        }
    };
    let mut duties: Vec<ValidatorDuty> = Vec::new();

    // Get a list of all validators for this epoch
    let validator_proposers: Vec<usize> = epoch
        .slot_iter(T::EthSpec::slots_per_epoch())
        .map(|slot| {
            head_state
                .get_beacon_proposer_index(slot, relative_epoch, &beacon_chain.spec)
                .map_err(|e| {
                    ApiError::ServerError(format!(
                        "Unable to get proposer index for validator: {:?}",
                        e
                    ))
                })
        })
        .collect::<Result<Vec<usize>, _>>()?;

    // Look up duties for each validator
    for val_pk in validators {
        let mut duty = ValidatorDuty::new();
        duty.validator_pubkey = val_pk.as_hex_string();

        // Get the validator index
        // If it does not exist in the index, just add a null duty and move on.
        let val_index: usize = match head_state.get_validator_index(&val_pk) {
            Ok(Some(i)) => i,
            Ok(None) => {
                duties.append(&mut vec![duty]);
                continue;
            }
            Err(e) => {
                return Err(ApiError::ServerError(format!(
                    "Unable to read validator index cache. {:?}",
                    e
                )));
            }
        };

        // Set attestation duties
        match head_state.get_attestation_duties(val_index, relative_epoch) {
            Ok(Some(d)) => {
                duty.attestation_slot = Some(d.slot);
                duty.attestation_shard = Some(d.shard);
            }
            Ok(None) => {}
            Err(e) => {
                return Err(ApiError::ServerError(format!(
                    "unable to read cache for attestation duties: {:?}",
                    e
                )))
            }
        };

        // If the validator is to propose a block, identify the slot
        if let Some(slot) = validator_proposers.iter().position(|&v| val_index == v) {
            duty.block_proposal_slot = Some(Slot::new(
                relative_epoch
                    .into_epoch(current_epoch)
                    .start_slot(T::EthSpec::slots_per_epoch())
                    .as_u64()
                    + slot as u64,
            ));
        }

        duties.append(&mut vec![duty]);
    }
    let body = Body::from(
        serde_json::to_string(&duties)
            .expect("We should always be able to serialize the duties we created."),
    );
    Ok(success_response(body))
}

/// HTTP Handler to produce a new BeaconBlock from the current state, ready to be signed by a validator.
pub fn get_new_beacon_block<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let beacon_chain = get_beacon_chain_from_request::<T>(&req)?;

    let query = UrlQuery::from_request(&req)?;
    let slot = match query.first_of(&["slot"]) {
        Ok((_, v)) => Slot::new(v.parse::<u64>().map_err(|e| {
            ApiError::InvalidQueryParams(format!("Invalid slot parameter, must be a u64. {:?}", e))
        })?),
        Err(e) => {
            return Err(e);
        }
    };
    let randao_reveal = match query.first_of(&["randao_reveal"]) {
        Ok((_, v)) => Signature::from_bytes(
            hex::decode(&v)
                .map_err(|e| {
                    ApiError::InvalidQueryParams(format!(
                        "Invalid hex string for randao_reveal: {:?}",
                        e
                    ))
                })?
                .as_slice(),
        )
        .map_err(|e| {
            ApiError::InvalidQueryParams(format!("randao_reveal is not a valid signature: {:?}", e))
        })?,
        Err(e) => {
            return Err(e);
        }
    };

    let new_block = match beacon_chain.produce_block(randao_reveal, slot) {
        Ok((block, _state)) => block,
        Err(e) => {
            return Err(ApiError::ServerError(format!(
                "Beacon node is not able to produce a block: {:?}",
                e
            )));
        }
    };

    let body = Body::from(
        serde_json::to_string(&new_block)
            .expect("We should always be able to serialize a new block that we produced."),
    );
    Ok(success_response(body))
}

/// HTTP Handler to accept a validator-signed BeaconBlock, and publish it to the network.
pub fn publish_beacon_block<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let beacon_chain = get_beacon_chain_from_request::<T>(&req)?;

    let query = UrlQuery::from_request(&req)?;
    let slot = match query.first_of(&["slot"]) {
        Ok((_, v)) => Slot::new(v.parse::<u64>().map_err(|e| {
            ApiError::InvalidQueryParams(format!("Invalid slot parameter, must be a u64. {:?}", e))
        })?),
        Err(e) => {
            return Err(e);
        }
    };
    let randao_reveal = match query.first_of(&["randao_reveal"]) {
        Ok((_, v)) => Signature::from_bytes(
            hex::decode(&v)
                .map_err(|e| {
                    ApiError::InvalidQueryParams(format!(
                        "Invalid hex string for randao_reveal: {:?}",
                        e
                    ))
                })?
                .as_slice(),
        )
        .map_err(|e| {
            ApiError::InvalidQueryParams(format!("randao_reveal is not a valid signature: {:?}", e))
        })?,
        Err(e) => {
            return Err(e);
        }
    };

    let new_block = match beacon_chain.produce_block(randao_reveal, slot) {
        Ok((block, _state)) => block,
        Err(e) => {
            return Err(ApiError::ServerError(format!(
                "Beacon node is not able to produce a block: {:?}",
                e
            )));
        }
    };

    let body = Body::from(
        serde_json::to_string(&new_block)
            .expect("We should always be able to serialize a new block that we produced."),
    );
    Ok(success_response(body))
}

/// HTTP Handler to produce a new Attestation from the current state, ready to be signed by a validator.
pub fn get_new_attestation<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let beacon_chain = get_beacon_chain_from_request::<T>(&req)?;
    let head_state = &beacon_chain.head().beacon_state;

    let query = UrlQuery::from_request(&req)?;
    let val_pk: PublicKey = match query.first_of(&["validator_pubkey"]) {
        Ok((_, v)) => parse_pubkey(v.as_str())?,
        Err(e) => {
            return Err(e);
        }
    };
    // Get the validator index from the supplied public key
    // If it does not exist in the index, we cannot continue.
    let val_index: usize = match head_state.get_validator_index(&val_pk) {
        Ok(Some(i)) => i,
        Ok(None) => {
            return Err(ApiError::InvalidQueryParams(
                "The provided validator public key does not correspond to a validator index."
                    .into(),
            ));
        }
        Err(e) => {
            return Err(ApiError::ServerError(format!(
                "Unable to read validator index cache. {:?}",
                e
            )));
        }
    };
    // Get the duties of the validator, to make sure they match up.
    // If they don't have duties this epoch, then return an error
    let val_duty = match head_state.get_attestation_duties(val_index, RelativeEpoch::Current) {
        Ok(Some(d)) => d,
        Ok(None) => {
            return Err(ApiError::InvalidQueryParams("No validator duties could be found for the requested validator. Cannot provide valid attestation.".into()));
        }
        Err(e) => {
            return Err(ApiError::ServerError(format!(
                "unable to read cache for attestation duties: {:?}",
                e
            )))
        }
    };

    // Check that we are requesting an attestation during the slot where it is relevant.
    let present_slot = match beacon_chain.read_slot_clock() {
        Some(s) => s,
        None => {
            return Err(ApiError::ServerError(
                "Beacon node is unable to determine present slot, either the state isn't generated or the chain hasn't begun.".into()
            ));
        }
    };
    if val_duty.slot != present_slot {
        return Err(ApiError::InvalidQueryParams(format!("Validator is only able to request an attestation during the slot they are allocated. Current slot: {:?}, allocated slot: {:?}", head_state.slot, val_duty.slot)));
    }

    // Parse the POC bit and insert it into the aggregation bits
    let poc_bit: bool = match query.first_of(&["poc_bit"]) {
        Ok((_, v)) => v.parse::<bool>().map_err(|e| {
            ApiError::InvalidQueryParams(format!("poc_bit is not a valid boolean value: {:?}", e))
        })?,
        Err(e) => {
            return Err(e);
        }
    };
    let mut aggregation_bits = BitList::with_capacity(val_duty.committee_len)
        .expect("An empty BitList should always be created, or we have bigger problems.");
    aggregation_bits
        .set(val_duty.committee_index, poc_bit)
        .map_err(|e| {
            ApiError::ServerError(format!(
                "Unable to set aggregation bits for the attestation: {:?}",
                e
            ))
        })?;

    // Allow a provided slot parameter to check against the expected slot as a sanity check.
    // Presently, we don't support attestations at future or past slots.
    let _slot = match query.first_of(&["slot"]) {
        Ok((_, v)) => {
            let requested_slot = v.parse::<u64>().map_err(|e| {
                ApiError::InvalidQueryParams(format!(
                    "Invalid slot parameter, must be a u64. {:?}",
                    e
                ))
            })?;
            let current_slot = beacon_chain.head().beacon_state.slot.as_u64();
            if requested_slot != current_slot {
                return Err(ApiError::InvalidQueryParams(format!("Attestation data can only be requested for the current slot ({:?}), not your requested slot ({:?})", current_slot, requested_slot)));
            }
            Slot::new(requested_slot)
        }
        Err(ApiError::InvalidQueryParams(_)) => {
            // Just fill _slot with a dummy value for now, making the slot parameter optional
            // We'll get the real slot from the ValidatorDuty
            Slot::new(0)
        }
        Err(e) => {
            return Err(e);
        }
    };

    let shard: Shard = match query.first_of(&["shard"]) {
        Ok((_, v)) => v.parse::<u64>().map_err(|e| {
            ApiError::InvalidQueryParams(format!("Shard is not a valid u64 value: {:?}", e))
        })?,
        Err(e) => {
            // This is a mandatory parameter, return the error
            return Err(e);
        }
    };
    let attestation_data = match beacon_chain.produce_attestation_data(shard) {
        Ok(v) => v,
        Err(e) => {
            return Err(ApiError::ServerError(format!(
                "Could not produce an attestation: {:?}",
                e
            )));
        }
    };

    let attestation: Attestation<T::EthSpec> = Attestation {
        aggregation_bits,
        data: attestation_data,
        custody_bits: BitList::with_capacity(val_duty.committee_len)
            .expect("Should be able to create an empty BitList for the custody bits."),
        signature: AggregateSignature::new(),
    };

    let body = Body::from(
        serde_json::to_string(&attestation)
            .expect("We should always be able to serialize a new attestation that we produced."),
    );
    Ok(success_response(body))
}
