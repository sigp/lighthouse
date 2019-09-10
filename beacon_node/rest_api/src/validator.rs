use crate::helpers::*;
use crate::{ApiError, ApiResult, UrlQuery};
use beacon_chain::{BeaconChainTypes, BlockProcessingOutcome};
use bls::{AggregateSignature, PublicKey, Signature};
use futures::future::Future;
use futures::stream::Stream;
use hyper::{Body, Error, Request};
use network::NetworkMessage;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use slog::{info, trace, warn};
use std::sync::Arc;
use tokio;
use tokio::sync::mpsc;
use types::beacon_state::EthSpec;
use types::{Attestation, BeaconBlock, BitList, Epoch, RelativeEpoch, Shard, Slot};

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
    let log = get_logger_from_request(&req);
    slog::trace!(log, "Validator duties requested of API: {:?}", &req);
    let (beacon_chain, head_state) = get_beacon_chain_from_request::<T>(&req)?;

    slog::trace!(log, "Got head state from request.");
    // Parse and check query parameters
    let query = UrlQuery::from_request(&req)?;
    let current_epoch = head_state.current_epoch();
    let epoch = match query.first_of(&["epoch"]) {
        Ok((_, v)) => {
            slog::trace!(log, "Requested epoch {:?}", v);
            Epoch::new(v.parse::<u64>().map_err(|e| {
                slog::info!(log, "Invalid epoch {:?}", e);
                ApiError::InvalidQueryParams(format!(
                    "Invalid epoch parameter, must be a u64. {:?}",
                    e
                ))
            })?)
        }
        Err(_) => {
            // epoch not supplied, use the current epoch
            slog::info!(log, "Using default epoch {:?}", current_epoch);
            current_epoch
        }
    };
    let relative_epoch = RelativeEpoch::from_epoch(current_epoch, epoch).map_err(|e| {
        slog::info!(log, "Requested epoch out of range.");
        ApiError::InvalidQueryParams(format!(
            "Cannot get RelativeEpoch, epoch out of range: {:?}",
            e
        ))
    })?;
    let validators: Vec<PublicKey> = query
        .all_of("validator_pubkeys")?
        .iter()
        .map(|pk| parse_pubkey(pk))
        .collect::<Result<Vec<_>, _>>()?;
    let mut duties: Vec<ValidatorDuty> = Vec::new();

    // Update the committee cache
    // TODO: Do we need to update the cache on the state, for the epoch which has been specified?
    beacon_chain
        .state_now()
        .map_err(|e| ApiError::ServerError(format!("Unable to get current BeaconState {:?}", e)))?
        .maybe_as_mut_ref()
        .ok_or(ApiError::ServerError(
            "Unable to get mutable BeaconState".into(),
        ))?
        .build_committee_cache(relative_epoch, &beacon_chain.spec)
        .map_err(|e| ApiError::ServerError(format!("Unable to build state caches: {:?}", e)))?;

    // Get a list of all validators for this epoch
    let validator_proposers: Vec<usize> = epoch
        .slot_iter(T::EthSpec::slots_per_epoch())
        .map(|slot| {
            head_state
                .get_beacon_proposer_index(slot, relative_epoch, &beacon_chain.spec)
                .map_err(|e| {
                    // TODO: why are we getting an uninitialized state error here???
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
    Ok(success_response_old(body))
}

/// HTTP Handler to produce a new BeaconBlock from the current state, ready to be signed by a validator.
pub fn get_new_beacon_block<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let (beacon_chain, _head_state) = get_beacon_chain_from_request::<T>(&req)?;

    let query = UrlQuery::from_request(&req)?;
    let slot = query
        .first_of(&["slot"])
        .map(|(_key, value)| value)?
        .parse::<u64>()
        .map(Slot::from)
        .map_err(|e| {
            ApiError::InvalidQueryParams(format!("Invalid slot parameter, must be a u64. {:?}", e))
        })?;
    let randao_bytes = query
        .first_of(&["randao_reveal"])
        .map(|(_key, value)| value)
        .map(hex::decode)?
        .map_err(|e| {
            ApiError::InvalidQueryParams(format!("Invalid hex string for randao_reveal: {:?}", e))
        })?;
    let randao_reveal = Signature::from_bytes(randao_bytes.as_slice()).map_err(|e| {
        ApiError::InvalidQueryParams(format!("randao_reveal is not a valid signature: {:?}", e))
    })?;

    let (new_block, _state) = beacon_chain
        .produce_block(randao_reveal, slot)
        .map_err(|e| {
            ApiError::ServerError(format!(
                "Beacon node is not able to produce a block: {:?}",
                e
            ))
        })?;

    let body = Body::from(
        serde_json::to_string(&new_block)
            .expect("We should always be able to serialize a new block that we produced."),
    );
    Ok(success_response_old(body))
}

/// HTTP Handler to publish a BeaconBlock, which has been signed by a validator.
pub fn publish_beacon_block<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let _ = check_content_type_for_json(&req)?;
    let log = get_logger_from_request(&req);
    let (beacon_chain, _head_state) = get_beacon_chain_from_request::<T>(&req)?;
    // Get the network sending channel from the request, for later transmission
    let network_chan = req
        .extensions()
        .get::<Arc<RwLock<mpsc::UnboundedSender<NetworkMessage>>>>()
        .expect("Should always get the network channel from the request, since we put it in there.")
        .clone();

    let body = req.into_body();
    trace!(
        log,
        "Got the request body, now going to parse it into a block."
    );
    let block_future = body
        .concat2()
        .map(move |chunk| chunk.iter().cloned().collect::<Vec<u8>>())
        .map(|chunks| {
            let block_result: Result<BeaconBlock<T::EthSpec>, ApiError> =
                serde_json::from_slice(&chunks.as_slice()).map_err(|e| {
                    ApiError::InvalidQueryParams(format!(
                        "Unable to deserialize JSON into a BeaconBlock: {:?}",
                        e
                    ))
                });
            block_result
        });
    let block = block_future.wait()??;
    trace!(log, "BeaconBlock successfully parsed from JSON");
    match beacon_chain.process_block(block.clone()) {
        Ok(BlockProcessingOutcome::Processed { block_root }) => {
            // Block was processed, publish via gossipsub
            info!(log, "Processed valid block from API, transmitting to network."; "block_slot" => block.slot, "block_root" => format!("{}", block_root));
            publish_beacon_block_to_network::<T>(network_chan, block)?;
        }
        Ok(outcome) => {
            warn!(log, "Block could not be processed, but is being sent to the network anyway."; "block_slot" => block.slot, "outcome" => format!("{:?}", outcome));
            //TODO need to send to network and return http 202
            return Err(ApiError::InvalidQueryParams(format!(
                "The BeaconBlock could not be processed: {:?}",
                outcome
            )));
        }
        Err(e) => {
            return Err(ApiError::ServerError(format!(
                "Unable to process block: {:?}",
                e
            )));
        }
    }

    Ok(success_response_old(Body::empty()))
}

/// HTTP Handler to produce a new Attestation from the current state, ready to be signed by a validator.
pub fn get_new_attestation<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let (beacon_chain, head_state) = get_beacon_chain_from_request::<T>(&req)?;

    let query = UrlQuery::from_request(&req)?;
    let val_pk_str = query
        .first_of(&["validator_pubkey"])
        .map(|(_key, value)| value)?;
    let val_pk = parse_pubkey(val_pk_str.as_str())?;

    // Get the validator index from the supplied public key
    // If it does not exist in the index, we cannot continue.
    let val_index = head_state
        .get_validator_index(&val_pk)
        .map_err(|e| {
            ApiError::ServerError(format!("Unable to read validator index cache. {:?}", e))
        })?
        .ok_or(ApiError::InvalidQueryParams(
            "The provided validator public key does not correspond to a validator index.".into(),
        ))?;

    // Get the duties of the validator, to make sure they match up.
    // If they don't have duties this epoch, then return an error
    let val_duty = head_state
        .get_attestation_duties(val_index, RelativeEpoch::Current)
        .map_err(|e| {
            ApiError::ServerError(format!(
                "unable to read cache for attestation duties: {:?}",
                e
            ))
        })?
        .ok_or(ApiError::InvalidQueryParams("No validator duties could be found for the requested validator. Cannot provide valid attestation.".into()))?;

    // Check that we are requesting an attestation during the slot where it is relevant.
    let present_slot = beacon_chain.slot().map_err(|e| ApiError::ServerError(
        format!("Beacon node is unable to determine present slot, either the state isn't generated or the chain hasn't begun. {:?}", e)
    ))?;
    if val_duty.slot != present_slot {
        return Err(ApiError::InvalidQueryParams(format!("Validator is only able to request an attestation during the slot they are allocated. Current slot: {:?}, allocated slot: {:?}", head_state.slot, val_duty.slot)));
    }

    // Parse the POC bit and insert it into the aggregation bits
    let poc_bit = query
        .first_of(&["poc_bit"])
        .map(|(_key, value)| value)?
        .parse::<bool>()
        .map_err(|e| {
            ApiError::InvalidQueryParams(format!("Invalid slot parameter, must be a u64. {:?}", e))
        })?;

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

    // Allow a provided slot parameter to check against the expected slot as a sanity check only.
    // Presently, we don't support attestations at future or past slots.
    let requested_slot = query
        .first_of(&["slot"])
        .map(|(_key, value)| value)?
        .parse::<u64>()
        .map(Slot::from)
        .map_err(|e| {
            ApiError::InvalidQueryParams(format!("Invalid slot parameter, must be a u64. {:?}", e))
        })?;
    let current_slot = beacon_chain.head().beacon_state.slot.as_u64();
    if requested_slot != current_slot {
        return Err(ApiError::InvalidQueryParams(format!("Attestation data can only be requested for the current slot ({:?}), not your requested slot ({:?})", current_slot, requested_slot)));
    }

    let shard = query
        .first_of(&["shard"])
        .map(|(_key, value)| value)?
        .parse::<u64>()
        .map_err(|e| {
            ApiError::InvalidQueryParams(format!("Shard is not a valid u64 value: {:?}", e))
        })?;

    let attestation_data = beacon_chain
        .produce_attestation_data(shard, current_slot.into())
        .map_err(|e| ApiError::ServerError(format!("Could not produce an attestation: {:?}", e)))?;

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
    Ok(success_response_old(body))
}
