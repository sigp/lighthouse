use crate::helpers::{
    check_content_type_for_json, parse_epoch, parse_pubkey, parse_signature,
    publish_attestation_to_network, publish_beacon_block_to_network,
};
use crate::response_builder::ResponseBuilder;
use crate::{ApiError, ApiResult, BoxFut, NetworkChannel, UrlQuery};
use beacon_chain::{
    AttestationProcessingOutcome, BeaconChain, BeaconChainTypes, BlockProcessingOutcome,
};
use bls::{AggregateSignature, PublicKey};
use futures::future::Future;
use futures::stream::Stream;
use hyper::{Body, Request};
use serde::{Deserialize, Serialize};
use slog::{info, trace, warn, Logger};
use std::sync::Arc;
use types::beacon_state::EthSpec;
use types::{Attestation, BeaconBlock, BitList, CommitteeIndex, RelativeEpoch, Slot};

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorDuty {
    /// The validator's BLS public key, uniquely identifying them. _48-bytes, hex encoded with 0x prefix, case insensitive._
    pub validator_pubkey: PublicKey,
    /// The slot at which the validator must attest.
    pub attestation_slot: Option<Slot>,
    /// The index of the committee within `slot` of which the validator is a member.
    pub attestation_committee_index: Option<CommitteeIndex>,
    /// The slot in which a validator must propose a block, or `null` if block production is not required.
    pub block_proposal_slot: Option<Slot>,
}

/// HTTP Handler to retrieve a the duties for a set of validators during a particular epoch
///
/// The given `epoch` must be within one epoch of the current epoch.
pub fn get_validator_duties<T: BeaconChainTypes + 'static>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
    log: Logger,
) -> ApiResult {
    slog::trace!(log, "Validator duties requested of API: {:?}", &req);

    let query = UrlQuery::from_request(&req)?;

    let epoch = query
        .first_of(&["epoch"])
        .and_then(|(_key, value)| parse_epoch(&value))?;

    let mut head_state = beacon_chain.head().beacon_state;

    let current_epoch = head_state.current_epoch();
    let relative_epoch = RelativeEpoch::from_epoch(current_epoch, epoch).map_err(|_| {
        ApiError::BadRequest(format!(
            "Epoch must be within one epoch of the current epoch",
        ))
    })?;

    head_state
        .build_committee_cache(relative_epoch, &beacon_chain.spec)
        .map_err(|e| ApiError::ServerError(format!("Unable to build committee cache: {:?}", e)))?;
    head_state
        .update_pubkey_cache()
        .map_err(|e| ApiError::ServerError(format!("Unable to build pubkey cache: {:?}", e)))?;

    // Get a list of all validators for this epoch.
    //
    // Used for quickly determining the slot for a proposer.
    let validator_proposers: Vec<(usize, Slot)> = epoch
        .slot_iter(T::EthSpec::slots_per_epoch())
        .map(|slot| {
            head_state
                .get_beacon_proposer_index(slot, &beacon_chain.spec)
                .map(|i| (i, slot))
                .map_err(|e| {
                    ApiError::ServerError(format!(
                        "Unable to get proposer index for validator: {:?}",
                        e
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let duties = query
        .all_of("validator_pubkeys")?
        .iter()
        .map(|validator_pubkey_str| {
            parse_pubkey(validator_pubkey_str).and_then(|validator_pubkey| {
                if let Some(validator_index) = head_state
                    .get_validator_index(&validator_pubkey)
                    .map_err(|e| {
                        ApiError::ServerError(format!("Unable to read pubkey cache: {:?}", e))
                    })?
                {
                    let duties = head_state
                        .get_attestation_duties(validator_index, relative_epoch)
                        .map_err(|e| {
                            ApiError::ServerError(format!(
                                "Unable to obtain attestation duties: {:?}",
                                e
                            ))
                        })?;

                    let block_proposal_slot = validator_proposers
                        .iter()
                        .find(|(i, _slot)| validator_index == *i)
                        .map(|(_i, slot)| *slot);

                    Ok(ValidatorDuty {
                        validator_pubkey,
                        attestation_slot: duties.map(|d| d.slot),
                        attestation_committee_index: duties.map(|d| d.index),
                        block_proposal_slot,
                    })
                } else {
                    Ok(ValidatorDuty {
                        validator_pubkey,
                        attestation_slot: None,
                        attestation_committee_index: None,
                        block_proposal_slot: None,
                    })
                }
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;

    ResponseBuilder::new(&req)?.body_no_ssz(&duties)
}

/// HTTP Handler to produce a new BeaconBlock from the current state, ready to be signed by a validator.
pub fn get_new_beacon_block<T: BeaconChainTypes + 'static>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let query = UrlQuery::from_request(&req)?;
    let slot = query
        .first_of(&["slot"])
        .map(|(_key, value)| value)?
        .parse::<u64>()
        .map(Slot::from)
        .map_err(|e| {
            ApiError::BadRequest(format!("Invalid slot parameter, must be a u64. {:?}", e))
        })?;
    let randao_reveal = query
        .first_of(&["randao_reveal"])
        .and_then(|(_key, value)| parse_signature(&value))
        .map_err(|e| {
            ApiError::BadRequest(format!("Invalid hex string for randao_reveal: {:?}", e))
        })?;

    let (new_block, _state) = beacon_chain
        .produce_block(randao_reveal, slot)
        .map_err(|e| {
            ApiError::ServerError(format!(
                "Beacon node is not able to produce a block: {:?}",
                e
            ))
        })?;

    ResponseBuilder::new(&req)?.body(&new_block)
}

/// HTTP Handler to publish a BeaconBlock, which has been signed by a validator.
pub fn publish_beacon_block<T: BeaconChainTypes + 'static>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
    network_chan: NetworkChannel,
    log: Logger,
) -> BoxFut {
    try_future!(check_content_type_for_json(&req));
    let response_builder = ResponseBuilder::new(&req);

    let body = req.into_body();
    trace!(
        log,
        "Got the request body, now going to parse it into a block."
    );
    Box::new(body
        .concat2()
        .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}",e)))
        .and_then(|chunks| {
            serde_json::from_slice(&chunks).map_err(|e| ApiError::BadRequest(format!("Unable to parse JSON into BeaconBlock: {:?}",e)))
        })
        .and_then(move |block: BeaconBlock<T::EthSpec>| {
            let slot = block.slot;
            match beacon_chain.process_block(block.clone()) {
                Ok(BlockProcessingOutcome::Processed { block_root }) => {
                    // Block was processed, publish via gossipsub
                    info!(log, "Processed valid block from API, transmitting to network."; "block_slot" => slot, "block_root" => format!("{}", block_root));
                    publish_beacon_block_to_network::<T>(network_chan, block)
                }
                Ok(outcome) => {
                    warn!(log, "BeaconBlock could not be processed, but is being sent to the network anyway."; "outcome" => format!("{:?}", outcome));
                    publish_beacon_block_to_network::<T>(network_chan, block)?;
                    Err(ApiError::ProcessingError(format!(
                        "The BeaconBlock could not be processed, but has still been published: {:?}",
                        outcome
                    )))
                }
                Err(e) => {
                    Err(ApiError::ServerError(format!(
                        "Error while processing block: {:?}",
                        e
                    )))
                }
            }
        }).and_then(|_| {
            response_builder?.body_no_ssz(&())
        }))
}

/// HTTP Handler to produce a new Attestation from the current state, ready to be signed by a validator.
pub fn get_new_attestation<T: BeaconChainTypes + 'static>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let mut head_state = beacon_chain.head().beacon_state;

    let query = UrlQuery::from_request(&req)?;
    let val_pk_str = query
        .first_of(&["validator_pubkey"])
        .map(|(_key, value)| value)?;
    let val_pk = parse_pubkey(val_pk_str.as_str())?;

    head_state
        .update_pubkey_cache()
        .map_err(|e| ApiError::ServerError(format!("Unable to build pubkey cache: {:?}", e)))?;
    // Get the validator index from the supplied public key
    // If it does not exist in the index, we cannot continue.
    let val_index = head_state
        .get_validator_index(&val_pk)
        .map_err(|e| {
            ApiError::ServerError(format!("Unable to read validator index cache. {:?}", e))
        })?
        .ok_or_else(|| {
            ApiError::BadRequest(
                "The provided validator public key does not correspond to a validator index."
                    .into(),
            )
        })?;

    // Build cache for the requested epoch
    head_state
        .build_committee_cache(RelativeEpoch::Current, &beacon_chain.spec)
        .map_err(|e| ApiError::ServerError(format!("Unable to build committee cache: {:?}", e)))?;
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
        .ok_or_else(|| ApiError::BadRequest("No validator duties could be found for the requested validator. Cannot provide valid attestation.".into()))?;

    // Check that we are requesting an attestation during the slot where it is relevant.
    let present_slot = beacon_chain.slot().map_err(|e| ApiError::ServerError(
        format!("Beacon node is unable to determine present slot, either the state isn't generated or the chain hasn't begun. {:?}", e)
    ))?;

    /*
    if val_duty.slot != present_slot {
        return Err(ApiError::BadRequest(format!("Validator is only able to request an attestation during the slot they are allocated. Current slot: {:?}, allocated slot: {:?}", head_state.slot, val_duty.slot)));
    }
    */

    // Parse the POC bit and insert it into the aggregation bits
    let poc_bit = query
        .first_of(&["poc_bit"])
        .map(|(_key, value)| value)?
        .parse::<bool>()
        .map_err(|e| {
            ApiError::BadRequest(format!("Invalid slot parameter, must be a u64. {:?}", e))
        })?;

    let mut aggregation_bits = BitList::with_capacity(val_duty.committee_len).map_err(|e| {
        ApiError::ServerError(format!("Unable to create aggregation bitlist: {:?}", e))
    })?;

    aggregation_bits
        .set(val_duty.committee_position, poc_bit)
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
            ApiError::BadRequest(format!("Invalid slot parameter, must be a u64. {:?}", e))
        })?;
    let current_slot = beacon_chain.head().beacon_state.slot.as_u64();
    if requested_slot != current_slot {
        return Err(ApiError::BadRequest(format!("Attestation data can only be requested for the current slot ({:?}), not your requested slot ({:?})", current_slot, requested_slot)));
    }

    let index = query
        .first_of(&["index"])
        .map(|(_key, value)| value)?
        .parse::<u64>()
        .map_err(|e| ApiError::BadRequest(format!("Index is not a valid u64 value: {:?}", e)))?;

    let attestation_data = beacon_chain
        .produce_attestation_data(current_slot.into(), index)
        .map_err(|e| ApiError::ServerError(format!("Could not produce an attestation: {:?}", e)))?;

    let attestation: Attestation<T::EthSpec> = Attestation {
        aggregation_bits,
        data: attestation_data,
        signature: AggregateSignature::new(),
    };

    ResponseBuilder::new(&req)?.body(&attestation)
}

/// HTTP Handler to publish an Attestation, which has been signed by a validator.
pub fn publish_attestation<T: BeaconChainTypes + 'static>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
    network_chan: NetworkChannel,
    log: Logger,
) -> BoxFut {
    try_future!(check_content_type_for_json(&req));
    let response_builder = ResponseBuilder::new(&req);

    let body = req.into_body();
    trace!(
        log,
        "Got the request body, now going to parse it into an attesation."
    );
    Box::new(body
        .concat2()
        .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}",e)))
        .map(|chunk| chunk.iter().cloned().collect::<Vec<u8>>())
        .and_then(|chunks| {
            serde_json::from_slice(&chunks.as_slice()).map_err(|e| {
                ApiError::BadRequest(format!(
                    "Unable to deserialize JSON into a BeaconBlock: {:?}",
                    e
                ))
            })
        })
        .and_then(move |attestation: Attestation<T::EthSpec>| {
            match beacon_chain.process_attestation(attestation.clone()) {
                Ok(AttestationProcessingOutcome::Processed) => {
                    // Block was processed, publish via gossipsub
                    info!(log, "Processed valid attestation from API, transmitting to network.");
                    publish_attestation_to_network::<T>(network_chan, attestation)
                }
                Ok(outcome) => {
                    warn!(log, "Attestation could not be processed, but is being sent to the network anyway."; "outcome" => format!("{:?}", outcome));
                    publish_attestation_to_network::<T>(network_chan, attestation)?;
                    Err(ApiError::ProcessingError(format!(
                        "The Attestation could not be processed, but has still been published: {:?}",
                        outcome
                    )))
                }
                Err(e) => {
                    Err(ApiError::ServerError(format!(
                        "Error while processing attestation: {:?}",
                        e
                    )))
                }
            }
        }).and_then(|_| {
        response_builder?.body_no_ssz(&())
    }))
}
