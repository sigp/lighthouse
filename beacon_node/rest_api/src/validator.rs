use crate::helpers::{
    check_content_type_for_json, parse_pubkey, publish_attestation_to_network,
    publish_beacon_block_to_network,
};
use crate::response_builder::ResponseBuilder;
use crate::{ApiError, ApiResult, BoxFut, NetworkChannel, UrlQuery};
use beacon_chain::{
    AttestationProcessingOutcome, BeaconChain, BeaconChainTypes, BlockProcessingOutcome,
};
use bls::PublicKey;
use futures::future::Future;
use futures::stream::Stream;
use hyper::{Body, Request};
use serde::{Deserialize, Serialize};
use slog::{info, warn, Logger};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use types::beacon_state::EthSpec;
use types::{Attestation, BeaconBlock, CommitteeIndex, Epoch, RelativeEpoch, Slot};

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct ValidatorDuty {
    /// The validator's BLS public key, uniquely identifying them. _48-bytes, hex encoded with 0x prefix, case insensitive._
    pub validator_pubkey: PublicKey,
    /// The slot at which the validator must attest.
    pub attestation_slot: Option<Slot>,
    /// The index of the committee within `slot` of which the validator is a member.
    pub attestation_committee_index: Option<CommitteeIndex>,
    /// The position of the validator in the committee.
    pub attestation_committee_position: Option<usize>,
    /// The slot in which a validator must propose a block, or `null` if block production is not required.
    pub block_proposal_slot: Option<Slot>,
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone, Encode, Decode)]
pub struct BulkValidatorDutiesRequest {
    pub epoch: Epoch,
    pub pubkeys: Vec<PublicKey>,
}

/// HTTP Handler to retrieve a the duties for a set of validators during a particular epoch. This
/// method allows for collecting bulk sets of validator duties without risking exceeding the max
/// URL length with query pairs.
pub fn post_validator_duties<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> BoxFut {
    let response_builder = ResponseBuilder::new(&req);

    let future = req
        .into_body()
        .concat2()
        .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}", e)))
        .and_then(|chunks| {
            serde_json::from_slice::<BulkValidatorDutiesRequest>(&chunks).map_err(|e| {
                ApiError::BadRequest(format!(
                    "Unable to parse JSON into BulkValidatorDutiesRequest: {:?}",
                    e
                ))
            })
        })
        .and_then(|bulk_request| {
            return_validator_duties(beacon_chain, bulk_request.epoch, bulk_request.pubkeys)
        })
        .and_then(|duties| response_builder?.body_no_ssz(&duties));

    Box::new(future)
}

/// HTTP Handler to retrieve a the duties for a set of validators during a particular epoch
///
/// The given `epoch` must be within one epoch of the current epoch.
pub fn get_validator_duties<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let query = UrlQuery::from_request(&req)?;

    let epoch = query.epoch()?;
    let validator_pubkeys = query
        .all_of("validator_pubkeys")?
        .iter()
        .map(|validator_pubkey_str| parse_pubkey(validator_pubkey_str))
        .collect::<Result<_, _>>()?;

    let duties = return_validator_duties(beacon_chain, epoch, validator_pubkeys)?;

    ResponseBuilder::new(&req)?.body_no_ssz(&duties)
}

fn return_validator_duties<T: BeaconChainTypes>(
    beacon_chain: Arc<BeaconChain<T>>,
    epoch: Epoch,
    validator_pubkeys: Vec<PublicKey>,
) -> Result<Vec<ValidatorDuty>, ApiError> {
    let head_state = beacon_chain.head().beacon_state;
    let head_epoch = head_state.current_epoch();

    let relative_epoch = RelativeEpoch::from_epoch(head_epoch, epoch);
    let mut state = if relative_epoch.is_err() {
        head_state
    } else {
        match beacon_chain.state_at_slot(epoch.start_slot(T::EthSpec::slots_per_epoch())) {
            Ok(state) => state,
            Err(e) => {
                return Err(ApiError::ServerError(format!(
                    "Unable to load state for epoch {}: {:?}",
                    epoch, e
                )))
            }
        }
    };

    let relative_epoch = relative_epoch.or_else(|_| {
        RelativeEpoch::from_epoch(state.current_epoch(), epoch).map_err(|_| {
            ApiError::BadRequest(String::from(
                "Epoch must be within one epoch of the current epoch",
            ))
        })
    })?;

    state
        .build_committee_cache(relative_epoch, &beacon_chain.spec)
        .map_err(|e| ApiError::ServerError(format!("Unable to build committee cache: {:?}", e)))?;
    state
        .update_pubkey_cache()
        .map_err(|e| ApiError::ServerError(format!("Unable to build pubkey cache: {:?}", e)))?;

    // Get a list of all validators for this epoch.
    //
    // Used for quickly determining the slot for a proposer.
    let validator_proposers: Vec<(usize, Slot)> = epoch
        .slot_iter(T::EthSpec::slots_per_epoch())
        .map(|slot| {
            state
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

    validator_pubkeys
        .into_iter()
        .map(|validator_pubkey| {
            if let Some(validator_index) =
                state.get_validator_index(&validator_pubkey).map_err(|e| {
                    ApiError::ServerError(format!("Unable to read pubkey cache: {:?}", e))
                })?
            {
                let duties = state
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
                    attestation_committee_position: duties.map(|d| d.committee_position),
                    block_proposal_slot,
                })
            } else {
                Ok(ValidatorDuty {
                    validator_pubkey,
                    attestation_slot: None,
                    attestation_committee_index: None,
                    attestation_committee_position: None,
                    block_proposal_slot: None,
                })
            }
        })
        .collect::<Result<Vec<_>, ApiError>>()
}

/// HTTP Handler to produce a new BeaconBlock from the current state, ready to be signed by a validator.
pub fn get_new_beacon_block<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let query = UrlQuery::from_request(&req)?;

    let slot = query.slot()?;
    let randao_reveal = query.randao_reveal()?;

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
pub fn publish_beacon_block<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
    network_chan: NetworkChannel,
    log: Logger,
) -> BoxFut {
    try_future!(check_content_type_for_json(&req));
    let response_builder = ResponseBuilder::new(&req);

    let body = req.into_body();
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
pub fn get_new_attestation<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let query = UrlQuery::from_request(&req)?;

    let slot = query.slot()?;
    let index = query.committee_index()?;

    let attestation = beacon_chain
        .produce_attestation(slot, index)
        .map_err(|e| ApiError::BadRequest(format!("Unable to produce attestation: {:?}", e)))?;

    ResponseBuilder::new(&req)?.body(&attestation)
}

/// HTTP Handler to publish an Attestation, which has been signed by a validator.
pub fn publish_attestation<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
    network_chan: NetworkChannel,
    log: Logger,
) -> BoxFut {
    try_future!(check_content_type_for_json(&req));
    let response_builder = ResponseBuilder::new(&req);

    Box::new(req
        .into_body()
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
