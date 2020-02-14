use crate::helpers::{
    check_content_type_for_json, publish_attestation_to_network, publish_beacon_block_to_network,
};
use crate::response_builder::ResponseBuilder;
use crate::{ApiError, ApiResult, BoxFut, NetworkChannel, UrlQuery};
use beacon_chain::{
    AttestationProcessingOutcome, BeaconChain, BeaconChainTypes, BlockProcessingOutcome,
};
use bls::PublicKeyBytes;
use futures::{Future, Stream};
use hyper::{Body, Request};
use serde::{Deserialize, Serialize};
use slog::{error, info, warn, Logger};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use types::beacon_state::EthSpec;
use types::{
    Attestation, BeaconState, CommitteeIndex, Epoch, RelativeEpoch, SignedBeaconBlock, Slot,
};

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct ValidatorDuty {
    /// The validator's BLS public key, uniquely identifying them. _48-bytes, hex encoded with 0x prefix, case insensitive._
    pub validator_pubkey: PublicKeyBytes,
    /// The validator's index in `state.validators`
    pub validator_index: Option<usize>,
    /// The slot at which the validator must attest.
    pub attestation_slot: Option<Slot>,
    /// The index of the committee within `slot` of which the validator is a member.
    pub attestation_committee_index: Option<CommitteeIndex>,
    /// The position of the validator in the committee.
    pub attestation_committee_position: Option<usize>,
    /// The slots in which a validator must propose a block (can be empty).
    pub block_proposal_slots: Vec<Slot>,
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone, Encode, Decode)]
pub struct ValidatorDutiesRequest {
    pub epoch: Epoch,
    pub pubkeys: Vec<PublicKeyBytes>,
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
            serde_json::from_slice::<ValidatorDutiesRequest>(&chunks).map_err(|e| {
                ApiError::BadRequest(format!(
                    "Unable to parse JSON into ValidatorDutiesRequest: {:?}",
                    e
                ))
            })
        })
        .and_then(|bulk_request| {
            return_validator_duties(
                beacon_chain,
                bulk_request.epoch,
                bulk_request.pubkeys.into_iter().map(Into::into).collect(),
            )
        })
        .and_then(|duties| response_builder?.body_no_ssz(&duties));

    Box::new(future)
}

/// HTTP Handler to retrieve all validator duties for the given epoch.
pub fn get_all_validator_duties<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let query = UrlQuery::from_request(&req)?;

    let epoch = query.epoch()?;

    let state = get_state_for_epoch(&beacon_chain, epoch)?;

    let validator_pubkeys = state
        .validators
        .iter()
        .map(|validator| validator.pubkey.clone())
        .collect();

    let duties = return_validator_duties(beacon_chain, epoch, validator_pubkeys)?;

    ResponseBuilder::new(&req)?.body_no_ssz(&duties)
}

/// HTTP Handler to retrieve all active validator duties for the given epoch.
pub fn get_active_validator_duties<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let query = UrlQuery::from_request(&req)?;

    let epoch = query.epoch()?;

    let state = get_state_for_epoch(&beacon_chain, epoch)?;

    let validator_pubkeys = state
        .validators
        .iter()
        .filter(|validator| validator.is_active_at(state.current_epoch()))
        .map(|validator| validator.pubkey.clone())
        .collect();

    let duties = return_validator_duties(beacon_chain, epoch, validator_pubkeys)?;

    ResponseBuilder::new(&req)?.body_no_ssz(&duties)
}

/// Helper function to return the state that can be used to determine the duties for some `epoch`.
pub fn get_state_for_epoch<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
    epoch: Epoch,
) -> Result<BeaconState<T::EthSpec>, ApiError> {
    let slots_per_epoch = T::EthSpec::slots_per_epoch();
    let head_epoch = beacon_chain.head()?.beacon_state.current_epoch();

    if RelativeEpoch::from_epoch(head_epoch, epoch).is_ok() {
        Ok(beacon_chain.head()?.beacon_state)
    } else {
        let slot = if epoch > head_epoch {
            // Move to the first slot of the epoch prior to the request.
            //
            // Taking advantage of saturating epoch subtraction.
            (epoch - 1).start_slot(slots_per_epoch)
        } else {
            // Move to the end of the epoch following the target.
            //
            // Taking advantage of saturating epoch subtraction.
            (epoch + 2).start_slot(slots_per_epoch) - 1
        };

        beacon_chain.state_at_slot(slot).map_err(|e| {
            ApiError::ServerError(format!("Unable to load state for epoch {}: {:?}", epoch, e))
        })
    }
}

/// Helper function to get the duties for some `validator_pubkeys` in some `epoch`.
fn return_validator_duties<T: BeaconChainTypes>(
    beacon_chain: Arc<BeaconChain<T>>,
    epoch: Epoch,
    validator_pubkeys: Vec<PublicKeyBytes>,
) -> Result<Vec<ValidatorDuty>, ApiError> {
    let mut state = get_state_for_epoch(&beacon_chain, epoch)?;

    let relative_epoch = RelativeEpoch::from_epoch(state.current_epoch(), epoch)
        .map_err(|_| ApiError::ServerError(String::from("Loaded state is in the wrong epoch")))?;

    state.update_pubkey_cache()?;
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

                let block_proposal_slots = validator_proposers
                    .iter()
                    .filter(|(i, _slot)| validator_index == *i)
                    .map(|(_i, slot)| *slot)
                    .collect();

                Ok(ValidatorDuty {
                    validator_pubkey,
                    validator_index: Some(validator_index),
                    attestation_slot: duties.map(|d| d.slot),
                    attestation_committee_index: duties.map(|d| d.index),
                    attestation_committee_position: duties.map(|d| d.committee_position),
                    block_proposal_slots,
                })
            } else {
                Ok(ValidatorDuty {
                    validator_pubkey,
                    validator_index: None,
                    attestation_slot: None,
                    attestation_committee_index: None,
                    attestation_committee_position: None,
                    block_proposal_slots: vec![],
                })
            }
        })
        .collect::<Result<Vec<_>, ApiError>>()
}

/// HTTP Handler to produce a new BeaconBlock from the current state, ready to be signed by a validator.
pub fn get_new_beacon_block<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
    log: Logger,
) -> ApiResult {
    let query = UrlQuery::from_request(&req)?;

    let slot = query.slot()?;
    let randao_reveal = query.randao_reveal()?;

    let (new_block, _state) = beacon_chain
        .produce_block(randao_reveal, slot)
        .map_err(|e| {
            error!(
                log,
                "Error whilst producing block";
                "error" => format!("{:?}", e)
            );

            ApiError::ServerError(format!(
                "Beacon node is not able to produce a block: {:?}",
                e
            ))
        })?;

    ResponseBuilder::new(&req)?.body(&new_block)
}

/// HTTP Handler to publish a SignedBeaconBlock, which has been signed by a validator.
pub fn publish_beacon_block<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
    network_chan: NetworkChannel,
    log: Logger,
) -> BoxFut {
    try_future!(check_content_type_for_json(&req));
    let response_builder = ResponseBuilder::new(&req);

    let body = req.into_body();
    Box::new(
        body.concat2()
            .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}", e)))
            .and_then(|chunks| {
                serde_json::from_slice(&chunks).map_err(|e| {
                    ApiError::BadRequest(format!("Unable to parse JSON into SignedBeaconBlock: {:?}", e))
                })
            })
            .and_then(move |block: SignedBeaconBlock<T::EthSpec>| {
                let slot = block.slot();
                match beacon_chain.process_block(block.clone()) {
                    Ok(BlockProcessingOutcome::Processed { block_root }) => {
                        // Block was processed, publish via gossipsub
                        info!(
                            log,
                            "Block from local validator";
                            "block_root" => format!("{}", block_root),
                            "block_slot" => slot,
                        );

                        publish_beacon_block_to_network::<T>(network_chan, block)?;

                        // Run the fork choice algorithm and enshrine a new canonical head, if
                        // found.
                        //
                        // The new head may or may not be the block we just received.
                        if let Err(e) = beacon_chain.fork_choice() {
                            error!(
                                log,
                                "Failed to find beacon chain head";
                                "error" => format!("{:?}", e)
                            );
                        } else {
                            // In the best case, validators should produce blocks that become the
                            // head.
                            //
                            // Potential reasons this may not be the case:
                            //
                            // - A quick re-org between block produce and publish.
                            // - Excessive time between block produce and publish.
                            // - A validator is using another beacon node to produce blocks and
                            // submitting them here.
                            if beacon_chain.head()?.beacon_block_root != block_root {
                                warn!(
                                    log,
                                    "Block from validator is not head";
                                    "desc" => "potential re-org",
                                );

                            }
                        }

                        Ok(())
                    }
                    Ok(outcome) => {
                        warn!(
                            log,
                            "Invalid block from local validator";
                            "outcome" => format!("{:?}", outcome)
                        );

                        Err(ApiError::ProcessingError(format!(
                            "The SignedBeaconBlock could not be processed and has not been published: {:?}",
                            outcome
                        )))
                    }
                    Err(e) => {
                        error!(
                            log,
                            "Error whilst processing block";
                            "error" => format!("{:?}", e)
                        );

                        Err(ApiError::ServerError(format!(
                            "Error while processing block: {:?}",
                            e
                        )))
                    }
                }
        })
        .and_then(|_| response_builder?.body_no_ssz(&()))
    )
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

    Box::new(
        req.into_body()
            .concat2()
            .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}", e)))
            .map(|chunk| chunk.iter().cloned().collect::<Vec<u8>>())
            .and_then(|chunks| {
                serde_json::from_slice(&chunks.as_slice()).map_err(|e| {
                    ApiError::BadRequest(format!(
                        "Unable to deserialize JSON into a SignedBeaconBlock: {:?}",
                        e
                    ))
                })
            })
            .and_then(move |attestation: Attestation<T::EthSpec>| {
                match beacon_chain.process_attestation(attestation.clone()) {
                    Ok(AttestationProcessingOutcome::Processed) => {
                        // Block was processed, publish via gossipsub
                        info!(
                            log,
                            "Attestation from local validator";
                            "target" => attestation.data.source.epoch,
                            "source" => attestation.data.source.epoch,
                            "index" => attestation.data.index,
                            "slot" => attestation.data.slot,
                        );
                        publish_attestation_to_network::<T>(network_chan, attestation)
                    }
                    Ok(outcome) => {
                        warn!(
                            log,
                            "Invalid attestation from local validator";
                            "outcome" => format!("{:?}", outcome)
                        );

                        Err(ApiError::ProcessingError(format!(
                            "The Attestation could not be processed and has not been published: {:?}",
                            outcome
                        )))
                    }
                    Err(e) => {
                        error!(
                            log,
                            "Error whilst processing attestation";
                            "error" => format!("{:?}", e)
                        );

                        Err(ApiError::ServerError(format!(
                            "Error while processing attestation: {:?}",
                            e
                        )))
                    }
                }
            })
            .and_then(|_| response_builder?.body_no_ssz(&())),
    )
}
