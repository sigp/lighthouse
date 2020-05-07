use crate::helpers::{check_content_type_for_json, publish_beacon_block_to_network};
use crate::response_builder::ResponseBuilder;
use crate::{ApiError, ApiResult, BoxFut, NetworkChannel, UrlQuery};
use beacon_chain::{
    attestation_verification::Error as AttnError, BeaconChain, BeaconChainTypes, BlockError,
    StateSkipConfig,
};
use bls::PublicKeyBytes;
use eth2_libp2p::PubsubMessage;
use futures::{Future, Stream};
use hyper::{Body, Request};
use network::NetworkMessage;
use rayon::prelude::*;
use rest_types::{ValidatorDutiesRequest, ValidatorDutyBytes, ValidatorSubscription};
use slog::{error, info, trace, warn, Logger};
use std::sync::Arc;
use types::beacon_state::EthSpec;
use types::{
    Attestation, AttestationData, BeaconState, Epoch, RelativeEpoch, SelectionProof,
    SignedAggregateAndProof, SignedBeaconBlock, Slot,
};

/// HTTP Handler to retrieve the duties for a set of validators during a particular epoch. This
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

/// HTTP Handler to retrieve subscriptions for a set of validators. This allows the node to
/// organise peer discovery and topic subscription for known validators.
pub fn post_validator_subscriptions<T: BeaconChainTypes>(
    req: Request<Body>,
    mut network_chan: NetworkChannel<T::EthSpec>,
) -> BoxFut {
    try_future!(check_content_type_for_json(&req));
    let response_builder = ResponseBuilder::new(&req);

    let body = req.into_body();
    Box::new(
        body.concat2()
            .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}", e)))
            .and_then(|chunks| {
                serde_json::from_slice(&chunks).map_err(|e| {
                    ApiError::BadRequest(format!(
                        "Unable to parse JSON into ValidatorSubscriptions: {:?}",
                        e
                    ))
                })
            })
            .and_then(move |subscriptions: Vec<ValidatorSubscription>| {
                network_chan
                    .try_send(NetworkMessage::Subscribe { subscriptions })
                    .map_err(|e| {
                        ApiError::ServerError(format!(
                            "Unable to subscriptions to the network: {:?}",
                            e
                        ))
                    })?;
                Ok(())
            })
            .and_then(|_| response_builder?.body_no_ssz(&())),
    )
}

/// HTTP Handler to retrieve all validator duties for the given epoch.
pub fn get_all_validator_duties<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let query = UrlQuery::from_request(&req)?;

    let epoch = query.epoch()?;

    let state = get_state_for_epoch(&beacon_chain, epoch, StateSkipConfig::WithoutStateRoots)?;

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

    let state = get_state_for_epoch(&beacon_chain, epoch, StateSkipConfig::WithoutStateRoots)?;

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
    config: StateSkipConfig,
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

        beacon_chain.state_at_slot(slot, config).map_err(|e| {
            ApiError::ServerError(format!("Unable to load state for epoch {}: {:?}", epoch, e))
        })
    }
}

/// Helper function to get the duties for some `validator_pubkeys` in some `epoch`.
fn return_validator_duties<T: BeaconChainTypes>(
    beacon_chain: Arc<BeaconChain<T>>,
    epoch: Epoch,
    validator_pubkeys: Vec<PublicKeyBytes>,
) -> Result<Vec<ValidatorDutyBytes>, ApiError> {
    let mut state = get_state_for_epoch(&beacon_chain, epoch, StateSkipConfig::WithoutStateRoots)?;

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
            // The `beacon_chain` can return a validator index that does not exist in all states.
            // Therefore, we must check to ensure that the validator index is valid for our
            // `state`.
            let validator_index = beacon_chain
                .validator_index(&validator_pubkey)
                .map_err(|e| {
                    ApiError::ServerError(format!("Unable to get validator index: {:?}", e))
                })?
                .filter(|i| *i < state.validators.len());

            if let Some(validator_index) = validator_index {
                let duties = state
                    .get_attestation_duties(validator_index, relative_epoch)
                    .map_err(|e| {
                        ApiError::ServerError(format!(
                            "Unable to obtain attestation duties: {:?}",
                            e
                        ))
                    })?;

                let aggregator_modulo = duties
                    .map(|duties| SelectionProof::modulo(duties.committee_len, &beacon_chain.spec))
                    .transpose()
                    .map_err(|e| {
                        ApiError::ServerError(format!("Unable to find modulo: {:?}", e))
                    })?;

                let block_proposal_slots = validator_proposers
                    .iter()
                    .filter(|(i, _slot)| validator_index == *i)
                    .map(|(_i, slot)| *slot)
                    .collect();

                Ok(ValidatorDutyBytes {
                    validator_pubkey,
                    validator_index: Some(validator_index as u64),
                    attestation_slot: duties.map(|d| d.slot),
                    attestation_committee_index: duties.map(|d| d.index),
                    attestation_committee_position: duties.map(|d| d.committee_position),
                    block_proposal_slots,
                    aggregator_modulo,
                })
            } else {
                Ok(ValidatorDutyBytes {
                    validator_pubkey,
                    validator_index: None,
                    attestation_slot: None,
                    attestation_committee_index: None,
                    attestation_committee_position: None,
                    block_proposal_slots: vec![],
                    aggregator_modulo: None,
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
    network_chan: NetworkChannel<T::EthSpec>,
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
                    Ok(block_root) => {
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
                    Err(BlockError::BeaconChainError(e)) => {
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
                    Err(other) => {
                        warn!(
                            log,
                            "Invalid block from local validator";
                            "outcome" => format!("{:?}", other)
                        );

                        Err(ApiError::ProcessingError(format!(
                            "The SignedBeaconBlock could not be processed and has not been published: {:?}",
                            other
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
        .produce_unaggregated_attestation(slot, index)
        .map_err(|e| ApiError::BadRequest(format!("Unable to produce attestation: {:?}", e)))?;

    ResponseBuilder::new(&req)?.body(&attestation)
}

/// HTTP Handler to retrieve the aggregate attestation for a slot
pub fn get_aggregate_attestation<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    let query = UrlQuery::from_request(&req)?;

    let attestation_data = query.attestation_data()?;

    match beacon_chain.get_aggregated_attestation(&attestation_data) {
        Ok(Some(attestation)) => ResponseBuilder::new(&req)?.body(&attestation),
        Ok(None) => Err(ApiError::NotFound(
            "No matching aggregate attestation is known".into(),
        )),
        Err(e) => Err(ApiError::ServerError(format!(
            "Unable to obtain attestation: {:?}",
            e
        ))),
    }
}

/// HTTP Handler to publish a list of Attestations, which have been signed by a number of validators.
pub fn publish_attestations<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
    network_chan: NetworkChannel<T::EthSpec>,
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
                        "Unable to deserialize JSON into a list of attestations: {:?}",
                        e
                    ))
                })
            })
            // Process all of the aggregates _without_ exiting early if one fails.
            .map(move |attestations: Vec<Attestation<T::EthSpec>>| {
                attestations
                    .into_par_iter()
                    .enumerate()
                    .map(|(i, attestation)| {
                        process_unaggregated_attestation(
                            &beacon_chain,
                            network_chan.clone(),
                            attestation,
                            i,
                            &log,
                        )
                    })
                    .collect::<Vec<Result<_, _>>>()
            })
            // Iterate through all the results and return on the first `Err`.
            //
            // Note: this will only provide info about the _first_ failure, not all failures.
            .and_then(|processing_results| {
                processing_results.into_iter().try_for_each(|result| result)
            })
            .and_then(|_| response_builder?.body_no_ssz(&())),
    )
}

/// Processes an unaggregrated attestation that was included in a list of attestations with the
/// index `i`.
fn process_unaggregated_attestation<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
    mut network_chan: NetworkChannel<T::EthSpec>,
    attestation: Attestation<T::EthSpec>,
    i: usize,
    log: &Logger,
) -> Result<(), ApiError> {
    let data = &attestation.data.clone();

    // Verify that the attestation is valid to included on the gossip network.
    let verified_attestation = beacon_chain
        .verify_unaggregated_attestation_for_gossip(attestation.clone())
        .map_err(|e| {
            handle_attestation_error(
                e,
                &format!("unaggregated attestation {} failed gossip verification", i),
                data,
                log,
            )
        })?;

    // Publish the attestation to the network
    if let Err(e) = network_chan.try_send(NetworkMessage::Publish {
        messages: vec![PubsubMessage::Attestation(Box::new((
            attestation
                .subnet_id(&beacon_chain.spec)
                .map_err(|e| ApiError::ServerError(format!("Unable to get subnet id: {:?}", e)))?,
            attestation,
        )))],
    }) {
        return Err(ApiError::ServerError(format!(
            "Unable to send unaggregated attestation {} to network: {:?}",
            i, e
        )));
    }

    beacon_chain
        .apply_attestation_to_fork_choice(&verified_attestation)
        .map_err(|e| {
            handle_attestation_error(
                e,
                &format!(
                    "unaggregated attestation {} was unable to be added to fork choice",
                    i
                ),
                data,
                log,
            )
        })?;

    beacon_chain
        .add_to_naive_aggregation_pool(verified_attestation)
        .map_err(|e| {
            handle_attestation_error(
                e,
                &format!(
                    "unaggregated attestation {} was unable to be added to aggregation pool",
                    i
                ),
                data,
                log,
            )
        })?;

    Ok(())
}

/// HTTP Handler to publish an Attestation, which has been signed by a validator.
pub fn publish_aggregate_and_proofs<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
    network_chan: NetworkChannel<T::EthSpec>,
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
                        "Unable to deserialize JSON into a list of SignedAggregateAndProof: {:?}",
                        e
                    ))
                })
            })
            // Process all of the aggregates _without_ exiting early if one fails.
            .map(
                move |signed_aggregates: Vec<SignedAggregateAndProof<T::EthSpec>>| {
                    signed_aggregates
                        .into_par_iter()
                        .enumerate()
                        .map(|(i, signed_aggregate)| {
                            process_aggregated_attestation(
                                &beacon_chain,
                                network_chan.clone(),
                                signed_aggregate,
                                i,
                                &log,
                            )
                        })
                        .collect::<Vec<Result<_, _>>>()
                },
            )
            // Iterate through all the results and return on the first `Err`.
            //
            // Note: this will only provide info about the _first_ failure, not all failures.
            .and_then(|processing_results| {
                processing_results.into_iter().try_for_each(|result| result)
            })
            .and_then(|_| response_builder?.body_no_ssz(&())),
    )
}

/// Processes an aggregrated attestation that was included in a list of attestations with the index
/// `i`.
fn process_aggregated_attestation<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
    mut network_chan: NetworkChannel<T::EthSpec>,
    signed_aggregate: SignedAggregateAndProof<T::EthSpec>,
    i: usize,
    log: &Logger,
) -> Result<(), ApiError> {
    let data = &signed_aggregate.message.aggregate.data.clone();

    // Verify that the attestation is valid to be included on the gossip network.
    //
    // Using this gossip check for local validators is not necessarily ideal, there will be some
    // attestations that we reject that could possibly be included in a block (e.g., attestations
    // that late by more than 1 epoch but less than 2). We can come pick this back up if we notice
    // that it's materially affecting validator profits. Until then, I'm hesitant to introduce yet
    // _another_ attestation verification path.
    let verified_attestation =
        match beacon_chain.verify_aggregated_attestation_for_gossip(signed_aggregate.clone()) {
            Ok(verified_attestation) => verified_attestation,
            Err(AttnError::AttestationAlreadyKnown(attestation_root)) => {
                trace!(
                    log,
                    "Ignored known attn from local validator";
                    "attn_root" => format!("{}", attestation_root)
                );

                // Exit early with success for a known attestation, there's no need to re-process
                // an aggregate we already know.
                return Ok(());
            }
            /*
             * It's worth noting that we don't check for `Error::AggregatorAlreadyKnown` since (at
             * the time of writing) we check for `AttestationAlreadyKnown` first.
             *
             * Given this, it's impossible to hit `Error::AggregatorAlreadyKnown` without that
             * aggregator having already produced a conflicting aggregation. This is not slashable
             * but I think it's still the sort of condition we should error on, at least for now.
             */
            Err(e) => {
                return Err(handle_attestation_error(
                    e,
                    &format!("aggregated attestation {} failed gossip verification", i),
                    data,
                    log,
                ))
            }
        };

    // Publish the attestation to the network
    if let Err(e) = network_chan.try_send(NetworkMessage::Publish {
        messages: vec![PubsubMessage::AggregateAndProofAttestation(Box::new(
            signed_aggregate,
        ))],
    }) {
        return Err(ApiError::ServerError(format!(
            "Unable to send aggregated attestation {} to network: {:?}",
            i, e
        )));
    }

    beacon_chain
        .apply_attestation_to_fork_choice(&verified_attestation)
        .map_err(|e| {
            handle_attestation_error(
                e,
                &format!(
                    "aggregated attestation {} was unable to be added to fork choice",
                    i
                ),
                data,
                log,
            )
        })?;

    beacon_chain
        .add_to_block_inclusion_pool(verified_attestation)
        .map_err(|e| {
            handle_attestation_error(
                e,
                &format!(
                    "aggregated attestation {} was unable to be added to op pool",
                    i
                ),
                data,
                log,
            )
        })?;

    Ok(())
}

/// Common handler for `AttnError` during attestation verification.
fn handle_attestation_error(
    e: AttnError,
    detail: &str,
    data: &AttestationData,
    log: &Logger,
) -> ApiError {
    match e {
        AttnError::BeaconChainError(e) => {
            error!(
                log,
                "Internal error verifying local attestation";
                "detail" => detail,
                "error" => format!("{:?}", e),
                "target" => data.target.epoch,
                "source" => data.source.epoch,
                "index" => data.index,
                "slot" => data.slot,
            );

            ApiError::ServerError(format!(
                "Internal error verifying local attestation. Error: {:?}. Detail: {}",
                e, detail
            ))
        }
        e => {
            error!(
                log,
                "Invalid local attestation";
                "detail" => detail,
                "reason" => format!("{:?}", e),
                "target" => data.target.epoch,
                "source" => data.source.epoch,
                "index" => data.index,
                "slot" => data.slot,
            );

            ApiError::ProcessingError(format!(
                "Invalid local attestation. Error: {:?} Detail: {}",
                e, detail
            ))
        }
    }
}
