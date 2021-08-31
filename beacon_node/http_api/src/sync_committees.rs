//! Handlers for sync committee endpoints.

use crate::publish_pubsub_message;
use beacon_chain::sync_committee_verification::{
    Error as SyncVerificationError, VerifiedSyncCommitteeMessage,
};
use beacon_chain::{
    validator_monitor::timestamp_now, BeaconChain, BeaconChainError, BeaconChainTypes,
    StateSkipConfig, MAXIMUM_GOSSIP_CLOCK_DISPARITY,
};
use eth2::types::{self as api_types};
use eth2_libp2p::PubsubMessage;
use network::NetworkMessage;
use slog::{error, warn, Logger};
use slot_clock::SlotClock;
use std::cmp::max;
use std::collections::HashMap;
use tokio::sync::mpsc::UnboundedSender;
use types::{
    slot_data::SlotData, BeaconStateError, Epoch, EthSpec, SignedContributionAndProof,
    SyncCommitteeMessage, SyncDuty, SyncSubnetId,
};

/// The struct that is returned to the requesting HTTP client.
type SyncDuties = api_types::GenericResponse<Vec<SyncDuty>>;

/// Handles a request from the HTTP API for sync committee duties.
pub fn sync_committee_duties<T: BeaconChainTypes>(
    request_epoch: Epoch,
    request_indices: &[u64],
    chain: &BeaconChain<T>,
) -> Result<SyncDuties, warp::reject::Rejection> {
    let altair_fork_epoch = if let Some(altair_fork_epoch) = chain.spec.altair_fork_epoch {
        altair_fork_epoch
    } else {
        // Empty response for networks with Altair disabled.
        return Ok(convert_to_response(vec![]));
    };

    // Try using the head's sync committees to satisfy the request. This should be sufficient for
    // the vast majority of requests. Rather than checking if we think the request will succeed in a
    // way prone to data races, we attempt the request immediately and check the error code.
    match chain.sync_committee_duties_from_head(request_epoch, request_indices) {
        Ok(duties) => return Ok(convert_to_response(duties)),
        Err(BeaconChainError::SyncDutiesError(BeaconStateError::SyncCommitteeNotKnown {
            ..
        }))
        | Err(BeaconChainError::SyncDutiesError(BeaconStateError::IncorrectStateVariant)) => (),
        Err(e) => return Err(warp_utils::reject::beacon_chain_error(e)),
    }

    let duties = duties_from_state_load(request_epoch, request_indices, altair_fork_epoch, chain)
        .map_err(|e| match e {
        BeaconChainError::SyncDutiesError(BeaconStateError::SyncCommitteeNotKnown {
            current_epoch,
            ..
        }) => warp_utils::reject::custom_bad_request(format!(
            "invalid epoch: {}, current epoch: {}",
            request_epoch, current_epoch
        )),
        e => warp_utils::reject::beacon_chain_error(e),
    })?;
    Ok(convert_to_response(duties))
}

/// Slow path for duties: load a state and use it to compute the duties.
fn duties_from_state_load<T: BeaconChainTypes>(
    request_epoch: Epoch,
    request_indices: &[u64],
    altair_fork_epoch: Epoch,
    chain: &BeaconChain<T>,
) -> Result<Vec<Option<SyncDuty>>, BeaconChainError> {
    // Determine what the current epoch would be if we fast-forward our system clock by
    // `MAXIMUM_GOSSIP_CLOCK_DISPARITY`.
    //
    // Most of the time, `tolerant_current_epoch` will be equal to `current_epoch`. However, during
    // the last `MAXIMUM_GOSSIP_CLOCK_DISPARITY` duration of the epoch `tolerant_current_epoch`
    // will equal `current_epoch + 1`
    let current_epoch = chain.epoch()?;
    let tolerant_current_epoch = chain
        .slot_clock
        .now_with_future_tolerance(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
        .ok_or(BeaconChainError::UnableToReadSlot)?
        .epoch(T::EthSpec::slots_per_epoch());

    let max_sync_committee_period = tolerant_current_epoch.sync_committee_period(&chain.spec)? + 1;
    let sync_committee_period = request_epoch.sync_committee_period(&chain.spec)?;

    if tolerant_current_epoch < altair_fork_epoch {
        // Empty response if the epoch is pre-Altair.
        Ok(vec![])
    } else if sync_committee_period <= max_sync_committee_period {
        // Load the state at the start of the *previous* sync committee period.
        // This is sufficient for historical duties, and efficient in the case where the head
        // is lagging the current epoch and we need duties for the next period (because we only
        // have to transition the head to start of the current period).
        //
        // We also need to ensure that the load slot is after the Altair fork.
        let load_slot = max(
            chain.spec.epochs_per_sync_committee_period * sync_committee_period.saturating_sub(1),
            altair_fork_epoch,
        )
        .start_slot(T::EthSpec::slots_per_epoch());

        let state = chain.state_at_slot(load_slot, StateSkipConfig::WithoutStateRoots)?;

        state
            .get_sync_committee_duties(request_epoch, request_indices, &chain.spec)
            .map_err(BeaconChainError::SyncDutiesError)
    } else {
        Err(BeaconChainError::SyncDutiesError(
            BeaconStateError::SyncCommitteeNotKnown {
                current_epoch,
                epoch: request_epoch,
            },
        ))
    }
}

fn convert_to_response(duties: Vec<Option<SyncDuty>>) -> SyncDuties {
    api_types::GenericResponse::from(duties.into_iter().flatten().collect::<Vec<_>>())
}

/// Receive sync committee duties, storing them in the pools & broadcasting them.
pub fn process_sync_committee_signatures<T: BeaconChainTypes>(
    sync_committee_signatures: Vec<SyncCommitteeMessage>,
    network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
    chain: &BeaconChain<T>,
    log: Logger,
) -> Result<(), warp::reject::Rejection> {
    let mut failures = vec![];

    let seen_timestamp = timestamp_now();

    for (i, sync_committee_signature) in sync_committee_signatures.iter().enumerate() {
        let subnet_positions = match get_subnet_positions_for_sync_committee_message(
            sync_committee_signature,
            chain,
        ) {
            Ok(positions) => positions,
            Err(e) => {
                error!(
                    log,
                    "Unable to compute subnet positions for sync message";
                    "error" => ?e,
                    "slot" => sync_committee_signature.slot,
                );
                failures.push(api_types::Failure::new(i, format!("Verification: {:?}", e)));
                continue;
            }
        };

        // Verify and publish on all relevant subnets.
        //
        // The number of assigned subnets on any practical network should be ~1, so the apparent
        // inefficiency of verifying multiple times is not a real inefficiency.
        let mut verified_for_pool = None;
        for subnet_id in subnet_positions.keys().copied() {
            match VerifiedSyncCommitteeMessage::verify(
                sync_committee_signature.clone(),
                subnet_id,
                chain,
            ) {
                Ok(verified) => {
                    publish_pubsub_message(
                        &network_tx,
                        PubsubMessage::SyncCommitteeMessage(Box::new((
                            subnet_id,
                            verified.sync_message().clone(),
                        ))),
                    )?;

                    // Register with validator monitor
                    chain
                        .validator_monitor
                        .read()
                        .register_api_sync_committee_message(
                            seen_timestamp,
                            verified.sync_message(),
                            &chain.slot_clock,
                        );

                    verified_for_pool = Some(verified);
                }
                Err(e) => {
                    error!(
                        log,
                        "Failure verifying sync committee signature for gossip";
                        "error" => ?e,
                        "request_index" => i,
                        "slot" => sync_committee_signature.slot,
                        "validator_index" => sync_committee_signature.validator_index,
                    );
                    failures.push(api_types::Failure::new(i, format!("Verification: {:?}", e)));
                }
            }
        }

        if let Some(verified) = verified_for_pool {
            if let Err(e) = chain.add_to_naive_sync_aggregation_pool(verified) {
                error!(
                    log,
                    "Unable to add sync committee signature to pool";
                    "error" => ?e,
                    "slot" => sync_committee_signature.slot,
                    "validator_index" => sync_committee_signature.validator_index,
                );
            }
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(warp_utils::reject::indexed_bad_request(
            "error processing sync committee signatures".to_string(),
            failures,
        ))
    }
}

/// Get the set of all subnet assignments for a `SyncCommitteeMessage`.
pub fn get_subnet_positions_for_sync_committee_message<T: BeaconChainTypes>(
    sync_message: &SyncCommitteeMessage,
    chain: &BeaconChain<T>,
) -> Result<HashMap<SyncSubnetId, Vec<usize>>, SyncVerificationError> {
    let pubkey = chain
        .validator_pubkey_bytes(sync_message.validator_index as usize)?
        .ok_or(SyncVerificationError::UnknownValidatorIndex(
            sync_message.validator_index as usize,
        ))?;
    let sync_committee = chain.sync_committee_at_next_slot(sync_message.get_slot())?;
    Ok(sync_committee.subcommittee_positions_for_public_key(&pubkey)?)
}

/// Receive signed contributions and proofs, storing them in the op pool and broadcasting.
pub fn process_signed_contribution_and_proofs<T: BeaconChainTypes>(
    signed_contribution_and_proofs: Vec<SignedContributionAndProof<T::EthSpec>>,
    network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
    chain: &BeaconChain<T>,
    log: Logger,
) -> Result<(), warp::reject::Rejection> {
    let mut verified_contributions = Vec::with_capacity(signed_contribution_and_proofs.len());
    let mut failures = vec![];

    let seen_timestamp = timestamp_now();

    // Verify contributions & broadcast to the network.
    for (index, contribution) in signed_contribution_and_proofs.into_iter().enumerate() {
        let aggregator_index = contribution.message.aggregator_index;
        let subcommittee_index = contribution.message.contribution.subcommittee_index;
        let contribution_slot = contribution.message.contribution.slot;

        match chain.verify_sync_contribution_for_gossip(contribution) {
            Ok(verified_contribution) => {
                publish_pubsub_message(
                    &network_tx,
                    PubsubMessage::SignedContributionAndProof(Box::new(
                        verified_contribution.aggregate().clone(),
                    )),
                )?;

                // Register with validator monitor
                chain
                    .validator_monitor
                    .read()
                    .register_api_sync_committee_contribution(
                        seen_timestamp,
                        verified_contribution.aggregate(),
                        verified_contribution.participant_pubkeys(),
                        &chain.slot_clock,
                    );

                verified_contributions.push((index, verified_contribution));
            }
            // If we already know the contribution, don't broadcast it or attempt to
            // further verify it. Return success.
            Err(SyncVerificationError::SyncContributionAlreadyKnown(_)) => continue,
            Err(e) => {
                error!(
                    log,
                    "Failure verifying signed contribution and proof";
                    "error" => ?e,
                    "request_index" => index,
                    "aggregator_index" => aggregator_index,
                    "subcommittee_index" => subcommittee_index,
                    "contribution_slot" => contribution_slot,
                );
                failures.push(api_types::Failure::new(
                    index,
                    format!("Verification: {:?}", e),
                ));
            }
        }
    }

    // Add to the block inclusion pool.
    for (index, verified_contribution) in verified_contributions {
        if let Err(e) = chain.add_contribution_to_block_inclusion_pool(verified_contribution) {
            warn!(
                log,
                "Could not add verified sync contribution to the inclusion pool";
                "error" => ?e,
                "request_index" => index,
            );
            failures.push(api_types::Failure::new(index, format!("Op pool: {:?}", e)));
        }
    }

    if !failures.is_empty() {
        Err(warp_utils::reject::indexed_bad_request(
            "error processing contribution and proofs".to_string(),
            failures,
        ))
    } else {
        Ok(())
    }
}
