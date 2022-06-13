use crate::metrics;
use beacon_chain::validator_monitor::{get_block_delay_ms, timestamp_now};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use slog::{crit, debug, error, info, Logger};
use slot_clock::SlotClock;
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tree_hash::TreeHash;
use types::{
    BeaconBlockAltair, BeaconBlockBase, BeaconBlockBodyAltair, BeaconBlockBodyBase,
    BeaconBlockBodyMerge, BeaconBlockMerge, BlindedPayload, ExecutionBlockHash, ExecutionPayload,
    ExecutionPayloadHeader, FullPayload, SignedBeaconBlock, SignedBeaconBlockAltair,
    SignedBeaconBlockBase, SignedBeaconBlockMerge,
};
use warp::Rejection;

/// Handles a request from the HTTP API for full blocks.
pub fn publish_block<T: BeaconChainTypes>(
    block: SignedBeaconBlock<T::EthSpec>,
    chain: Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    log: Logger,
) -> Result<(), Rejection> {
    let seen_timestamp = timestamp_now();

    // Send the block, regardless of whether or not it is valid. The API
    // specification is very clear that this is the desired behaviour.
    crate::publish_pubsub_message(
        network_tx,
        PubsubMessage::BeaconBlock(Box::new(block.clone())),
    )?;

    // Determine the delay after the start of the slot, register it with metrics.
    let delay = get_block_delay_ms(seen_timestamp, block.message(), &chain.slot_clock);
    metrics::observe_duration(&metrics::HTTP_API_BLOCK_BROADCAST_DELAY_TIMES, delay);

    match chain.process_block(block.clone()) {
        Ok(root) => {
            info!(
                log,
                "Valid block from HTTP API";
                "block_delay" => ?delay,
                "root" => format!("{}", root),
                "proposer_index" => block.message().proposer_index(),
                "slot" => block.slot(),
            );

            // Notify the validator monitor.
            chain.validator_monitor.read().register_api_block(
                seen_timestamp,
                block.message(),
                root,
                &chain.slot_clock,
            );

            // Update the head since it's likely this block will become the new
            // head.
            chain
                .fork_choice()
                .map_err(warp_utils::reject::beacon_chain_error)?;

            // Perform some logging to inform users if their blocks are being produced
            // late.
            //
            // Check to see the thresholds are non-zero to avoid logging errors with small
            // slot times (e.g., during testing)
            let crit_threshold = chain.slot_clock.unagg_attestation_production_delay();
            let error_threshold = crit_threshold / 2;
            if delay >= crit_threshold {
                crit!(
                    log,
                    "Block was broadcast too late";
                    "msg" => "system may be overloaded, block likely to be orphaned",
                    "delay_ms" => delay.as_millis(),
                    "slot" => block.slot(),
                    "root" => ?root,
                )
            } else if delay >= error_threshold {
                error!(
                    log,
                    "Block broadcast was delayed";
                    "msg" => "system may be overloaded, block may be orphaned",
                    "delay_ms" => delay.as_millis(),
                    "slot" => block.slot(),
                    "root" => ?root,
                )
            }

            Ok(())
        }
        Err(e) => {
            let msg = format!("{:?}", e);
            error!(
                log,
                "Invalid block provided to HTTP API";
                "reason" => &msg
            );
            Err(warp_utils::reject::broadcast_without_import(msg))
        }
    }
}

/// Handles a request from the HTTP API for blinded blocks. This converts blinded blocks into full
/// blocks before publishing.
pub fn publish_blinded_block<T: BeaconChainTypes>(
    block: SignedBeaconBlock<T::EthSpec, BlindedPayload<T::EthSpec>>,
    chain: Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    log: Logger,
) -> Result<(), Rejection> {
    let full_block = reconstruct_block(chain.clone(), block, log.clone())?;
    publish_block::<T>(full_block, chain, network_tx, log)
}

/// Deconstruct the given blinded block, and construct a full block. This attempts to use the
/// execution layer's payload cache, and if that misses, attempts a blind block proposal to retrieve
/// the full payload.
fn reconstruct_block<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block: SignedBeaconBlock<T::EthSpec, BlindedPayload<T::EthSpec>>,
    log: Logger,
) -> Result<SignedBeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>, Rejection> {
    let block_clone = block.clone();
    let full_block = match block {
        SignedBeaconBlock::Base(b) => {
            let SignedBeaconBlockBase { message, signature } = b;

            let BeaconBlockBase {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body,
            } = message;

            let BeaconBlockBodyBase {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                _phantom,
            } = body;

            SignedBeaconBlock::Base(SignedBeaconBlockBase {
                message: BeaconBlockBase {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body: BeaconBlockBodyBase {
                        randao_reveal,
                        eth1_data,
                        graffiti,
                        proposer_slashings,
                        attester_slashings,
                        attestations,
                        deposits,
                        voluntary_exits,
                        _phantom: PhantomData::default(),
                    },
                },
                signature,
            })
        }
        SignedBeaconBlock::Altair(b) => {
            let SignedBeaconBlockAltair { message, signature } = b;

            let BeaconBlockAltair {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body,
            } = message;

            let BeaconBlockBodyAltair {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                sync_aggregate,
                _phantom,
            } = body;

            let full_body = BeaconBlockBodyAltair {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                sync_aggregate,
                _phantom: PhantomData::default(),
            };

            SignedBeaconBlock::Altair(SignedBeaconBlockAltair {
                message: BeaconBlockAltair {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body: full_body,
                },
                signature,
            })
        }
        SignedBeaconBlock::Merge(b) => {
            let SignedBeaconBlockMerge { message, signature } = b;

            let BeaconBlockMerge {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body,
            } = message;

            let BeaconBlockBodyMerge {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                sync_aggregate,
                execution_payload,
            } = body;

            let payload_root = execution_payload.tree_hash_root();

            let BlindedPayload {
                execution_payload_header,
            } = execution_payload;

            debug!(log, "Blinded payload before reconstruction"; "execution_payload_header" => ?execution_payload_header);

            let ExecutionPayloadHeader {
                parent_hash,
                fee_recipient,
                state_root: payload_state_root,
                receipts_root,
                logs_bloom,
                prev_randao,
                block_number,
                gas_limit,
                gas_used,
                timestamp,
                extra_data,
                base_fee_per_gas,
                block_hash,
                transactions_root: _transactions_root,
            } = execution_payload_header;

            let el = chain.execution_layer.as_ref().ok_or_else(|| {
                warp_utils::reject::custom_server_error("Missing execution layer".to_string())
            })?;

            // If the execution block hash is zero, use an empty payload.
            let full_payload = if block_hash == ExecutionBlockHash::zero() {
                ExecutionPayload::default()
            // If we already have an execution payload with this transactions root cached, use it.
            } else if let Some(cached_payload) = el.get_payload_by_root(&payload_root) {
                cached_payload
            // Otherwise, this means we are attempting a blind block proposal.
            } else {
                el.block_on(|el| el.propose_blinded_beacon_block(&block_clone))
                    .map_err(|e| {
                        warp_utils::reject::custom_server_error(format!(
                            "Blind block proposal failed: {:?}",
                            e
                        ))
                    })?
            };

            SignedBeaconBlock::Merge(SignedBeaconBlockMerge {
                message: BeaconBlockMerge {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body: BeaconBlockBodyMerge {
                        randao_reveal,
                        eth1_data,
                        graffiti,
                        proposer_slashings,
                        attester_slashings,
                        attestations,
                        deposits,
                        voluntary_exits,
                        sync_aggregate,
                        execution_payload: FullPayload {
                            execution_payload: ExecutionPayload {
                                parent_hash,
                                fee_recipient,
                                state_root: payload_state_root,
                                receipts_root,
                                logs_bloom,
                                prev_randao,
                                block_number,
                                gas_limit,
                                gas_used,
                                timestamp,
                                extra_data,
                                base_fee_per_gas,
                                block_hash,
                                transactions: full_payload.transactions,
                            },
                        },
                    },
                },
                signature,
            })
        }
    };
    Ok(full_block)
}
