use crate::*;
use itertools::Itertools;
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use slog::{debug, info, Logger};
use slot_clock::SlotClock;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::sleep;
use types::EthSpec;

const BROADCAST_CHUNK_SIZE: usize = 128;
const BROADCAST_CHUNK_DELAY: Duration = Duration::from_millis(500);

#[allow(dead_code)]
pub async fn broadcast_address_changes_at_capella<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    network_send: UnboundedSender<NetworkMessage<T::EthSpec>>,
    log: &Logger,
) {
    let spec = &chain.spec;
    let slot_clock = &chain.slot_clock;

    let capella_fork_slot = if let Some(epoch) = spec.capella_fork_epoch {
        epoch.start_slot(T::EthSpec::slots_per_epoch())
    } else {
        // Exit now if Capella is not defined.
        return;
    };

    // Wait until the Capella fork epoch.
    loop {
        match slot_clock.duration_to_slot(capella_fork_slot) {
            Some(duration) => {
                sleep(duration).await;
                break;
            }
            None => {
                if chain.slot().map_or(false, |slot| slot >= capella_fork_slot) {
                    // The Capella fork has passed, exit now.
                    return;
                }
                // We were unable to read the slot clock, wait another slot and then try again.
                sleep(slot_clock.slot_duration()).await;
            }
        }
    }

    let head = chain.head_snapshot();
    let changes = chain
        .op_pool
        .get_bls_to_execution_changes_for_capella_broadcast(&head.beacon_state, &chain.spec);

    for (i, chunk) in changes
        .into_iter()
        .chunks(BROADCAST_CHUNK_SIZE)
        .into_iter()
        .enumerate()
    {
        let mut num_ok = 0;
        let mut num_err = 0;

        // Wait before publishing the chunk of messages (unless it's the first chunk).
        if i > 0 {
            sleep(BROADCAST_CHUNK_DELAY).await;
        }

        // Publish each individual address change.
        for address_change in chunk {
            let validator_index = address_change.message.validator_index;

            let pubsub_message = PubsubMessage::BlsToExecutionChange(Box::new(address_change));
            let message = NetworkMessage::Publish {
                messages: vec![pubsub_message],
            };
            let publish_result = network_send.send(message);
            if let Err(e) = publish_result {
                debug!(
                    log,
                    "Failed to publish change message";
                    "error" => ?e,
                    "validator_index" => validator_index
                );
                num_err += 1;
            } else {
                num_ok += 1;
            }
        }

        info!(
            log,
            "Published address change messages";
            "num_unable_to_publish" => num_err,
            "num_published" => num_ok,
        )
    }

    debug!(
        log,
        "Address change routine complete";
    );
}
