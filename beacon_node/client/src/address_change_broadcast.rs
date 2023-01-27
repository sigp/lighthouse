use crate::*;
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use slog::{debug, info, Logger};
use slot_clock::SlotClock;
use std::cmp;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::sleep;
use types::EthSpec;

/// The size of each chunk of addresses changes to be broadcast at the Capella
/// fork.
const BROADCAST_CHUNK_SIZE: usize = 128;
/// The delay between broadcasting each chunk.
const BROADCAST_CHUNK_DELAY: Duration = Duration::from_millis(500);

/// Waits until the Capella fork epoch and then publishes any bls to execution
/// address changes which were placed in the pool prior to the fork.
///
/// Does nothing if the Capella fork has already happened.
///
/// Address changes are published in chunks, with a delay between each chunk.
/// This helps reduce the load on the P2P network and also helps prevent us from
/// clogging our `network_send` channel and being late to publish
/// blocks, attestations, etc.
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
    let mut changes = chain
        .op_pool
        .get_bls_to_execution_changes_for_capella_broadcast(&head.beacon_state, &chain.spec);

    loop {
        if changes.is_empty() {
            break;
        }
        // This `split_off` approach is to allow us to have owned chunks of the
        // `changes` vec. The `itertools` iterator that achives this isn't
        // `Send` so it doesn't work well with the `sleep` at the end of the
        // loop.
        let chunk = changes.split_off(cmp::min(BROADCAST_CHUNK_SIZE, changes.len()));

        let mut num_ok = 0;
        let mut num_err = 0;

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
        );

        sleep(BROADCAST_CHUNK_DELAY).await;
    }

    // Forget all the indices that should be broadcast at the Capella fork.
    // This means that any future calls to this function will have no effect.
    chain.op_pool.drop_capella_broadcast_indices();

    debug!(
        log,
        "Address change routine complete";
    );
}
