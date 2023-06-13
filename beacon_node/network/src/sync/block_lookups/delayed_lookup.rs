use crate::sync::SyncMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use slog::{crit, warn};
use slot_clock::SlotClock;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::interval_at;
use tokio::time::Instant;
use types::Hash256;

#[derive(Debug)]
pub enum DelayedLookupMessage {
    /// A lookup for all components of a block or blob seen over gossip.
    MissingComponents(Hash256),
}

/// This service is responsible for collecting lookup messages and sending them back to sync
/// for processing after a short delay.
///
/// We want to delay lookups triggered from gossip for the following reasons:
///
/// - We only want to make one request for components we are unlikely to see on gossip. This means
///   we don't have to repeatedly update our RPC request's state as we receive gossip components.
///
/// - We are likely to receive blocks/blobs over gossip more quickly than we could via an RPC request.
///
/// - Delaying a lookup means we are less likely to simultaneously download the same blocks/blobs
///   over gossip and RPC.
///
/// - We would prefer to request peers based on whether we've seen them attest, because this gives
///   us an idea about whether they *should* have the block/blobs we're missing. This is because a
///   node should not attest to a block unless it has all the blobs for that block. This gives us a
///   stronger basis for peer scoring.
pub fn spawn_delayed_lookup_service<T: BeaconChainTypes>(
    executor: &task_executor::TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    mut delayed_lookups_recv: mpsc::Receiver<DelayedLookupMessage>,
    sync_send: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
    log: slog::Logger,
) {
    executor.spawn(
        async move {
            let slot_duration = beacon_chain.slot_clock.slot_duration();
            let delay = beacon_chain.slot_clock.single_lookup_delay();
            let interval_start = match (
                beacon_chain.slot_clock.duration_to_next_slot(),
                beacon_chain.slot_clock.seconds_from_current_slot_start(),
            ) {
                (Some(duration_to_next_slot), Some(seconds_from_current_slot_start)) => {
                    let duration_until_start = if seconds_from_current_slot_start > delay {
                        duration_to_next_slot + delay
                    } else {
                        delay - seconds_from_current_slot_start
                    };
                    tokio::time::Instant::now() + duration_until_start
                                  }
                _ => {
                    crit!(log,
                        "Failed to read slot clock, delayed lookup service timing will be inaccurate.\
                         This may degrade performance"
                    );
                    Instant::now()
                }
            };

            let mut interval = interval_at(interval_start, slot_duration);
            loop {
                interval.tick().await;
                while let Ok(msg) = delayed_lookups_recv.try_recv() {
                    match msg {
                        DelayedLookupMessage::MissingComponents(block_root) => {
                            if let Err(e) = sync_send
                                .send(SyncMessage::MissingGossipBlockComponentsDelayed(block_root))
                            {
                                warn!(log, "Failed to send delayed lookup message"; "error" => ?e);
                            }
                        }
                    }
                }
            }
        },
        "delayed_lookups",
    );
}
