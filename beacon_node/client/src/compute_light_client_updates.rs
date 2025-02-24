use beacon_chain::{BeaconChain, BeaconChainTypes, LightClientProducerEvent};
use beacon_processor::work_reprocessing_queue::ReprocessQueueMessage;
use futures::channel::mpsc::Receiver;
use futures::StreamExt;
use slog::{error, Logger};
use tokio::sync::mpsc::Sender;

// Each `LightClientProducerEvent` is ~200 bytes. With the light_client server producing only recent
// updates it is okay to drop some events in case of overloading. In normal network conditions
// there's one event emitted per block at most every 12 seconds, while consuming the event should
// take a few milliseconds. 32 is a small enough arbitrary number.
pub(crate) const LIGHT_CLIENT_SERVER_CHANNEL_CAPACITY: usize = 32;

pub async fn compute_light_client_updates<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    mut light_client_server_rv: Receiver<LightClientProducerEvent<T::EthSpec>>,
    reprocess_tx: Sender<ReprocessQueueMessage>,
    log: &Logger,
) {
    // Should only receive events for recent blocks, import_block filters by blocks close to clock.
    //
    // Intents to process SyncAggregates of all recent blocks sequentially, without skipping.
    // Uses a bounded receiver, so may drop some SyncAggregates if very overloaded. This is okay
    // since only the most recent updates have value.
    while let Some(event) = light_client_server_rv.next().await {
        let parent_root = event.0;

        chain
            .recompute_and_cache_light_client_updates(event)
            .unwrap_or_else(|e| {
                error!(log, "error computing light_client updates {:?}", e);
            });

        let msg = ReprocessQueueMessage::NewLightClientOptimisticUpdate { parent_root };
        if reprocess_tx.try_send(msg).is_err() {
            error!(log, "Failed to inform light client update"; "parent_root" => %parent_root)
        };
    }
}
