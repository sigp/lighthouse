use beacon_chain::{BeaconChain, BeaconChainTypes, LightclientProducerEvent};
use slog::{error, Logger};
use tokio::sync::mpsc::Receiver;

// Each LightclientProducerEvent is ~200 bytes. With the lightclient server producing only recent
// updates it is okay to drop some events in case of overloading. In normal network conditions
// there's one event emitted per block at most every 12 seconds, while consuming the event should
// take a few miliseconds. 32 is a small enough arbitrary number.
pub(crate) const LIGHTCLIENT_SERVER_CHANNEL_CAPACITY: usize = 32;

pub async fn compute_lightclient_updates<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    mut lightclient_server_rv: Receiver<LightclientProducerEvent<T::EthSpec>>,
    log: &Logger,
) {
    // lightclient_server_rv is Some if lightclient flag is enabled
    //
    // Should only receive events for recent blocks, import_block filters by blocks close to clock.
    //
    // Intents to process SyncAggregates of all recent blocks sequentially, without skipping.
    // Uses a bounded receiver, so may drop some SyncAggregates if very overloaded. This is okay
    // since only the most recent updates have value.
    while let Some((block_root, slot, sync_aggregate)) = lightclient_server_rv.recv().await {
        chain
            .recompute_and_cache_lightclient_updates((block_root, slot, sync_aggregate))
            .unwrap_or_else(|e| {
                error!(log, "error computing lightclient updates {:?}", e);
            })
    }
}
