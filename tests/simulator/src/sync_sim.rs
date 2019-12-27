use crate::checks::{epoch_delay, verify_all_finalized_at};
use crate::local_network::LocalNetwork;
use futures::Future;
use node_test_rig::ClientConfig;
use std::time::Duration;
use types::{Epoch, EthSpec};

pub fn verify_one_node_sync<E: EthSpec>(
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    initial_delay: u64,
    sync_delay: u64,
) -> impl Future<Item = (), Error = String> {
    // Delay for `initial_delay` epochs before adding another node to start syncing
    epoch_delay(
        Epoch::new(initial_delay),
        slot_duration,
        E::slots_per_epoch(),
    )
    .and_then(move |_| {
        // Add a beacon node
        network.add_beacon_node(beacon_config).map(|_| network)
    })
    .and_then(move |network| {
        // Delay for `sync_delay` epochs before verifying synced state.
        epoch_delay(Epoch::new(sync_delay), slot_duration, E::slots_per_epoch()).map(|_| network)
    })
    .and_then(move |network| network.bootnode_epoch().map(|e| (e, network)))
    .and_then(move |(epoch, network)| verify_all_finalized_at(network, epoch))
}
