use crate::checks::{epoch_delay, verify_all_finalized_at};
use crate::local_network::LocalNetwork;
use futures::stream;
use futures::{Future, IntoFuture, Stream};
use node_test_rig::ClientConfig;
use std::time::Duration;
use tokio::timer::Interval;
use types::{Epoch, EthSpec};

pub fn pick_strategy<E: EthSpec>(
    strategy: &str,
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    initial_delay: u64,
    sync_timeout: u64,
) -> Box<dyn Future<Item = (), Error = String> + Send + 'static> {
    match strategy {
        "one-node" => Box::new(verify_one_node_sync(
            network,
            beacon_config,
            slot_duration,
            initial_delay,
            sync_timeout,
        )),
        "two-nodes" => Box::new(verify_two_nodes_sync(
            network,
            beacon_config,
            slot_duration,
            initial_delay,
            sync_timeout,
        )),
        "mixed" => Box::new(verify_in_between_sync(
            network,
            beacon_config,
            slot_duration,
            initial_delay,
            sync_timeout,
        )),
        "all" => Box::new(verify_syncing(
            network,
            beacon_config,
            slot_duration,
            initial_delay,
            sync_timeout,
        )),
        _ => Box::new(Err("Invalid strategy".into()).into_future()),
    }
}

/// Verify one node added after `initial_delay` epochs is in sync
/// after `sync_timeout` epochs.
pub fn verify_one_node_sync<E: EthSpec>(
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    initial_delay: u64,
    sync_timeout: u64,
) -> impl Future<Item = (), Error = String> {
    let epoch_duration = slot_duration * (E::slots_per_epoch() as u32);
    let network_c = network.clone();
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
        // Check every `epoch_duration` if nodes are synced
        // limited to at most `sync_timeout` epochs
        Interval::new_interval(epoch_duration)
            .take(sync_timeout)
            .map_err(|_| "Failed to create interval".to_string())
            .take_while(move |_| check_still_syncing(&network_c))
            .for_each(|_| Ok(())) // consume the stream
            .map(|_| network)
    })
    .and_then(move |network| network.bootnode_epoch().map(|e| (e, network)))
    .and_then(move |(epoch, network)| {
        verify_all_finalized_at(network, epoch).map_err(|e| format!("One node sync error: {}", e))
    })
}

/// Verify two nodes added after `initial_delay` epochs are in sync
/// after `sync_timeout` epochs.
pub fn verify_two_nodes_sync<E: EthSpec>(
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    initial_delay: u64,
    sync_timeout: u64,
) -> impl Future<Item = (), Error = String> {
    let epoch_duration = slot_duration * (E::slots_per_epoch() as u32);
    let network_c = network.clone();
    // Delay for `initial_delay` epochs before adding another node to start syncing
    epoch_delay(
        Epoch::new(initial_delay),
        slot_duration,
        E::slots_per_epoch(),
    )
    .and_then(move |_| {
        // Add beacon nodes
        network
            .add_beacon_node(beacon_config.clone())
            .map(|_| (network, beacon_config))
            .and_then(|(network, beacon_config)| {
                network.add_beacon_node(beacon_config).map(|_| network)
            })
    })
    .and_then(move |network| {
        // Check every `epoch_duration` if nodes are synced
        // limited to at most `sync_timeout` epochs
        Interval::new_interval(epoch_duration)
            .take(sync_timeout)
            .map_err(|_| "Failed to create interval".to_string())
            .take_while(move |_| check_still_syncing(&network_c))
            .for_each(|_| Ok(())) // consume the stream
            .map(|_| network)
    })
    .and_then(move |network| network.bootnode_epoch().map(|e| (e, network)))
    .and_then(move |(epoch, network)| {
        verify_all_finalized_at(network, epoch).map_err(|e| format!("Two node sync error: {}", e))
    })
}

/// Add 2 syncing nodes after `initial_delay` epochs,
/// Add another node after `sync_timeout - 5` epochs and verify all are
/// in sync after `sync_timeout + 5` epochs.
pub fn verify_in_between_sync<E: EthSpec>(
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    initial_delay: u64,
    sync_timeout: u64,
) -> impl Future<Item = (), Error = String> {
    let epoch_duration = slot_duration * (E::slots_per_epoch() as u32);
    let network_c = network.clone();
    // Delay for `initial_delay` epochs before adding another node to start syncing
    let config1 = beacon_config.clone();
    epoch_delay(
        Epoch::new(initial_delay),
        slot_duration,
        E::slots_per_epoch(),
    )
    .and_then(move |_| {
        // Add a beacon node
        network
            .add_beacon_node(beacon_config.clone())
            .map(|_| (network, beacon_config))
            .and_then(|(network, beacon_config)| {
                network.add_beacon_node(beacon_config).map(|_| network)
            })
    })
    .and_then(move |network| {
        // Delay before adding additional syncing nodes.
        epoch_delay(
            Epoch::new(sync_timeout - 5),
            slot_duration,
            E::slots_per_epoch(),
        )
        .map(|_| network)
    })
    .and_then(move |network| {
        // Add a beacon node
        network.add_beacon_node(config1.clone()).map(|_| network)
    })
    .and_then(move |network| {
        // Check every `epoch_duration` if nodes are synced
        // limited to at most `sync_timeout` epochs
        Interval::new_interval(epoch_duration)
            .take(sync_timeout + 5)
            .map_err(|_| "Failed to create interval".to_string())
            .take_while(move |_| check_still_syncing(&network_c))
            .for_each(|_| Ok(())) // consume the stream
            .map(|_| network)
    })
    .and_then(move |network| network.bootnode_epoch().map(|e| (e, network)))
    .and_then(move |(epoch, network)| {
        verify_all_finalized_at(network, epoch).map_err(|e| format!("In between sync error: {}", e))
    })
}

/// Run syncing strategies one after other.
pub fn verify_syncing<E: EthSpec>(
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    initial_delay: u64,
    sync_timeout: u64,
) -> impl Future<Item = (), Error = String> {
    verify_one_node_sync(
        network.clone(),
        beacon_config.clone(),
        slot_duration,
        initial_delay,
        sync_timeout,
    )
    .map(|_| println!("Completed one node sync"))
    .and_then(move |_| {
        verify_two_nodes_sync(
            network.clone(),
            beacon_config.clone(),
            slot_duration,
            initial_delay,
            sync_timeout,
        )
        .map(|_| {
            println!("Completed two node sync");
            (network, beacon_config)
        })
    })
    .and_then(move |(network, beacon_config)| {
        verify_in_between_sync(
            network,
            beacon_config,
            slot_duration,
            initial_delay,
            sync_timeout,
        )
        .map(|_| println!("Completed in between sync"))
    })
}

pub fn check_still_syncing<E: EthSpec>(
    network: &LocalNetwork<E>,
) -> impl Future<Item = bool, Error = String> {
    let net = network.clone();
    network
        .remote_nodes()
        .into_future()
        // get all head epochs
        .and_then(|remote_nodes| {
            stream::unfold(remote_nodes.into_iter(), |mut iter| {
                iter.next().map(|remote_node| {
                    remote_node
                        .http
                        .beacon()
                        .get_head()
                        .map(|head| head.finalized_slot.epoch(E::slots_per_epoch()))
                        .map(|epoch| (epoch, iter))
                        .map_err(|e| format!("Get head via http failed: {:?}", e))
                })
            })
            .collect()
        })
        // find current epoch
        .and_then(move |epochs| net.bootnode_epoch().map(|epoch| (epochs, epoch)))
        .and_then(move |(epochs, epoch)| Ok(epochs.iter().any(|head_epoch| *head_epoch != epoch)))
        .map_err(|e| format!("Failed syncing check: {:?}", e))
}
