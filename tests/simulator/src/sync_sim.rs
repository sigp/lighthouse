use crate::checks::{epoch_delay, verify_all_finalized_at};
use crate::local_network::LocalNetwork;
use futures::Future;
use node_test_rig::{testing_client_config, ClientConfig};
use std::time::{Duration, Instant};
use tokio::timer::Delay;
use types::{Epoch, EthSpec};

#[derive(Debug, PartialEq)]
pub enum SyncStrategy {
    OneNodeSync,
    TwoNodeSync,
    TwoNodeSyncTwoJoin,
}

impl SyncStrategy {
    pub fn get_strategy(strategy: usize) -> Option<Self> {
        match strategy {
            0 => Some(SyncStrategy::OneNodeSync),
            1 => Some(SyncStrategy::TwoNodeSync),
            2 => Some(SyncStrategy::TwoNodeSyncTwoJoin),
            _ => None,
        }
    }
}

pub fn verify_sync<E: EthSpec>(
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    sync_duration: Duration,
    strategy: SyncStrategy,
) -> impl Future<Item = (), Error = String> {
    match strategy {
        SyncStrategy::OneNodeSync => {
            Box::new(
                epoch_delay(Epoch::new(3), slot_duration, E::slots_per_epoch())
                    .and_then(move |_| {
                        // Add a beacon node
                        network.add_beacon_node(beacon_config).map(|_| network)
                    })
                    .and_then(move |network| {
                        Delay::new(Instant::now() + sync_duration)
                            .map_err(|e| format!("Delay failed: {:?}", e))
                            .map(|_| network)
                    })
                    .and_then(move |network| network.bootnode_epoch().map(|e| (e, network)))
                    .and_then(move |(epoch, network)| verify_all_finalized_at(network, epoch)),
            )
        }
        // SyncStrategy::TwoNodeSync => {
        //     Box::new(
        //         epoch_delay(Epoch::new(3), slot_duration, E::slots_per_epoch())
        //             .and_then(move |_| {
        //                 // Add 2 beacon nodes
        //                 network
        //                     .add_beacon_node(testing_client_config())
        //                     .join(network.add_beacon_node(testing_client_config()))
        //                     .map(move |_| network)
        //             })
        //             .and_then(move |network| {
        //                 Delay::new(Instant::now() + sync_duration)
        //                     .map_err(|e| format!("Delay failed: {:?}", e))
        //                     .map(|_| network)
        //             })
        //             .and_then(move |network| network.bootnode_epoch().map(|e| (e, network)))
        //             .and_then(move |(epoch, network)| verify_all_finalized_at(network, epoch)),
        //     )
        // }
        _ => unimplemented!(),
    }
}
