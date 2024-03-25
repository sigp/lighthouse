//! This service keeps track of which data column subnets the beacon node should be subscribed to at any
//! given time. It schedules subscriptions to data column subnets and requests peer discoveries.

use itertools::Itertools;
use std::sync::Arc;

use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::{discovery::peer_id_to_node_id, NetworkGlobals};
use slog::o;
use types::{DataColumnSubnetId, EthSpec};

pub struct DataColumnService<T: BeaconChainTypes> {
    /// A reference to the beacon chain to process data columns.
    pub(crate) _beacon_chain: Arc<BeaconChain<T>>,

    /// A reference to the nodes network globals
    _network_globals: Arc<NetworkGlobals<T::EthSpec>>,

    /// The logger for the data column service.
    _log: slog::Logger,
}

impl<T: BeaconChainTypes> DataColumnService<T> {
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
        log: &slog::Logger,
    ) -> Self {
        let log = log.new(o!("service" => "data_column_service"));
        let peer_id = network_globals.local_peer_id();

        // TODO(das) temporary logic so we can have data column ids avail on the beacon chain
        // future iteration of the data column subnet service will introduce data column rotation
        // and other relevant logic.
        if let Ok(node_id) = peer_id_to_node_id(&peer_id) {
            let mut data_column_subnet_ids = DataColumnSubnetId::compute_subnets_for_data_column::<
                T::EthSpec,
            >(node_id.raw().into(), &beacon_chain.spec);

            beacon_chain
                .data_column_custody_tracker
                .set_custody_requirements(
                    data_column_subnet_ids
                        .by_ref()
                        .map(|data_column| *data_column)
                        .collect_vec(),
                );
        }
        Self {
            _beacon_chain: beacon_chain,
            _network_globals: network_globals,
            _log: log,
        }
    }
}
