use crate::beacon_chain::BeaconChain;
use futures::Future;
use grpcio::{RpcContext, UnarySink};
use protos::services::{Empty, Fork, NodeInfo};
use protos::services_grpc::BeaconNodeService;
use slog::{debug, trace, warn};
use std::sync::Arc;

#[derive(Clone)]
pub struct BeaconNodeServiceInstance {
    pub chain: Arc<BeaconChain>,
    pub log: slog::Logger,
}

impl BeaconNodeService for BeaconNodeServiceInstance {
    /// Provides basic node information.
    fn info(&mut self, ctx: RpcContext, _req: Empty, sink: UnarySink<NodeInfo>) {
        trace!(self.log, "Node info requested via RPC");

        let mut node_info = NodeInfo::new();
        node_info.set_version(version::version());
        // get the chain state fork
        let state_fork = self.chain.get_state().fork.clone();
        // build the rpc fork struct
        let mut fork = Fork::new();
        fork.set_previous_version(state_fork.previous_version.to_vec());
        fork.set_current_version(state_fork.current_version.to_vec());
        fork.set_epoch(state_fork.epoch.into());
        node_info.set_fork(fork);

        node_info.set_chain_id(self.chain.get_spec().chain_id as u32);

        // send the node_info the requester
        let error_log = self.log.clone();
        let f = sink
            .success(node_info)
            .map_err(move |e| warn!(error_log, "failed to reply {:?}", e));
        ctx.spawn(f)
    }
}
