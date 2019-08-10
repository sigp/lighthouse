use beacon_chain::{BeaconChain, BeaconChainTypes};
use futures::Future;
use grpcio::{RpcContext, UnarySink};
use protos::services::{Empty, Fork, NodeInfoResponse};
use protos::services_grpc::BeaconNodeService;
use slog::{trace, warn};
use std::sync::Arc;

#[derive(Clone)]
pub struct BeaconNodeServiceInstance<T: BeaconChainTypes> {
    pub chain: Arc<BeaconChain<T>>,
    pub log: slog::Logger,
}

impl<T: BeaconChainTypes> BeaconNodeService for BeaconNodeServiceInstance<T> {
    /// Provides basic node information.
    fn info(&mut self, ctx: RpcContext, _req: Empty, sink: UnarySink<NodeInfoResponse>) {
        trace!(self.log, "Node info requested via RPC");

        // build the response
        let mut node_info = NodeInfoResponse::new();
        node_info.set_version(version::version());

        // get the chain state
        let state = &self.chain.head().beacon_state;
        let state_fork = state.fork.clone();
        let genesis_time = state.genesis_time;

        // build the rpc fork struct
        let mut fork = Fork::new();
        fork.set_previous_version(state_fork.previous_version.to_vec());
        fork.set_current_version(state_fork.current_version.to_vec());
        fork.set_epoch(state_fork.epoch.into());

        let spec = &self.chain.spec;

        node_info.set_fork(fork);
        node_info.set_genesis_time(genesis_time);
        node_info.set_genesis_slot(spec.genesis_slot.as_u64());
        node_info.set_network_id(u32::from(spec.network_id));

        // send the node_info the requester
        let error_log = self.log.clone();
        let f = sink
            .success(node_info)
            .map_err(move |e| warn!(error_log, "failed to reply {:?}", e));
        ctx.spawn(f)
    }
}
