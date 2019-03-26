use crate::beacon_chain::BeaconChain;
use futures::Future;
use grpcio::{RpcContext, UnarySink};
use protos::services::{Empty, Fork, NodeInfoResponse};
use protos::services_grpc::BeaconNodeService;
use slog::{trace, warn};
use std::sync::Arc;

#[derive(Clone)]
pub struct BeaconNodeServiceInstance {
    pub chain: Arc<BeaconChain>,
    pub log: slog::Logger,
}

impl BeaconNodeService for BeaconNodeServiceInstance {
    /// Provides basic node information.
    fn info(&mut self, ctx: RpcContext, _req: Empty, sink: UnarySink<NodeInfoResponse>) {
        trace!(self.log, "Node info requested via RPC");

        // build the response
        let mut node_info = NodeInfoResponse::new();
        node_info.set_version(version::version());

        // get the chain state
        let state = self.chain.get_state();
        let state_fork = state.fork.clone();
        let genesis_time = state.genesis_time.clone();

        // build the rpc fork struct
        let mut fork = Fork::new();
        fork.set_previous_version(state_fork.previous_version.to_vec());
        fork.set_current_version(state_fork.current_version.to_vec());
        fork.set_epoch(state_fork.epoch.into());

        node_info.set_fork(fork);
        node_info.set_genesis_time(genesis_time);
        node_info.set_genesis_slot(self.chain.get_spec().genesis_slot.as_u64());
        node_info.set_chain_id(self.chain.get_spec().chain_id as u32);

        // send the node_info the requester
        let error_log = self.log.clone();
        let f = sink
            .success(node_info)
            .map_err(move |e| warn!(error_log, "failed to reply {:?}", e));
        ctx.spawn(f)
    }
}
