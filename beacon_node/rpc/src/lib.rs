mod beacon_block;
mod beacon_node;
pub mod config;
mod validator;

use self::beacon_block::BeaconBlockServiceInstance;
use self::beacon_node::BeaconNodeServiceInstance;
use self::validator::ValidatorServiceInstance;
use beacon_chain::{db::ClientDB, fork_choice::ForkChoice, slot_clock::SlotClock, BeaconChain};
pub use config::Config as RPCConfig;
use grpcio::{Environment, Server, ServerBuilder};
use protos::services_grpc::{
    create_beacon_block_service, create_beacon_node_service, create_validator_service,
};
use std::sync::Arc;

use slog::{info, o};

pub fn start_server<T, U, F>(
    config: &RPCConfig,
    beacon_chain: Arc<BeaconChain<T, U, F>>,
    log: &slog::Logger,
) -> Server
where
    T: ClientDB + Clone + 'static,
    U: SlotClock + Clone + 'static,
    F: ForkChoice + Clone + 'static,
{
    let log = log.new(o!("Service"=>"RPC"));
    let env = Arc::new(Environment::new(1));

    // build the individual rpc services

    let beacon_node_service = {
        let instance = BeaconNodeServiceInstance {
            chain: beacon_chain.clone(),
            log: log.clone(),
        };
        create_beacon_node_service(instance)
    };

    let beacon_block_service = {
        let instance = BeaconBlockServiceInstance { log: log.clone() };
        create_beacon_block_service(instance)
    };
    let validator_service = {
        let instance = ValidatorServiceInstance { log: log.clone() };
        create_validator_service(instance)
    };

    let mut server = ServerBuilder::new(env)
        .register_service(beacon_block_service)
        .register_service(validator_service)
        .bind(config.listen_address.to_string(), config.port)
        .build()
        .unwrap();
    server.start();
    for &(ref host, port) in server.bind_addrs() {
        info!(log, "gRPC listening on {}:{}", host, port);
    }
    server
}
