mod beacon_block;
pub mod config;
mod validator;

use self::beacon_block::BeaconBlockServiceInstance;
use self::validator::ValidatorServiceInstance;
pub use config::Config as RPCConfig;
use grpcio::{Environment, Server, ServerBuilder};
use protos::services_grpc::{create_beacon_block_service, create_validator_service};
use std::sync::Arc;

use slog::{info, o};

pub fn start_server(config: &RPCConfig, log: &slog::Logger) -> Server {
    let log = log.new(o!("Service"=>"RPC"));
    let env = Arc::new(Environment::new(1));

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
