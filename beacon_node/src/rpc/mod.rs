mod beacon_block;
mod validator;

use self::beacon_block::BeaconBlockServiceInstance;
use self::validator::ValidatorServiceInstance;
use grpcio::{Environment, Server, ServerBuilder};
use protos::services_grpc::{create_beacon_block_service, create_validator_service};
use std::sync::Arc;

use slog::{info, Logger};

pub fn start_server(log: Logger) -> Server {
    let log_clone = log.clone();
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
        .bind("127.0.0.1", 50_051)
        .build()
        .unwrap();
    server.start();
    for &(ref host, port) in server.bind_addrs() {
        info!(log_clone, "gRPC listening on {}:{}", host, port);
    }
    server
}
