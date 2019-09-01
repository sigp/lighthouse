mod attestation;
mod beacon_block;
mod beacon_node;
pub mod config;
mod validator;

use self::attestation::AttestationServiceInstance;
use self::beacon_block::BeaconBlockServiceInstance;
use self::beacon_node::BeaconNodeServiceInstance;
use self::validator::ValidatorServiceInstance;
use beacon_chain::{BeaconChain, BeaconChainTypes};
pub use config::Config as RPCConfig;
use futures::Future;
use grpcio::{Environment, ServerBuilder};
use network::NetworkMessage;
use protos::services_grpc::{
    create_attestation_service, create_beacon_block_service, create_beacon_node_service,
    create_validator_service,
};
use slog::{info, o, warn};
use std::sync::Arc;
use tokio::runtime::TaskExecutor;
use tokio::sync::mpsc;

pub fn start_server<T: BeaconChainTypes + Clone + 'static>(
    config: &RPCConfig,
    executor: &TaskExecutor,
    network_chan: mpsc::UnboundedSender<NetworkMessage>,
    beacon_chain: Arc<BeaconChain<T>>,
    log: &slog::Logger,
) -> exit_future::Signal {
    let log = log.new(o!("Service"=>"RPC"));
    let env = Arc::new(Environment::new(1));

    // build a channel to kill the rpc server
    let (rpc_exit_signal, rpc_exit) = exit_future::signal();

    // build the individual rpc services
    let beacon_node_service = {
        let instance = BeaconNodeServiceInstance {
            chain: beacon_chain.clone(),
            log: log.clone(),
        };
        create_beacon_node_service(instance)
    };

    let beacon_block_service = {
        let instance = BeaconBlockServiceInstance {
            chain: beacon_chain.clone(),
            network_chan: network_chan.clone(),
            log: log.clone(),
        };
        create_beacon_block_service(instance)
    };
    let validator_service = {
        let instance = ValidatorServiceInstance {
            chain: beacon_chain.clone(),
            log: log.clone(),
        };
        create_validator_service(instance)
    };
    let attestation_service = {
        let instance = AttestationServiceInstance {
            network_chan,
            chain: beacon_chain.clone(),
            log: log.clone(),
        };
        create_attestation_service(instance)
    };

    let mut server = ServerBuilder::new(env)
        .register_service(beacon_block_service)
        .register_service(validator_service)
        .register_service(beacon_node_service)
        .register_service(attestation_service)
        .bind(config.listen_address.to_string(), config.port)
        .build()
        .unwrap();

    let spawn_rpc = {
        server.start();
        for &(ref host, port) in server.bind_addrs() {
            info!(
                log,
                "gRPC API started";
                "port" => port,
                "host" => host,
            );
        }
        rpc_exit.and_then(move |_| {
            info!(log, "RPC Server shutting down");
            server
                .shutdown()
                .wait()
                .map(|_| ())
                .map_err(|e| warn!(log, "RPC server failed to shutdown: {:?}", e))?;
            Ok(())
        })
    };
    executor.spawn(spawn_rpc);
    rpc_exit_signal
}
