use beacon_chain::BeaconChain;
use futures::Future;
use grpcio::{Environment, ServerBuilder};
use network::NetworkMessage;
use protos::services_grpc::{
    create_attestation_service, create_beacon_block_service, create_beacon_node_service,
    create_validator_service,
};
use slog::{info, o, warn};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::runtime::TaskExecutor;
use types::EthSpec;

use iron::prelude::*;
use iron::{status::Status, Handler, IronResult, Request, Response};
use router::Router;

#[derive(PartialEq, Clone, Debug)]
pub struct HttpServerConfig {
    pub enabled: bool,
    pub listen_address: String,
    /*
    pub listen_address: Ipv4Addr,
    pub port: u16,
    */
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_address: "127.0.0.1:5051".to_string(),
            /*
            listen_address: Ipv4Addr::new(127, 0, 0, 1),
            port: 5051,
            */
        }
    }
}

pub struct IndexHandler {
    message: String,
}

impl Handler for IndexHandler {
    fn handle(&self, _: &mut Request) -> IronResult<Response> {
        Ok(Response::with((Status::Ok, self.message.clone())))
    }
}

pub fn create_iron_http_server() -> Iron<Router> {
    let index_handler = IndexHandler {
        message: "Hello world".to_string(),
    };

    let mut router = Router::new();
    router.get("/", index_handler, "index");
    Iron::new(router)
}

pub fn start_service<T, U, F, E>(
    config: &HttpServerConfig,
    executor: &TaskExecutor,
    network_chan: crossbeam_channel::Sender<NetworkMessage>,
    beacon_chain: Arc<BeaconChain<T, U, F, E>>,
    log: &slog::Logger,
) -> exit_future::Signal
where
    T: store::Store,
    U: slot_clock::SlotClock,
    F: fork_choice::ForkChoice,
    E: EthSpec,
{
    let log = log.new(o!("Service"=>"RPC"));
    let env = Arc::new(Environment::new(1));

    // Create:
    //  - `shutdown_trigger` a one-shot to shut down this service.
    //  - `wait_for_shutdown` a future that will wait until someone calls shutdown.
    let (shutdown_trigger, wait_for_shutdown) = exit_future::signal();

    let iron = create_iron_http_server();

    let spawn_rpc = {
        let result = iron.http(config.listen_address.clone());

        if result.is_ok() {
            info!(log, "HTTP server running on {}", config.listen_address);
        } else {
            warn!(
                log,
                "HTTP server failed to start on {}", config.listen_address
            );
        }

        wait_for_shutdown.and_then(move |_| {
            info!(log, "HTTP server shutting down");

            // TODO: shutdown server.
            /*
            server
                .shutdown()
                .wait()
                .map(|_| ())
                .map_err(|e| warn!(log, "RPC server failed to shutdown: {:?}", e))?;
            Ok(())
            */
            info!(log, "HTTP server exited");
            Ok(())
        })
    };
    executor.spawn(spawn_rpc);
    shutdown_trigger
}
