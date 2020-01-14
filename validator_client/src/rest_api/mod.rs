mod config;
mod errors;
mod response_builder;
mod router;
mod status;
mod validator;

use crate::ProductionValidatorClient;
use config::Config;
use errors::{ApiError, ApiResult};
use hyper::rt::Future;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use slog::{info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::runtime::TaskExecutor;
use types::EthSpec;

pub type BoxFut = Box<dyn Future<Item = Response<Body>, Error = ApiError> + Send>;

pub fn start_server<T: EthSpec>(
    config: &Config,
    executor: &TaskExecutor,
    validator_client: Arc<ProductionValidatorClient<T>>,
    log: slog::Logger,
) -> Result<(exit_future::Signal, SocketAddr), hyper::Error> {
    let inner_log = log.clone();

    // Define the function that will build the request handler.
    let make_service = make_service_fn(move |_socket: &AddrStream| {
        let validator_client = validator_client.clone();
        let log = inner_log.clone();

        service_fn(move |req: Request<Body>| {
            router::route(req, validator_client.clone(), log.clone())
        })
    });

    let bind_addr = (config.listen_address, config.port).into();
    let server = Server::bind(&bind_addr).serve(make_service);

    // Determine the address the server is actually listening on.
    //
    // This may be different to `bind_addr` if bind port was 0 (this allows the OS to choose a free
    // port).
    let actual_listen_addr = server.local_addr();

    // Build a channel to kill the HTTP server.
    let (exit_signal, exit) = exit_future::signal();
    let inner_log = log.clone();
    let server_exit = exit.and_then(move |_| {
        info!(inner_log, "HTTP service shutdown");
        Ok(())
    });
    // Configure the `hyper` server to gracefully shutdown when the shutdown channel is triggered.
    let inner_log = log.clone();
    let server_future = server
        .with_graceful_shutdown(server_exit)
        .map_err(move |e| {
            warn!(
            inner_log,
            "HTTP server failed to start, Unable to bind"; "address" => format!("{:?}", e)
            )
        });

    info!(
        log,
        "HTTP API started";
        "address" => format!("{}", actual_listen_addr.ip()),
        "port" => actual_listen_addr.port(),
    );

    executor.spawn(server_future);

    Ok((exit_signal, actual_listen_addr))
}

mod tests {
    use super::*;
    use crate::config::Config as ValidatorConfig;
    use environment::EnvironmentBuilder;
    #[test]
    fn test_api() {
        let mut env = EnvironmentBuilder::mainnet()
            .async_logger("debug", None)
            .unwrap()
            .single_thread_tokio_runtime()
            .unwrap()
            .build()
            .unwrap();
        let context = env.core_context();
        let executor = context.executor.clone();
        let vc = ProductionValidatorClient::new(context, ValidatorConfig::default());
        let mut validator = env
            .runtime()
            .block_on(vc)
            .map_err(|e| format!("Failed to init validator client: {}", e))
            .unwrap();

        validator
            .start_service()
            .map_err(|e| format!("Failed to start validator client service: {}", e))
            .unwrap();

        let (ef, _addr) = start_server(
            &config::Config::default(),
            &executor,
            Arc::new(validator),
            env.core_context().log,
        )
        .unwrap();
        let _: Result<(), String> = env
            .runtime()
            .block_on(futures::future::empty())
            .map_err(|e: ()| format!("Satyanaash"))
            .unwrap();
    }
}
