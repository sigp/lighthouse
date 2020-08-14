use crate::{
    advanced, beacon, config::Config, consensus, error::ApiError, helpers, lighthouse, metrics,
    network, node, response_builder::ResponseBuilder, spec, validator, ApiResult, NetworkChannel,
};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use bus::Bus;
use eth2_config::Eth2Config;
use eth2_libp2p::NetworkGlobals;
use hyper::header::HeaderValue;
use hyper::{body::Bytes, Body, Method, Request, Response};
use parking_lot::Mutex;
use slog::debug;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use types::{SignedBeaconBlockHash, Slot};

use environment::TaskExecutor;
use slog::{info, warn};

pub struct Context<T: BeaconChainTypes> {
    pub executor: TaskExecutor,
    pub config: Config,
    pub beacon_chain: Arc<BeaconChain<T>>,
    pub network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    pub network_chan: NetworkChannel<T::EthSpec>,
    pub eth2_config: Arc<Eth2Config>,
    pub log: slog::Logger,
    pub db_path: PathBuf,
    pub freezer_db_path: PathBuf,
    pub events: Arc<Mutex<Bus<SignedBeaconBlockHash>>>,
}

/*
#[macro_export]
macro_rules! get_make_service_fn {
    ($router: ident) => {{
        let router = $router;
        let bind_addr = (router.config.listen_address, router.config.port).into();

        // Define the function that will build the request handler.
        let make_service =
            hyper::service::make_service_fn(move |_socket: &AddrStream| async move {
                Ok::<_, hyper::Error>(hyper::service::service_fn(move |req: Request<Body>| {
                    dbg!(router.config);
                    Response::new(Body::from(format!("Hello, {}!", remote_addr)))
                }))
            });

        Server::bind(&bind_addr).serve(make_service)
    }};
}
*/

/*
impl<T: BeaconChainTypes> BeaconNodeServer<T> {
    pub fn spawn(self) -> Result<SocketAddr, hyper::Error> {
        let bind_addr = (self.config.listen_address, self.config.port).into();
        let executor = self.executor.clone();
        let log = self.log.clone();
        let ctx = Arc::new(self);

        let make_svc = hyper::service::make_service_fn(move |socket: &AddrStream| {
            let remote_addr = socket.remote_addr();
            let ctx = ctx.clone();

            async move {
                Ok::<_, Infallible>(hyper::service::service_fn(move |_: Request<Body>| {
                    let ctx = ctx.clone();

                    async move {
                        dbg!(&ctx.config);
                        Ok::<_, Infallible>(Response::new(Body::from(format!(
                            "Hello, {}!",
                            remote_addr
                        ))))
                    }
                }))
            }
        });

        let server = Server::bind(&bind_addr).serve(make_svc);

        // Determine the address the server is actually listening on.
        //
        // This may be different to `bind_addr` if bind port was 0 (this allows the OS to choose a free
        // port).
        let actual_listen_addr = server.local_addr();

        // Build a channel to kill the HTTP server.
        let exit = executor.exit();
        let inner_log = log.clone();
        let server_exit = async move {
            let _ = exit.await;
            info!(inner_log, "HTTP service shutdown");
        };

        // Configure the `hyper` server to gracefully shutdown when the shutdown channel is triggered.
        let inner_log = log.clone();
        let server_future = server
            .with_graceful_shutdown(async {
                server_exit.await;
            })
            .map_err(move |e| {
                warn!(
                inner_log,
                "HTTP server failed to start, Unable to bind"; "address" => format!("{:?}", e)
                )
            })
            .unwrap_or_else(|_| ());

        info!(
            log,
            "HTTP API started";
            "address" => format!("{}", actual_listen_addr.ip()),
            "port" => actual_listen_addr.port(),
        );

        executor.spawn_without_exit(server_future, "http");

        Ok(actual_listen_addr)
    }
}
*/

/*
pub async fn paul_test(socket: &AddrStream) ->  {
    hyper::service::make_service_fn(|socket: &AddrStream| {
        let remote_addr = socket.remote_addr();
        async move {
            Ok::<_, Infallible>(hyper::service::service_fn(
                move |_: Request<Body>| async move {
                    Ok::<_, Infallible>(Response::new(Body::from(format!(
                        "Hello, {}!",
                        remote_addr
                    ))))
                },
            ))
        }
    })
}
*/

async fn blocking<T, I, NB, B>(
    ctx: Arc<Context<T>>,
    non_blocking_fn: NB,
    blocking_fn: B,
) -> Result<(), ApiError>
where
    I: Send + Sync + 'static,
    T: BeaconChainTypes,
    NB: Future<Output = Result<I, ApiError>>,
    B: Fn(Arc<Context<T>>, I) -> Result<(), ApiError> + Send + Sync + 'static,
{
    let intermediate_values = non_blocking_fn.await?;
    let result = ctx
        .executor
        .clone()
        .handle
        .spawn_blocking(move || blocking_fn(ctx, intermediate_values))
        .await
        .map_err(|e| {
            ApiError::ServerError(format!(
                "Failed to get blocking join handle: {}",
                e.to_string()
            ))
        })?;

    result
}

async fn blocking_with_body<T, I, NB, B>(
    ctx: Arc<Context<T>>,
    req: Request<Body>,
    blocking_fn: B,
) -> ApiResult
where
    T: BeaconChainTypes,
    B: Fn(Arc<Context<T>>, Bytes) -> Result<(), ApiError> + Send + Sync + 'static,
{
    let response_builder = ResponseBuilder::new(&req)?;

    let non_blocking_fn = async {
        let body = get_body(req).await;
        body
    };

    let result = blocking(ctx, non_blocking_fn, blocking_fn).await?;

    response_builder.body_no_ssz(&result)
}

async fn get_body(req: Request<Body>) -> Result<Bytes, ApiError> {
    hyper::body::to_bytes(req.into_body())
        .await
        .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}", e)))
}

// Allowing more than 7 arguments.
#[allow(clippy::too_many_arguments)]
pub async fn route<T: BeaconChainTypes>(
    req: Request<Body>,
    ctx: Arc<Context<T>>,
) -> Result<Response<Body>, ApiError> {
    metrics::inc_counter(&metrics::REQUEST_COUNT);
    let received_instant = Instant::now();

    let path = req.uri().path().to_string();

    let result = {
        let _timer = metrics::start_timer(&metrics::REQUEST_RESPONSE_TIME);

        match (req.method(), path.as_ref()) {
            // Methods for Client
            (&Method::GET, "/node/health") => node::get_health(req),
            (&Method::GET, "/node/version") => node::get_version(req),
            (&Method::POST, "/validator/attestations") => {
                blocking_with_body::<_, (), _, _>(
                    ctx,
                    req,
                    validator::publish_attestations_blocking,
                )
                .await
            }
            /*
            (&Method::POST, "/validator/attestations") => blocking(
                ctx,
                || get_body(req),
                |body| validator::publish_attestations_blocking(body, &ctx),
            ),

            (&Method::GET, "/node/syncing") => {
                // inform the current slot, or set to 0
                let current_slot = beacon_chain
                    .head_info()
                    .map(|info| info.slot)
                    .unwrap_or_else(|_| Slot::from(0u64));

                node::syncing::<T::EthSpec>(req, network_globals, current_slot)
            }

            // Methods for Network
            (&Method::GET, "/network/enr") => network::get_enr::<T>(req, network_globals),
            (&Method::GET, "/network/peer_count") => {
                network::get_peer_count::<T>(req, network_globals)
            }
            (&Method::GET, "/network/peer_id") => network::get_peer_id::<T>(req, network_globals),
            (&Method::GET, "/network/peers") => network::get_peer_list::<T>(req, network_globals),
            (&Method::GET, "/network/listen_port") => {
                network::get_listen_port::<T>(req, network_globals)
            }
            (&Method::GET, "/network/listen_addresses") => {
                network::get_listen_addresses::<T>(req, network_globals)
            }

            // Methods for Beacon Node
            (&Method::GET, "/beacon/head") => beacon::get_head::<T>(req, beacon_chain),
            (&Method::GET, "/beacon/heads") => beacon::get_heads::<T>(req, beacon_chain),
            (&Method::GET, "/beacon/block") => beacon::get_block::<T>(req, beacon_chain),
            (&Method::GET, "/beacon/block_root") => beacon::get_block_root::<T>(req, beacon_chain),
            (&Method::GET, "/beacon/fork") => beacon::get_fork::<T>(req, beacon_chain),
            (&Method::GET, "/beacon/fork/stream") => {
                let reader = events.lock().add_rx();
                beacon::stream_forks::<T>(log, reader)
            }
            (&Method::GET, "/beacon/genesis_time") => {
                beacon::get_genesis_time::<T>(req, beacon_chain)
            }
            (&Method::GET, "/beacon/genesis_validators_root") => {
                beacon::get_genesis_validators_root::<T>(req, beacon_chain)
            }
            (&Method::GET, "/beacon/validators") => beacon::get_validators::<T>(req, beacon_chain),
            (&Method::POST, "/beacon/validators") => {
                beacon::post_validators::<T>(req, beacon_chain).await
            }
            (&Method::GET, "/beacon/validators/all") => {
                beacon::get_all_validators::<T>(req, beacon_chain)
            }
            (&Method::GET, "/beacon/validators/active") => {
                beacon::get_active_validators::<T>(req, beacon_chain)
            }
            (&Method::GET, "/beacon/state") => beacon::get_state::<T>(req, beacon_chain),
            (&Method::GET, "/beacon/state_root") => beacon::get_state_root::<T>(req, beacon_chain),
            (&Method::GET, "/beacon/state/genesis") => {
                beacon::get_genesis_state::<T>(req, beacon_chain)
            }
            (&Method::GET, "/beacon/committees") => beacon::get_committees::<T>(req, beacon_chain),
            (&Method::POST, "/beacon/proposer_slashing") => {
                beacon::proposer_slashing::<T>(req, beacon_chain).await
            }
            (&Method::POST, "/beacon/attester_slashing") => {
                beacon::attester_slashing::<T>(req, beacon_chain).await
            }

            // Methods for Validator
            (&Method::POST, "/validator/duties") => {
                let timer =
                    metrics::start_timer(&metrics::VALIDATOR_GET_DUTIES_REQUEST_RESPONSE_TIME);
                let response = validator::post_validator_duties::<T>(req, beacon_chain);
                drop(timer);
                response.await
            }
            (&Method::POST, "/validator/subscribe") => {
                validator::post_validator_subscriptions::<T>(req, network_channel).await
            }
            (&Method::GET, "/validator/duties/all") => {
                validator::get_all_validator_duties::<T>(req, beacon_chain)
            }
            (&Method::GET, "/validator/duties/active") => {
                validator::get_active_validator_duties::<T>(req, beacon_chain)
            }
            (&Method::GET, "/validator/block") => {
                let timer =
                    metrics::start_timer(&metrics::VALIDATOR_GET_BLOCK_REQUEST_RESPONSE_TIME);
                let response = validator::get_new_beacon_block::<T>(req, beacon_chain, log);
                drop(timer);
                response
            }
            (&Method::POST, "/validator/block") => {
                validator::publish_beacon_block::<T>(req, beacon_chain, network_channel, log).await
            }
            (&Method::GET, "/validator/attestation") => {
                let timer =
                    metrics::start_timer(&metrics::VALIDATOR_GET_ATTESTATION_REQUEST_RESPONSE_TIME);
                let response = validator::get_new_attestation::<T>(req, beacon_chain);
                drop(timer);
                response
            }
            (&Method::GET, "/validator/aggregate_attestation") => {
                validator::get_aggregate_attestation::<T>(req, beacon_chain)
            }
            (&Method::POST, "/validator/attestations") => {
                validator::publish_attestations::<T>(req, beacon_chain, network_channel, log).await
            }
            (&Method::POST, "/validator/aggregate_and_proofs") => {
                validator::publish_aggregate_and_proofs::<T>(
                    req,
                    beacon_chain,
                    network_channel,
                    log,
                )
                .await
            }

            // Methods for consensus
            (&Method::GET, "/consensus/global_votes") => {
                consensus::get_vote_count::<T>(req, beacon_chain)
            }
            (&Method::POST, "/consensus/individual_votes") => {
                consensus::post_individual_votes::<T>(req, beacon_chain).await
            }

            // Methods for bootstrap and checking configuration
            (&Method::GET, "/spec") => spec::get_spec::<T>(req, beacon_chain),
            (&Method::GET, "/spec/slots_per_epoch") => spec::get_slots_per_epoch::<T>(req),
            (&Method::GET, "/spec/deposit_contract") => {
                helpers::implementation_pending_response(req)
            }
            (&Method::GET, "/spec/eth2_config") => spec::get_eth2_config::<T>(req, eth2_config),

            // Methods for advanced parameters
            (&Method::GET, "/advanced/fork_choice") => {
                advanced::get_fork_choice::<T>(req, beacon_chain)
            }
            (&Method::GET, "/advanced/operation_pool") => {
                advanced::get_operation_pool::<T>(req, beacon_chain)
            }

            (&Method::GET, "/metrics") => {
                metrics::get_prometheus::<T>(req, beacon_chain, db_path, freezer_db_path)
            }

            // Lighthouse specific
            (&Method::GET, "/lighthouse/syncing") => {
                lighthouse::syncing::<T::EthSpec>(req, network_globals)
            }

            (&Method::GET, "/lighthouse/peers") => {
                lighthouse::peers::<T::EthSpec>(req, network_globals)
            }

            (&Method::GET, "/lighthouse/connected_peers") => {
                lighthouse::connected_peers::<T::EthSpec>(req, network_globals)
            }
            _ => Err(ApiError::NotFound(
                "Request path and/or method not found.".to_owned(),
            )),
            */
            _ => Err(ApiError::NotFound(
                "Request path and/or method not found.".to_owned(),
            )),
        }
    };

    let request_processing_duration = Instant::now().duration_since(received_instant);

    // Map the Rust-friendly `Result` in to a http-friendly response. In effect, this ensures that
    // any `Err` returned from our response handlers becomes a valid http response to the client
    // (e.g., a response with a 404 or 500 status).

    match result {
        Ok(mut response) => {
            if ctx.config.allow_origin != "" {
                let headers = response.headers_mut();
                headers.insert(
                    hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                    HeaderValue::from_str(&ctx.config.allow_origin)?,
                );
                headers.insert(hyper::header::VARY, HeaderValue::from_static("Origin"));
            }

            debug!(
                ctx.log,
                "HTTP API request successful";
                "path" => path,
                "duration_ms" => request_processing_duration.as_millis()
            );
            metrics::inc_counter(&metrics::SUCCESS_COUNT);
            Ok(response)
        }

        Err(error) => {
            debug!(
                ctx.log,
                "HTTP API request failure";
                "path" => path,
                "duration_ms" => request_processing_duration.as_millis()
            );
            Ok(error.into())
        }
    }
}
