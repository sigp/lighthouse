use crate::{
    advanced, beacon,
    config::{ApiEncodingFormat, Config},
    consensus,
    error::ApiError,
    helpers, lighthouse, metrics, network, node,
    response_builder::ResponseBuilder,
    spec, validator, ApiResult, NetworkChannel,
};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use bus::Bus;
use eth2_config::Eth2Config;
use eth2_libp2p::NetworkGlobals;
use hyper::header::{self, HeaderValue};
use hyper::{body::Bytes, Body, Method, Request, Response, StatusCode};
use lighthouse_version::version_with_platform;
use parking_lot::Mutex;
use rest_types::Health;
use serde::Serialize;
use slog::debug;
use ssz::Encode;
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

struct Handler<T: BeaconChainTypes> {
    req: Request<Body>,
    ctx: Arc<Context<T>>,
    encoding: ApiEncodingFormat,
    allow_body: bool,
}

impl<T: BeaconChainTypes> Handler<T> {
    pub fn new(req: Request<Body>, ctx: Arc<Context<T>>) -> Result<Self, ApiError> {
        let accept_header: String = req
            .headers()
            .get(header::ACCEPT)
            .map_or(Ok(""), |h| h.to_str())
            .map_err(|e| {
                ApiError::BadRequest(format!(
                    "The Accept header contains invalid characters: {:?}",
                    e
                ))
            })
            .map(String::from)?;

        Ok(Self {
            req,
            ctx,
            allow_body: false,
            encoding: ApiEncodingFormat::from(accept_header.as_str()),
        })
    }

    pub fn allow_body(mut self) -> Self {
        self.allow_body = true;
        self
    }

    async fn static_value<V>(self, value: V) -> Result<HandledRequest<V>, ApiError> {
        let body = get_body(self.req).await?;

        if !self.allow_body && !&body[..].is_empty() {
            return Err(ApiError::BadRequest(
                "The request body must be empty".to_string(),
            ));
        }

        Ok(HandledRequest {
            value,
            encoding: self.encoding,
        })
    }

    async fn in_blocking_task<F, V>(self, blocking_fn: F) -> Result<HandledRequest<V>, ApiError>
    where
        V: Send + Sync + 'static,
        F: Fn(Arc<Context<T>>, Bytes) -> Result<V, ApiError> + Send + Sync + 'static,
    {
        let body = get_body(self.req).await?;

        if !self.allow_body && !&body[..].is_empty() {
            return Err(ApiError::BadRequest(
                "The request body must be empty".to_string(),
            ));
        }

        let ctx = self.ctx.clone();

        let value = ctx
            .executor
            .clone()
            .handle
            .spawn_blocking(move || blocking_fn(ctx, body))
            .await
            .map_err(|e| {
                ApiError::ServerError(format!(
                    "Failed to get blocking join handle: {}",
                    e.to_string()
                ))
            })??;

        Ok(HandledRequest {
            value,
            encoding: self.encoding,
        })
    }
}

struct HandledRequest<V> {
    encoding: ApiEncodingFormat,
    value: V,
}

impl HandledRequest<String> {
    pub fn from_string(value: String) -> ApiResult {
        Self {
            encoding: ApiEncodingFormat::JSON,
            value,
        }
        .text_encoding()
    }

    pub fn text_encoding(self) -> ApiResult {
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; charset=utf-8")
            .body(Body::from(self.value))
            .map_err(|e| ApiError::ServerError(format!("Failed to build response: {:?}", e)))
    }
}

impl<V: Serialize + Encode> HandledRequest<V> {
    pub fn all_encodings(self) -> ApiResult {
        match self.encoding {
            ApiEncodingFormat::SSZ => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/ssz")
                .body(Body::from(self.value.as_ssz_bytes()))
                .map_err(|e| ApiError::ServerError(format!("Failed to build response: {:?}", e))),
            _ => self.serde_encodings(),
        }
    }
}

impl<V: Serialize> HandledRequest<V> {
    pub fn serde_encodings(self) -> ApiResult {
        let (body, content_type) = match self.encoding {
            ApiEncodingFormat::JSON => (
                Body::from(serde_json::to_string(&self.value).map_err(|e| {
                    ApiError::ServerError(format!(
                        "Unable to serialize response body as JSON: {:?}",
                        e
                    ))
                })?),
                "application/json",
            ),
            ApiEncodingFormat::SSZ => {
                return Err(ApiError::UnsupportedType(
                    "Response cannot be encoded as SSZ.".into(),
                ));
            }
            ApiEncodingFormat::YAML => (
                Body::from(serde_yaml::to_string(&self.value).map_err(|e| {
                    ApiError::ServerError(format!(
                        "Unable to serialize response body as YAML: {:?}",
                        e
                    ))
                })?),
                "application/yaml",
            ),
        };

        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", content_type)
            .body(body)
            .map_err(|e| ApiError::ServerError(format!("Failed to build response: {:?}", e)))
    }
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
        let ctx = ctx.clone();
        let method = req.method().clone();
        let handler = Handler::new(req, ctx)?;

        match (method, path.as_ref()) {
            /*
             * Current lighthouse version.
             */
            (Method::GET, "/node/version") => handler
                .static_value(version_with_platform())
                .await?
                .text_encoding(),
            /*
             * The health of the host.
             */
            (Method::GET, "/node/health") => handler
                .static_value(Health::observe().map_err(ApiError::ServerError)?)
                .await?
                .serde_encodings(),
            /*
             * Network syncing status
             */
            (Method::GET, "/node/syncing") => handler
                .allow_body()
                .in_blocking_task(|ctx, _| node::syncing(ctx))
                .await?
                .serde_encodings(),
            /*
             * Unaggregated attestations from local validators.
             */
            (Method::POST, "/validator/attestations") => handler
                .allow_body()
                .in_blocking_task(validator::publish_attestations_blocking)
                .await?
                .serde_encodings(),
            /*
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
