use crate::{
    advanced, beacon,
    config::{ApiEncodingFormat, Config},
    consensus,
    error::ApiError,
    helpers, lighthouse, metrics, node,
    response_builder::ResponseBuilder,
    spec, validator, ApiResult, NetworkChannel,
};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use bus::Bus;
use eth2_config::Eth2Config;
use eth2_libp2p::{NetworkGlobals, PeerId};
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
    req: Request<()>,
    body: Body,
    ctx: Arc<Context<T>>,
    encoding: ApiEncodingFormat,
    allow_body: bool,
}

impl<T: BeaconChainTypes> Handler<T> {
    pub fn new(req: Request<Body>, ctx: Arc<Context<T>>) -> Result<Self, ApiError> {
        let (req_parts, body) = req.into_parts();
        let req = Request::from_parts(req_parts, ());

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
            body,
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
        // Always check and disallow a body for a static value.
        let _ = Self::get_body(self.body, false).await?;

        Ok(HandledRequest {
            value,
            encoding: self.encoding,
        })
    }

    async fn in_core_task<F, V>(self, func: F) -> Result<HandledRequest<V>, ApiError>
    where
        V: Send + Sync + 'static,
        F: Fn(Request<Vec<u8>>, Arc<Context<T>>) -> Result<V, ApiError> + Send + Sync + 'static,
    {
        let body = Self::get_body(self.body, self.allow_body).await?;
        let (req_parts, _) = self.req.into_parts();
        let req = Request::from_parts(req_parts, body);

        let value = func(req, self.ctx)?;

        Ok(HandledRequest {
            value,
            encoding: self.encoding,
        })
    }

    async fn in_blocking_task<F, V>(self, func: F) -> Result<HandledRequest<V>, ApiError>
    where
        V: Send + Sync + 'static,
        F: Fn(Request<Vec<u8>>, Arc<Context<T>>) -> Result<V, ApiError> + Send + Sync + 'static,
    {
        let ctx = self.ctx;
        let body = Self::get_body(self.body, self.allow_body).await?;
        let (req_parts, _) = self.req.into_parts();
        let req = Request::from_parts(req_parts, body);

        let value = ctx
            .executor
            .clone()
            .handle
            .spawn_blocking(move || func(req, ctx))
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

    async fn get_body(body: Body, allow_body: bool) -> Result<Vec<u8>, ApiError> {
        let bytes = hyper::body::to_bytes(body)
            .await
            .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}", e)))?;

        if !allow_body && !bytes[..].is_empty() {
            return Err(ApiError::BadRequest(
                "The request body must be empty".to_string(),
            ));
        } else {
            Ok(bytes.into_iter().collect())
        }
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
             * Network syncing status.
             */
            (Method::GET, "/node/syncing") => handler
                .allow_body()
                .in_blocking_task(|_, ctx| node::syncing(ctx))
                .await?
                .serde_encodings(),
            /*
             * ENR of this node.
             */
            (Method::GET, "/network/enr") => handler
                .in_core_task(|_, ctx| Ok(ctx.network_globals.local_enr().to_base64()))
                .await?
                .serde_encodings(),
            /*
             * Count of peers connected to this node.
             */
            (Method::GET, "/network/peer_count") => handler
                .in_core_task(|_, ctx| Ok(ctx.network_globals.connected_peers()))
                .await?
                .serde_encodings(),
            /*
             * Peer id (libp2p) of this node.
             */
            (Method::GET, "/network/peer_id") => handler
                .in_core_task(|_, ctx| Ok(ctx.network_globals.local_peer_id().to_base58()))
                .await?
                .serde_encodings(),
            /*
             * List of peers connected to this node.
             */
            (Method::GET, "/network/peers") => handler
                .in_blocking_task(|_, ctx| Ok(
                    ctx.network_globals.peers
                        .read()
                        .connected_peer_ids()
                        .map(PeerId::to_string)
                        .collect::<Vec<_>>()
                ))
                .await?
                .serde_encodings(),
            /*
             * Returns the TCP port number used by libp2p (not discovery).
             */
            (Method::GET, "/network/listen_port") => handler
                .in_core_task(|_, ctx| Ok(ctx.network_globals.listen_port_tcp()))
                .await?
                .serde_encodings(),
            /*
             * Returns a list of multiaddrs (libp2p) for each address that this node is listening
             * on.
             */
            (Method::GET, "/network/listen_addresses") => handler
                .in_blocking_task(|_, ctx| Ok(ctx.network_globals.listen_multiaddrs()))
                .await?
                .serde_encodings(),
            /*
             * Returns a summary of the head block of the beacon chain.
             */
            (Method::GET, "/beacon/head") => handler
                .in_blocking_task(|_, ctx| beacon::get_head(ctx))
                .await?
                .all_encodings(),
            /*
             * Returns the list of heads of the beacon chain.
             */
            (Method::GET, "/beacon/heads") => handler
                .in_blocking_task(|_, ctx| Ok(beacon::get_heads(ctx)))
                .await?
                .all_encodings(),
            /*
             * Returns a block by slot or root.
             */
            (Method::GET, "/beacon/block") => handler
                .in_blocking_task(beacon::get_block)
                .await?
                .all_encodings(),
            /*
             * Returns the block root in the canonical chain for the given slot.
             */
            (Method::GET, "/beacon/block_root") => handler
                .in_blocking_task(beacon::get_block_root)
                .await?
                .all_encodings(),
            /*
             * Returns the fork of the canonical head.
             */
            (Method::GET, "/beacon/fork") => handler
                .in_blocking_task(|_, ctx| Ok(ctx.beacon_chain.head_info()?.fork))
                .await?
                .all_encodings(),
            /*
             * SSE stream of changes to the canonical head.
             */
            (Method::GET, "/beacon/fork/stream") => {
                todo!()
                /* TODO
                let reader = events.lock().add_rx();
                beacon::stream_forks::<T>(log, reader)
                */
            }
            /*
             * Returns the genesis time of the canonical head.
             */
            (Method::GET, "/beacon/genesis_time") => handler
                .in_blocking_task(|_, ctx| Ok(ctx.beacon_chain.head_info()?.genesis_time))
                .await?
                .all_encodings(),
            /*
             * Returns the genesis validators root of the canonical head.
             */
            (Method::GET, "/beacon/genesis_validators_root") => handler
                .in_blocking_task(|_, ctx| Ok(ctx.beacon_chain.head_info()?.genesis_validators_root))
                .await?
                .all_encodings(),
            /*

            // Methods for Beacon Node
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
            /*
             * Unaggregated attestations from local validators.
             */
            (Method::POST, "/validator/attestations") => handler
                .allow_body()
                .in_blocking_task(validator::publish_attestations_blocking)
                .await?
                .serde_encodings(),
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
