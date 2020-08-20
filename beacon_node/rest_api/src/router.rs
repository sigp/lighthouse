use crate::{
    advanced, beacon,
    config::{ApiEncodingFormat, Config},
    consensus,
    error::ApiError,
    helpers, lighthouse, metrics, node,
    response_builder::ResponseBuilder,
    validator, ApiResult, NetworkChannel,
};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use bus::Bus;
use eth2_config::Eth2Config;
use eth2_libp2p::{NetworkGlobals, PeerId};
use hyper::header::{self, HeaderValue};
use hyper::{body::Bytes, Body, Method, Request, Response, StatusCode};
use lighthouse_version::version_with_platform;
use operation_pool::PersistedOperationPool;
use parking_lot::Mutex;
use rest_types::Health;
use serde::Serialize;
use slog::debug;
use ssz::Encode;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use types::{EthSpec, SignedBeaconBlockHash, Slot};

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
                .in_blocking_task(|_, ctx| {
                    Ok(ctx
                        .network_globals
                        .peers
                        .read()
                        .connected_peer_ids()
                        .map(PeerId::to_string)
                        .collect::<Vec<_>>())
                })
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
                .in_blocking_task(|_, ctx| {
                    Ok(ctx.beacon_chain.head_info()?.genesis_validators_root)
                })
                .await?
                .all_encodings(),
            /*
             * Return a list of all validators in the canonical head state.
             */
            (Method::GET, "/beacon/validators") => handler
                .in_blocking_task(beacon::get_validators)
                .await?
                .all_encodings(),
            (Method::POST, "/beacon/validators") => handler
                .in_blocking_task(beacon::post_validators)
                .await?
                .all_encodings(),
            (Method::GET, "/beacon/validators/all") => handler
                .in_blocking_task(beacon::get_all_validators)
                .await?
                .all_encodings(),
            (Method::GET, "/beacon/validators/active") => handler
                .in_blocking_task(beacon::get_active_validators)
                .await?
                .all_encodings(),
            (Method::GET, "/beacon/state") => handler
                .in_blocking_task(beacon::get_state)
                .await?
                .all_encodings(),
            (Method::GET, "/beacon/state_root") => handler
                .in_blocking_task(beacon::get_state_root)
                .await?
                .all_encodings(),
            (Method::GET, "/beacon/state/genesis") => handler
                .in_blocking_task(|_, ctx| beacon::get_genesis_state(ctx))
                .await?
                .all_encodings(),
            (Method::GET, "/beacon/committees") => handler
                .in_blocking_task(beacon::get_committees)
                .await?
                .all_encodings(),
            (Method::POST, "/beacon/proposer_slashing") => handler
                .in_blocking_task(beacon::proposer_slashing)
                .await?
                .serde_encodings(),
            (Method::POST, "/beacon/attester_slashing") => handler
                .in_blocking_task(beacon::attester_slashing)
                .await?
                .serde_encodings(),
            (Method::POST, "/validator/duties") => handler
                .in_blocking_task(validator::post_validator_duties)
                .await?
                .serde_encodings(),
            (Method::POST, "/validator/subscribe") => handler
                .in_blocking_task(validator::post_validator_subscriptions)
                .await?
                .serde_encodings(),
            (Method::GET, "/validator/duties/all") => handler
                .in_blocking_task(validator::get_all_validator_duties)
                .await?
                .serde_encodings(),
            (Method::GET, "/validator/duties/active") => handler
                .in_blocking_task(validator::get_active_validator_duties)
                .await?
                .serde_encodings(),
            (Method::GET, "/validator/block") => handler
                .in_blocking_task(validator::get_new_beacon_block)
                .await?
                .serde_encodings(),
            (Method::POST, "/validator/block") => handler
                .in_blocking_task(validator::publish_beacon_block)
                .await?
                .serde_encodings(),
            (Method::GET, "/validator/attestation") => handler
                .in_blocking_task(validator::get_new_attestation)
                .await?
                .serde_encodings(),
            (Method::GET, "/validator/aggregate_attestation") => handler
                .in_blocking_task(validator::get_aggregate_attestation)
                .await?
                .serde_encodings(),
            (Method::POST, "/validator/attestations") => handler
                .in_blocking_task(validator::publish_attestations)
                .await?
                .serde_encodings(),
            (Method::POST, "/validator/aggregate_and_proofs") => handler
                .in_blocking_task(validator::publish_aggregate_and_proofs)
                .await?
                .serde_encodings(),
            (Method::GET, "/consensus/global_votes") => handler
                .in_blocking_task(consensus::get_vote_count)
                .await?
                .serde_encodings(),
            (Method::POST, "/consensus/individual_votes") => handler
                .in_blocking_task(consensus::post_individual_votes)
                .await?
                .serde_encodings(),
            (Method::GET, "/spec") => handler
                // TODO: this clone is not ideal.
                .in_blocking_task(|_, ctx| Ok(ctx.beacon_chain.spec.clone()))
                .await?
                .serde_encodings(),
            (Method::GET, "/spec/slots_per_epoch") => handler
                .in_core_task(|_, _| Ok(T::EthSpec::slots_per_epoch()))
                .await?
                .serde_encodings(),
            (Method::GET, "/spec/eth2_config") => handler
                // TODO: this clone is not ideal.
                .in_blocking_task(|_, ctx| Ok(ctx.eth2_config.as_ref().clone()))
                .await?
                .serde_encodings(),
            (Method::GET, "/advanced/fork_choice") => handler
                .in_blocking_task(|_, ctx| {
                    Ok(ctx
                        .beacon_chain
                        .fork_choice
                        .read()
                        .proto_array()
                        .core_proto_array()
                        .clone())
                })
                .await?
                .serde_encodings(),
            (Method::GET, "/advanced/operation_pool") => handler
                .in_blocking_task(|_, ctx| {
                    Ok(PersistedOperationPool::from_operation_pool(
                        &ctx.beacon_chain.op_pool,
                    ))
                })
                .await?
                .serde_encodings(),
            (Method::GET, "/metrics") => handler
                .in_blocking_task(metrics::get_prometheus)
                .await?
                .text_encoding(),
            (Method::GET, "/lighthouse/syncing") => handler
                .in_blocking_task(|_, ctx| Ok(ctx.network_globals.sync_state()))
                .await?
                .serde_encodings(),
            (Method::GET, "/lighthouse/peers") => handler
                .in_blocking_task(|_, ctx| lighthouse::peers(ctx))
                .await?
                .serde_encodings(),
            (Method::GET, "/lighthouse/connected_peers") => handler
                .in_blocking_task(|_, ctx| lighthouse::connected_peers(ctx))
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
