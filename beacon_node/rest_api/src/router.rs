use crate::{
    beacon, config::Config, consensus, lighthouse, metrics, node, validator, NetworkChannel,
};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use bus::Bus;
use environment::TaskExecutor;
use eth2_config::Eth2Config;
use eth2_libp2p::{NetworkGlobals, PeerId};
use hyper::header::HeaderValue;
use hyper::{Body, Method, Request, Response};
use lighthouse_version::version_with_platform;
use operation_pool::PersistedOperationPool;
use parking_lot::Mutex;
use rest_types::{ApiError, Handler, Health};
use slog::debug;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use types::{EthSpec, SignedBeaconBlockHash};

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
        let executor = ctx.executor.clone();
        let handler = Handler::new(req, ctx, executor)?;

        match (method, path.as_ref()) {
            (Method::GET, "/node/version") => handler
                .static_value(version_with_platform())
                .await?
                .text_encoding(),
            (Method::GET, "/node/health") => handler
                .static_value(Health::observe().map_err(ApiError::ServerError)?)
                .await?
                .serde_encodings(),
            (Method::GET, "/node/syncing") => handler
                .allow_body()
                .in_blocking_task(|_, ctx| node::syncing(ctx))
                .await?
                .serde_encodings(),
            (Method::GET, "/network/enr") => handler
                .in_core_task(|_, ctx| Ok(ctx.network_globals.local_enr().to_base64()))
                .await?
                .serde_encodings(),
            (Method::GET, "/network/peer_count") => handler
                .in_core_task(|_, ctx| Ok(ctx.network_globals.connected_peers()))
                .await?
                .serde_encodings(),
            (Method::GET, "/network/peer_id") => handler
                .in_core_task(|_, ctx| Ok(ctx.network_globals.local_peer_id().to_base58()))
                .await?
                .serde_encodings(),
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
            (Method::GET, "/network/listen_port") => handler
                .in_core_task(|_, ctx| Ok(ctx.network_globals.listen_port_tcp()))
                .await?
                .serde_encodings(),
            (Method::GET, "/network/listen_addresses") => handler
                .in_blocking_task(|_, ctx| Ok(ctx.network_globals.listen_multiaddrs()))
                .await?
                .serde_encodings(),
            (Method::GET, "/beacon/head") => handler
                .in_blocking_task(|_, ctx| beacon::get_head(ctx))
                .await?
                .all_encodings(),
            (Method::GET, "/beacon/heads") => handler
                .in_blocking_task(|_, ctx| Ok(beacon::get_heads(ctx)))
                .await?
                .all_encodings(),
            (Method::GET, "/beacon/block") => handler
                .in_blocking_task(beacon::get_block)
                .await?
                .all_encodings(),
            (Method::GET, "/beacon/block_root") => handler
                .in_blocking_task(beacon::get_block_root)
                .await?
                .all_encodings(),
            (Method::GET, "/beacon/fork") => handler
                .in_blocking_task(|_, ctx| Ok(ctx.beacon_chain.head_info()?.fork))
                .await?
                .all_encodings(),
            (Method::GET, "/beacon/fork/stream") => {
                todo!()
                /* TODO
                let reader = events.lock().add_rx();
                beacon::stream_forks::<T>(log, reader)
                */
            }
            (Method::GET, "/beacon/genesis_time") => handler
                .in_blocking_task(|_, ctx| Ok(ctx.beacon_chain.head_info()?.genesis_time))
                .await?
                .all_encodings(),
            (Method::GET, "/beacon/genesis_validators_root") => handler
                .in_blocking_task(|_, ctx| {
                    Ok(ctx.beacon_chain.head_info()?.genesis_validators_root)
                })
                .await?
                .all_encodings(),
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
                .static_value(T::EthSpec::slots_per_epoch())
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
                .in_blocking_task(|_, ctx| metrics::get_prometheus(ctx))
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
