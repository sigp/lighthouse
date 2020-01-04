use crate::{
    beacon, consensus, error::ApiError, helpers, metrics, network, node, spec, validator, BoxFut,
    NetworkChannel,
};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use client_network::Service as NetworkService;
use eth2_config::Eth2Config;
use futures::{Future, IntoFuture};
use hyper::{Body, Error, Method, Request, Response};
use slog::debug;
use std::path::PathBuf;
use std::sync::Arc;

fn into_boxfut<F: IntoFuture + 'static>(item: F) -> BoxFut
where
    F: IntoFuture<Item = Response<Body>, Error = ApiError>,
    F::Future: Send,
{
    Box::new(item.into_future())
}

pub fn route<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
    network_service: Arc<NetworkService<T>>,
    network_channel: NetworkChannel,
    eth2_config: Arc<Eth2Config>,
    local_log: slog::Logger,
    db_path: PathBuf,
    freezer_db_path: PathBuf,
) -> impl Future<Item = Response<Body>, Error = Error> {
    metrics::inc_counter(&metrics::REQUEST_COUNT);
    let timer = metrics::start_timer(&metrics::REQUEST_RESPONSE_TIME);

    let path = req.uri().path().to_string();

    let log = local_log.clone();
    let request_result: Box<dyn Future<Item = Response<_>, Error = _> + Send> =
        match (req.method(), path.as_ref()) {
            // Methods for Client
            (&Method::GET, "/node/version") => into_boxfut(node::get_version(req)),
            (&Method::GET, "/node/syncing") => {
                into_boxfut(helpers::implementation_pending_response(req))
            }

            // Methods for Network
            (&Method::GET, "/network/enr") => {
                into_boxfut(network::get_enr::<T>(req, network_service))
            }
            (&Method::GET, "/network/peer_count") => {
                into_boxfut(network::get_peer_count::<T>(req, network_service))
            }
            (&Method::GET, "/network/peer_id") => {
                into_boxfut(network::get_peer_id::<T>(req, network_service))
            }
            (&Method::GET, "/network/peers") => {
                into_boxfut(network::get_peer_list::<T>(req, network_service))
            }
            (&Method::GET, "/network/listen_port") => {
                into_boxfut(network::get_listen_port::<T>(req, network_service))
            }
            (&Method::GET, "/network/listen_addresses") => {
                into_boxfut(network::get_listen_addresses::<T>(req, network_service))
            }

            // Methods for Beacon Node
            (&Method::GET, "/beacon/head") => into_boxfut(beacon::get_head::<T>(req, beacon_chain)),
            (&Method::GET, "/beacon/heads") => {
                into_boxfut(beacon::get_heads::<T>(req, beacon_chain))
            }
            (&Method::GET, "/beacon/block") => {
                into_boxfut(beacon::get_block::<T>(req, beacon_chain))
            }
            (&Method::GET, "/beacon/block_root") => {
                into_boxfut(beacon::get_block_root::<T>(req, beacon_chain))
            }
            (&Method::GET, "/beacon/fork") => into_boxfut(beacon::get_fork::<T>(req, beacon_chain)),
            (&Method::GET, "/beacon/genesis_time") => {
                into_boxfut(beacon::get_genesis_time::<T>(req, beacon_chain))
            }
            (&Method::GET, "/beacon/validators") => {
                into_boxfut(beacon::get_validators::<T>(req, beacon_chain))
            }
            (&Method::POST, "/beacon/validators") => {
                into_boxfut(beacon::post_validators::<T>(req, beacon_chain))
            }
            (&Method::GET, "/beacon/validators/all") => {
                into_boxfut(beacon::get_all_validators::<T>(req, beacon_chain))
            }
            (&Method::GET, "/beacon/validators/active") => {
                into_boxfut(beacon::get_active_validators::<T>(req, beacon_chain))
            }
            (&Method::GET, "/beacon/state") => {
                into_boxfut(beacon::get_state::<T>(req, beacon_chain))
            }
            (&Method::GET, "/beacon/state_root") => {
                into_boxfut(beacon::get_state_root::<T>(req, beacon_chain))
            }
            (&Method::GET, "/beacon/state/genesis") => {
                into_boxfut(beacon::get_genesis_state::<T>(req, beacon_chain))
            }
            (&Method::GET, "/beacon/committees") => {
                into_boxfut(beacon::get_committees::<T>(req, beacon_chain))
            }

            // Methods for Validator
            (&Method::POST, "/validator/duties") => {
                validator::post_validator_duties::<T>(req, beacon_chain)
            }
            (&Method::GET, "/validator/duties/all") => {
                into_boxfut(validator::get_all_validator_duties::<T>(req, beacon_chain))
            }
            (&Method::GET, "/validator/duties/active") => into_boxfut(
                validator::get_active_validator_duties::<T>(req, beacon_chain),
            ),
            (&Method::GET, "/validator/block") => {
                into_boxfut(validator::get_new_beacon_block::<T>(req, beacon_chain, log))
            }
            (&Method::POST, "/validator/block") => {
                validator::publish_beacon_block::<T>(req, beacon_chain, network_channel, log)
            }
            (&Method::GET, "/validator/attestation") => {
                into_boxfut(validator::get_new_attestation::<T>(req, beacon_chain))
            }
            (&Method::POST, "/validator/attestation") => {
                validator::publish_attestation::<T>(req, beacon_chain, network_channel, log)
            }

            (&Method::GET, "/consensus/global_votes") => {
                into_boxfut(consensus::get_vote_count::<T>(req, beacon_chain))
            }
            (&Method::POST, "/consensus/individual_votes") => {
                consensus::post_individual_votes::<T>(req, beacon_chain)
            }

            // Methods for bootstrap and checking configuration
            (&Method::GET, "/spec") => into_boxfut(spec::get_spec::<T>(req, beacon_chain)),
            (&Method::GET, "/spec/slots_per_epoch") => {
                into_boxfut(spec::get_slots_per_epoch::<T>(req))
            }
            (&Method::GET, "/spec/deposit_contract") => {
                into_boxfut(helpers::implementation_pending_response(req))
            }
            (&Method::GET, "/spec/eth2_config") => {
                into_boxfut(spec::get_eth2_config::<T>(req, eth2_config))
            }

            (&Method::GET, "/metrics") => into_boxfut(metrics::get_prometheus::<T>(
                req,
                beacon_chain,
                db_path,
                freezer_db_path,
            )),

            _ => Box::new(futures::future::err(ApiError::NotFound(
                "Request path and/or method not found.".to_owned(),
            ))),
        };

    // Map the Rust-friendly `Result` in to a http-friendly response. In effect, this ensures that
    // any `Err` returned from our response handlers becomes a valid http response to the client
    // (e.g., a response with a 404 or 500 status).
    request_result.then(move |result| match result {
        Ok(response) => {
            debug!(local_log, "HTTP API request successful"; "path" => path);
            metrics::inc_counter(&metrics::SUCCESS_COUNT);
            metrics::stop_timer(timer);

            Ok(response)
        }
        Err(e) => {
            let error_response = e.into();

            debug!(local_log, "HTTP API request failure"; "path" => path);
            metrics::stop_timer(timer);

            Ok(error_response)
        }
    })
}
