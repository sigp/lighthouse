use crate::{
    advanced, beacon, consensus, error::ApiError, helpers, lighthouse, metrics, network, node,
    spec, validator, NetworkChannel,
};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use bus::Bus;
use eth2_config::Eth2Config;
use eth2_libp2p::NetworkGlobals;
use hyper::{Body, Error, Method, Request, Response};
use parking_lot::Mutex;
use slog::debug;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use types::{SignedBeaconBlockHash, Slot};

// Allowing more than 7 arguments.
#[allow(clippy::too_many_arguments)]
pub async fn route<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    network_channel: NetworkChannel<T::EthSpec>,
    eth2_config: Arc<Eth2Config>,
    local_log: slog::Logger,
    db_path: PathBuf,
    freezer_db_path: PathBuf,
    events: Arc<Mutex<Bus<SignedBeaconBlockHash>>>,
) -> Result<Response<Body>, Error> {
    metrics::inc_counter(&metrics::REQUEST_COUNT);
    let timer = metrics::start_timer(&metrics::REQUEST_RESPONSE_TIME);
    let received_instant = Instant::now();

    let path = req.uri().path().to_string();

    let log = local_log.clone();
    let request_result = match (req.method(), path.as_ref()) {
        // Methods for Client
        (&Method::GET, "/node/health") => node::get_health(req),
        (&Method::GET, "/node/version") => node::get_version(req),
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
        (&Method::GET, "/network/peer_count") => network::get_peer_count::<T>(req, network_globals),
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
        (&Method::GET, "/beacon/genesis_time") => beacon::get_genesis_time::<T>(req, beacon_chain),
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
            let timer = metrics::start_timer(&metrics::VALIDATOR_GET_DUTIES_REQUEST_RESPONSE_TIME);
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
            let timer = metrics::start_timer(&metrics::VALIDATOR_GET_BLOCK_REQUEST_RESPONSE_TIME);
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
            validator::publish_aggregate_and_proofs::<T>(req, beacon_chain, network_channel, log)
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
        (&Method::GET, "/spec/deposit_contract") => helpers::implementation_pending_response(req),
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
    };

    // Map the Rust-friendly `Result` in to a http-friendly response. In effect, this ensures that
    // any `Err` returned from our response handlers becomes a valid http response to the client
    // (e.g., a response with a 404 or 500 status).
    let duration = Instant::now().duration_since(received_instant);
    match request_result {
        Ok(response) => {
            debug!(
                local_log,
                "HTTP API request successful";
                "path" => path,
                "duration_ms" => duration.as_millis()
            );
            metrics::inc_counter(&metrics::SUCCESS_COUNT);
            metrics::stop_timer(timer);

            Ok(response)
        }
        Err(e) => {
            let error_response = e.into();

            debug!(
                local_log,
                "HTTP API request failure";
                "path" => path,
                "duration_ms" => duration.as_millis()
            );
            metrics::stop_timer(timer);

            Ok(error_response)
        }
    }
}
