#![allow(clippy::result_large_err)]
//! This crate contains a HTTP server which serves the endpoints listed here:
//!
//! https://github.com/ethereum/beacon-APIs
//!
//! There are also some additional, non-standard endpoints behind the `/lighthouse/` path which are
//! used for development.

mod aggregate_attestation;
mod attestation_performance;
mod attester_duties;
mod beacon;
mod block_id;
mod block_packing_efficiency;
mod block_rewards;
mod build_block_contents;
mod builder_states;
mod custody;
mod database;
mod light_client;
mod metrics;
mod peer;
mod produce_block;
mod proposer_duties;
mod publish_attestations;
mod publish_blocks;
mod standard_block_rewards;
mod state_id;
mod sync_committee_rewards;
mod sync_committees;
mod task_spawner;
pub mod test_utils;
mod ui;
mod utils;
mod validator;
mod validator_inclusion;
mod validators;
mod version;

use crate::beacon::pool::*;
use crate::light_client::{get_light_client_bootstrap, get_light_client_updates};
use crate::utils::{AnyVersionFilter, EthV1Filter};
use crate::validator::post_validator_liveness_epoch;
use crate::validator::*;
use crate::version::beacon_response;
use beacon::states;
use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes, WhenSlotSkipped};
use beacon_processor::BeaconProcessorSend;
pub use block_id::BlockId;
use builder_states::get_next_withdrawals;
use bytes::Bytes;
use context_deserialize::ContextDeserialize;
use directory::DEFAULT_ROOT_DIR;
use eth2::StatusCode;
use eth2::lighthouse::sync_state::SyncState;
use eth2::types::{
    self as api_types, BroadcastValidation, EndpointVersion, ForkChoice, ForkChoiceExtraData,
    ForkChoiceNode, LightClientUpdatesQuery, PublishBlockRequest, ValidatorId,
};
use eth2::{CONSENSUS_VERSION_HEADER, CONTENT_TYPE_HEADER, SSZ_CONTENT_TYPE_HEADER};
use health_metrics::observe::Observe;
use lighthouse_network::Enr;
use lighthouse_network::NetworkGlobals;
use lighthouse_network::PeerId;
use lighthouse_version::version_with_platform;
use logging::{SSELoggingComponents, crit};
use network::{NetworkMessage, NetworkSenders};
use network_utils::enr_ext::EnrExt;
use parking_lot::RwLock;
pub use publish_blocks::{
    ProvenancedBlock, publish_blinded_block, publish_block, reconstruct_block,
};
use serde::{Deserialize, Serialize};
use slot_clock::SlotClock;
use ssz::Encode;
pub use state_id::StateId;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use sysinfo::{System, SystemExt};
use system_health::{observe_nat, observe_system_health_bn};
use task_spawner::{Priority, TaskSpawner};
use tokio::sync::mpsc::UnboundedSender;
use tokio_stream::{
    StreamExt,
    wrappers::{BroadcastStream, errors::BroadcastStreamRecvError},
};
use tracing::{debug, info, warn};
use types::{
    BeaconStateError, Checkpoint, ConfigAndPreset, Epoch, EthSpec, ForkName, Hash256,
    SignedBlindedBeaconBlock, Slot,
};
use version::{
    ResponseIncludesVersion, V1, V2, add_consensus_version_header, add_ssz_content_type_header,
    execution_optimistic_finalized_beacon_response, inconsistent_fork_rejection,
    unsupported_version_rejection,
};
use warp::Reply;
use warp::hyper::Body;
use warp::sse::Event;
use warp::{Filter, Rejection, http::Response};
use warp_utils::{query::multi_key_query, uor::UnifyingOrFilter};

const API_PREFIX: &str = "eth";

/// A custom type which allows for both unsecured and TLS-enabled HTTP servers.
type HttpServer = (SocketAddr, Pin<Box<dyn Future<Output = ()> + Send>>);

/// Alias for readability.
pub type ExecutionOptimistic = bool;

/// Configuration used when serving the HTTP server over TLS.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// A wrapper around all the items required to spawn the HTTP server.
///
/// The server will gracefully handle the case where any fields are `None`.
pub struct Context<T: BeaconChainTypes> {
    pub config: Config,
    pub chain: Option<Arc<BeaconChain<T>>>,
    pub network_senders: Option<NetworkSenders<T::EthSpec>>,
    pub network_globals: Option<Arc<NetworkGlobals<T::EthSpec>>>,
    pub beacon_processor_send: Option<BeaconProcessorSend<T::EthSpec>>,
    pub sse_logging_components: Option<SSELoggingComponents>,
}

/// Configuration for the HTTP server.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub enabled: bool,
    pub listen_addr: IpAddr,
    pub listen_port: u16,
    pub allow_origin: Option<String>,
    pub tls_config: Option<TlsConfig>,
    pub data_dir: PathBuf,
    pub sse_capacity_multiplier: usize,
    pub enable_beacon_processor: bool,
    #[serde(with = "eth2::types::serde_status_code")]
    pub duplicate_block_status_code: StatusCode,
    pub target_peers: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            listen_port: 5052,
            allow_origin: None,
            tls_config: None,
            data_dir: PathBuf::from(DEFAULT_ROOT_DIR),
            sse_capacity_multiplier: 1,
            enable_beacon_processor: true,
            duplicate_block_status_code: StatusCode::ACCEPTED,
            target_peers: 100,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Warp(warp::Error),
    Other(String),
}

impl From<warp::Error> for Error {
    fn from(e: warp::Error) -> Self {
        Error::Warp(e)
    }
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        Error::Other(e)
    }
}

/// Creates a `warp` logging wrapper which we use for Prometheus metrics (not necessarily logging,
/// per say).
pub fn prometheus_metrics() -> warp::filters::log::Log<impl Fn(warp::filters::log::Info) + Clone> {
    warp::log::custom(move |info| {
        // Here we restrict the `info.path()` value to some predefined values. Without this, we end
        // up with a new metric type each time someone includes something unique in the path (e.g.,
        // a block hash).
        let path = {
            let equals = |s: &'static str| -> Option<&'static str> {
                if info.path() == format!("/{}/{}", API_PREFIX, s) {
                    Some(s)
                } else {
                    None
                }
            };

            let starts_with = |s: &'static str| -> Option<&'static str> {
                if info.path().starts_with(&format!("/{}/{}", API_PREFIX, s)) {
                    Some(s)
                } else {
                    None
                }
            };

            // First line covers `POST /v1/beacon/blocks` only
            equals("v1/beacon/blocks")
                .or_else(|| starts_with("v2/beacon/blocks"))
                .or_else(|| starts_with("v1/beacon/blob_sidecars"))
                .or_else(|| starts_with("v1/beacon/blobs"))
                .or_else(|| starts_with("v1/beacon/blocks/head/root"))
                .or_else(|| starts_with("v1/beacon/blinded_blocks"))
                .or_else(|| starts_with("v2/beacon/blinded_blocks"))
                .or_else(|| starts_with("v1/beacon/headers"))
                .or_else(|| starts_with("v1/beacon/light_client"))
                .or_else(|| starts_with("v1/beacon/pool/attestations"))
                .or_else(|| starts_with("v2/beacon/pool/attestations"))
                .or_else(|| starts_with("v1/beacon/pool/attester_slashings"))
                .or_else(|| starts_with("v1/beacon/pool/bls_to_execution_changes"))
                .or_else(|| starts_with("v1/beacon/pool/proposer_slashings"))
                .or_else(|| starts_with("v1/beacon/pool/sync_committees"))
                .or_else(|| starts_with("v1/beacon/pool/voluntary_exits"))
                .or_else(|| starts_with("v1/beacon/rewards/blocks"))
                .or_else(|| starts_with("v1/beacon/rewards/attestations"))
                .or_else(|| starts_with("v1/beacon/rewards/sync_committee"))
                .or_else(|| starts_with("v1/beacon/rewards"))
                .or_else(|| starts_with("v1/beacon/states"))
                .or_else(|| starts_with("v1/beacon/"))
                .or_else(|| starts_with("v2/beacon/"))
                .or_else(|| starts_with("v1/builder/states"))
                .or_else(|| starts_with("v1/config/deposit_contract"))
                .or_else(|| starts_with("v1/config/fork_schedule"))
                .or_else(|| starts_with("v1/config/spec"))
                .or_else(|| starts_with("v1/config/"))
                .or_else(|| starts_with("v1/debug/"))
                .or_else(|| starts_with("v2/debug/"))
                .or_else(|| starts_with("v1/events"))
                .or_else(|| starts_with("v1/events/"))
                .or_else(|| starts_with("v1/node/health"))
                .or_else(|| starts_with("v1/node/identity"))
                .or_else(|| starts_with("v1/node/peers"))
                .or_else(|| starts_with("v1/node/peer_count"))
                .or_else(|| starts_with("v1/node/syncing"))
                .or_else(|| starts_with("v1/node/version"))
                .or_else(|| starts_with("v1/node"))
                .or_else(|| starts_with("v1/validator/aggregate_and_proofs"))
                .or_else(|| starts_with("v2/validator/aggregate_and_proofs"))
                .or_else(|| starts_with("v1/validator/aggregate_attestation"))
                .or_else(|| starts_with("v2/validator/aggregate_attestation"))
                .or_else(|| starts_with("v1/validator/attestation_data"))
                .or_else(|| starts_with("v1/validator/beacon_committee_subscriptions"))
                .or_else(|| starts_with("v1/validator/blinded_blocks"))
                .or_else(|| starts_with("v2/validator/blinded_blocks"))
                .or_else(|| starts_with("v1/validator/blocks"))
                .or_else(|| starts_with("v2/validator/blocks"))
                .or_else(|| starts_with("v3/validator/blocks"))
                .or_else(|| starts_with("v1/validator/contribution_and_proofs"))
                .or_else(|| starts_with("v1/validator/duties/attester"))
                .or_else(|| starts_with("v1/validator/duties/proposer"))
                .or_else(|| starts_with("v1/validator/duties/sync"))
                .or_else(|| starts_with("v1/validator/liveness"))
                .or_else(|| starts_with("v1/validator/prepare_beacon_proposer"))
                .or_else(|| starts_with("v1/validator/register_validator"))
                .or_else(|| starts_with("v1/validator/sync_committee_contribution"))
                .or_else(|| starts_with("v1/validator/sync_committee_subscriptions"))
                .or_else(|| starts_with("v1/validator/"))
                .or_else(|| starts_with("v2/validator/"))
                .or_else(|| starts_with("v3/validator/"))
                .or_else(|| starts_with("lighthouse"))
                .unwrap_or("other")
        };

        metrics::inc_counter_vec(&metrics::HTTP_API_PATHS_TOTAL, &[path]);
        metrics::inc_counter_vec(
            &metrics::HTTP_API_STATUS_CODES_TOTAL,
            &[&info.status().to_string()],
        );
        metrics::observe_timer_vec(&metrics::HTTP_API_PATHS_TIMES, &[path], info.elapsed());
    })
}

/// Creates a `warp` logging wrapper which we use to create `tracing` logs.
pub fn tracing_logging() -> warp::filters::log::Log<impl Fn(warp::filters::log::Info) + Clone> {
    warp::log::custom(move |info| {
        let status = info.status();
        // Ensure elapsed time is in milliseconds.
        let elapsed = info.elapsed().as_secs_f64() * 1000.0;
        let path = info.path();
        let method = info.method().to_string();

        if status.is_success() {
            debug!(
                elapsed_ms = %elapsed,
                status = %status,
                path = %path,
                method = %method,
                "Processed HTTP API request"
            );
        } else {
            warn!(
                elapsed_ms = %elapsed,
                status = %status,
                path = %path,
                method = %method,
                "Error processing HTTP API request"
            );
        }
    })
}

/// Creates a server that will serve requests using information from `ctx`.
///
/// The server will shut down gracefully when the `shutdown` future resolves.
///
/// ## Returns
///
/// This function will bind the server to the provided address and then return a tuple of:
///
/// - `SocketAddr`: the address that the HTTP server will listen on.
/// - `Future`: the actual server future that will need to be awaited.
///
/// ## Errors
///
/// Returns an error if the server is unable to bind or there is another error during
/// configuration.
pub fn serve<T: BeaconChainTypes>(
    ctx: Arc<Context<T>>,
    shutdown: impl Future<Output = ()> + Send + Sync + 'static,
) -> Result<HttpServer, Error> {
    let config = ctx.config.clone();

    // Configure CORS.
    let cors_builder = {
        let builder = warp::cors()
            .allow_methods(vec!["GET", "POST"])
            .allow_headers(vec!["Content-Type"]);

        warp_utils::cors::set_builder_origins(
            builder,
            config.allow_origin.as_deref(),
            (config.listen_addr, config.listen_port),
        )?
    };

    // Sanity check.
    if !config.enabled {
        crit!("Cannot start disabled HTTP server");
        return Err(Error::Other(
            "A disabled server should not be started".to_string(),
        ));
    }

    // Create a filter that extracts the endpoint version.
    let any_version = warp::path(API_PREFIX)
        .and(
            warp::path::param::<EndpointVersion>().or_else(|_| async move {
                Err(warp_utils::reject::custom_bad_request(
                    "Invalid version identifier".to_string(),
                ))
            }),
        )
        .boxed();

    // Filter that enforces a single endpoint version and then discards the `EndpointVersion`.
    fn single_version(any_version: AnyVersionFilter, reqd: EndpointVersion) -> EthV1Filter {
        any_version
            .and_then(move |version| async move {
                if version == reqd {
                    Ok(())
                } else {
                    Err(unsupported_version_rejection(version))
                }
            })
            .untuple_one()
            .boxed()
    }

    let eth_v1 = single_version(any_version.clone(), V1);
    let eth_v2 = single_version(any_version.clone(), V2);

    // Create a `warp` filter that provides access to the network globals.
    let inner_network_globals = ctx.network_globals.clone();
    let network_globals = warp::any()
        .map(move || inner_network_globals.clone())
        .and_then(|network_globals| async move {
            match network_globals {
                Some(globals) => Ok(globals),
                None => Err(warp_utils::reject::custom_not_found(
                    "network globals are not initialized.".to_string(),
                )),
            }
        });

    // Create a `warp` filter for the data_dir.
    let inner_data_dir = ctx.config.data_dir.clone();
    let data_dir_filter = warp::any().map(move || inner_data_dir.clone());

    // Create a `warp` filter that provides access to the beacon chain.
    let inner_ctx = ctx.clone();
    let chain_filter = warp::any()
        .map(move || inner_ctx.chain.clone())
        .and_then(|chain| async move {
            match chain {
                Some(chain) => Ok(chain),
                None => Err(warp_utils::reject::custom_not_found(
                    "Beacon chain genesis has not yet been observed.".to_string(),
                )),
            }
        })
        .boxed();

    // Create a `warp` filter that provides access to the network sender channel.
    let network_tx = ctx
        .network_senders
        .as_ref()
        .map(|senders| senders.network_send());
    let network_tx_filter = warp::any()
        .map(move || network_tx.clone())
        .and_then(|network_tx| async move {
            match network_tx {
                Some(network_tx) => Ok(network_tx),
                None => Err(warp_utils::reject::custom_not_found(
                    "The networking stack has not yet started (network_tx).".to_string(),
                )),
            }
        })
        .boxed();

    // Create a `warp` filter that provides access to the network attestation subscription channel.
    let validator_subscriptions_tx = ctx
        .network_senders
        .as_ref()
        .map(|senders| senders.validator_subscription_send());
    let validator_subscription_tx_filter = warp::any()
        .map(move || validator_subscriptions_tx.clone())
        .and_then(|validator_subscriptions_tx| async move {
            match validator_subscriptions_tx {
                Some(validator_subscriptions_tx) => Ok(validator_subscriptions_tx),
                None => Err(warp_utils::reject::custom_not_found(
                    "The networking stack has not yet started (validator_subscription_tx)."
                        .to_string(),
                )),
            }
        })
        .boxed();

    // Create a `warp` filter that rejects requests whilst the node is syncing.
    let not_while_syncing_filter =
        warp::any()
            .and(network_globals.clone())
            .and(chain_filter.clone())
            .then(
                move |network_globals: Arc<NetworkGlobals<T::EthSpec>>,
                      chain: Arc<BeaconChain<T>>| async move {
                    match *network_globals.sync_state.read() {
                        SyncState::SyncingFinalized { .. } | SyncState::SyncingHead { .. } => {
                            let head_slot = chain.canonical_head.cached_head().head_slot();

                            let current_slot =
                                chain.slot_clock.now_or_genesis().ok_or_else(|| {
                                    warp_utils::reject::custom_server_error(
                                        "unable to read slot clock".to_string(),
                                    )
                                })?;

                            let tolerance =
                                chain.config.sync_tolerance_epochs * T::EthSpec::slots_per_epoch();

                            if head_slot + tolerance >= current_slot {
                                Ok(())
                            } else {
                                Err(warp_utils::reject::not_synced(format!(
                                    "head slot is {}, current slot is {}",
                                    head_slot, current_slot
                                )))
                            }
                        }
                        SyncState::SyncTransition
                        | SyncState::BackFillSyncing { .. }
                        | SyncState::CustodyBackFillSyncing { .. } => Ok(()),
                        SyncState::Synced => Ok(()),
                        SyncState::Stalled => Ok(()),
                    }
                },
            )
            .boxed();

    // Create a `warp` filter that returns 404s if the light client server is disabled.
    let light_client_server_filter =
        warp::any()
            .and(chain_filter.clone())
            .then(|chain: Arc<BeaconChain<T>>| async move {
                if chain.config.enable_light_client_server {
                    Ok(())
                } else {
                    Err(warp::reject::not_found())
                }
            });

    let inner_components = ctx.sse_logging_components.clone();
    let sse_component_filter = warp::any().map(move || inner_components.clone());

    // Create a `warp` filter that provides access to local system information.
    let system_info = Arc::new(RwLock::new(sysinfo::System::new()));
    {
        // grab write access for initialisation
        let mut system_info = system_info.write();
        system_info.refresh_disks_list();
        system_info.refresh_networks_list();
        system_info.refresh_cpu_specifics(sysinfo::CpuRefreshKind::everything());
        system_info.refresh_cpu();
    } // end lock

    let system_info_filter =
        warp::any()
            .map(move || system_info.clone())
            .map(|sysinfo: Arc<RwLock<System>>| {
                {
                    // refresh stats
                    let mut sysinfo_lock = sysinfo.write();
                    sysinfo_lock.refresh_memory();
                    sysinfo_lock.refresh_cpu_specifics(sysinfo::CpuRefreshKind::everything());
                    sysinfo_lock.refresh_cpu();
                    sysinfo_lock.refresh_system();
                    sysinfo_lock.refresh_networks();
                    sysinfo_lock.refresh_disks();
                } // end lock
                sysinfo
            });

    let app_start = std::time::Instant::now();
    let app_start_filter = warp::any().map(move || app_start);

    // Create a `warp` filter that provides access to the `TaskSpawner`.
    let beacon_processor_send = ctx
        .beacon_processor_send
        .clone()
        .filter(|_| config.enable_beacon_processor);
    let task_spawner_filter = warp::any()
        .map(move || TaskSpawner::new(beacon_processor_send.clone()))
        .boxed();

    let duplicate_block_status_code = ctx.config.duplicate_block_status_code;

    /*
     *
     * Start of HTTP method definitions.
     *
     */

    // GET beacon/genesis
    let get_beacon_genesis = eth_v1
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("genesis"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>, chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let genesis_data = api_types::GenesisData {
                        genesis_time: chain.genesis_time,
                        genesis_validators_root: chain.genesis_validators_root,
                        genesis_fork_version: chain.spec.genesis_fork_version,
                    };
                    Ok(api_types::GenericResponse::from(genesis_data))
                })
            },
        );

    /*
     * beacon/states/{state_id}
     */

    let beacon_states_path = eth_v1
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("states"))
        .and(warp::path::param::<StateId>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid state ID".to_string(),
            ))
        }))
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .boxed();

    // GET beacon/states/{state_id}/root
    let get_beacon_state_root = states::get_beacon_state_root(beacon_states_path.clone());

    // GET beacon/states/{state_id}/fork
    let get_beacon_state_fork = states::get_beacon_state_fork(beacon_states_path.clone());

    // GET beacon/states/{state_id}/finality_checkpoints
    let get_beacon_state_finality_checkpoints =
        states::get_beacon_state_finality_checkpoints(beacon_states_path.clone());

    // GET beacon/states/{state_id}/validator_balances?id
    let get_beacon_state_validator_balances =
        states::get_beacon_state_validator_balances(beacon_states_path.clone());

    // POST beacon/states/{state_id}/validator_balances
    let post_beacon_state_validator_balances =
        states::post_beacon_state_validator_balances(beacon_states_path.clone());

    // POST beacon/states/{state_id}/validator_identities
    let post_beacon_state_validator_identities =
        states::post_beacon_state_validator_identities(beacon_states_path.clone());

    // GET beacon/states/{state_id}/validators?id,status
    let get_beacon_state_validators =
        states::get_beacon_state_validators(beacon_states_path.clone());

    // POST beacon/states/{state_id}/validators
    let post_beacon_state_validators =
        states::post_beacon_state_validators(beacon_states_path.clone());

    // GET beacon/states/{state_id}/validators/{validator_id}
    let get_beacon_state_validators_id =
        states::get_beacon_state_validators_id(beacon_states_path.clone());

    // GET beacon/states/{state_id}/committees?slot,index,epoch
    let get_beacon_state_committees =
        states::get_beacon_state_committees(beacon_states_path.clone());

    // GET beacon/states/{state_id}/sync_committees?epoch
    let get_beacon_state_sync_committees =
        states::get_beacon_state_sync_committees(beacon_states_path.clone());

    // GET beacon/states/{state_id}/randao?epoch
    let get_beacon_state_randao = states::get_beacon_state_randao(beacon_states_path.clone());

    // GET beacon/states/{state_id}/pending_deposits
    let get_beacon_state_pending_deposits =
        states::get_beacon_state_pending_deposits(beacon_states_path.clone());

    // GET beacon/states/{state_id}/pending_partial_withdrawals
    let get_beacon_state_pending_partial_withdrawals =
        states::get_beacon_state_pending_partial_withdrawals(beacon_states_path.clone());

    // GET beacon/states/{state_id}/pending_consolidations
    let get_beacon_state_pending_consolidations =
        states::get_beacon_state_pending_consolidations(beacon_states_path.clone());

    // GET beacon/headers
    //
    // Note: this endpoint only returns information about blocks in the canonical chain. Given that
    // there's a `canonical` flag on the response, I assume it should also return non-canonical
    // things. Returning non-canonical things is hard for us since we don't already have a
    // mechanism for arbitrary forwards block iteration, we only support iterating forwards along
    // the canonical chain.
    let get_beacon_headers = eth_v1
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("headers"))
        .and(warp::query::<api_types::HeadersQuery>())
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |query: api_types::HeadersQuery,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let (root, block, execution_optimistic, finalized) =
                        match (query.slot, query.parent_root) {
                            // No query parameters, return the canonical head block.
                            (None, None) => {
                                let (cached_head, execution_status) = chain
                                    .canonical_head
                                    .head_and_execution_status()
                                    .map_err(warp_utils::reject::unhandled_error)?;
                                (
                                    cached_head.head_block_root(),
                                    cached_head.snapshot.beacon_block.clone_as_blinded(),
                                    execution_status.is_optimistic_or_invalid(),
                                    false,
                                )
                            }
                            // Only the parent root parameter, do a forwards-iterator lookup.
                            (None, Some(parent_root)) => {
                                let (parent, execution_optimistic, _parent_finalized) =
                                    BlockId::from_root(parent_root).blinded_block(&chain)?;
                                let (root, _slot) = chain
                                    .forwards_iter_block_roots(parent.slot())
                                    .map_err(warp_utils::reject::unhandled_error)?
                                    // Ignore any skip-slots immediately following the parent.
                                    .find(|res| {
                                        res.as_ref().is_ok_and(|(root, _)| *root != parent_root)
                                    })
                                    .transpose()
                                    .map_err(warp_utils::reject::unhandled_error)?
                                    .ok_or_else(|| {
                                        warp_utils::reject::custom_not_found(format!(
                                            "child of block with root {}",
                                            parent_root
                                        ))
                                    })?;

                                BlockId::from_root(root)
                                    .blinded_block(&chain)
                                    // Ignore this `execution_optimistic` since the first value has
                                    // more information about the original request.
                                    .map(|(block, _execution_optimistic, finalized)| {
                                        (root, block, execution_optimistic, finalized)
                                    })?
                            }
                            // Slot is supplied, search by slot and optionally filter by
                            // parent root.
                            (Some(slot), parent_root_opt) => {
                                let (root, execution_optimistic, finalized) =
                                    BlockId::from_slot(slot).root(&chain)?;
                                // Ignore the second `execution_optimistic`, the first one is the
                                // most relevant since it knows that we queried by slot.
                                let (block, _execution_optimistic, _finalized) =
                                    BlockId::from_root(root).blinded_block(&chain)?;

                                // If the parent root was supplied, check that it matches the block
                                // obtained via a slot lookup.
                                if let Some(parent_root) = parent_root_opt
                                    && block.parent_root() != parent_root
                                {
                                    return Err(warp_utils::reject::custom_not_found(format!(
                                        "no canonical block at slot {} with parent root {}",
                                        slot, parent_root
                                    )));
                                }

                                (root, block, execution_optimistic, finalized)
                            }
                        };

                    let data = api_types::BlockHeaderData {
                        root,
                        canonical: true,
                        header: api_types::BlockHeaderAndSignature {
                            message: block.message().block_header(),
                            signature: block.signature().clone().into(),
                        },
                    };

                    Ok(api_types::GenericResponse::from(vec![data])
                        .add_execution_optimistic_finalized(execution_optimistic, finalized))
                })
            },
        );

    // GET beacon/headers/{block_id}
    let get_beacon_headers_block_id = eth_v1
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("headers"))
        .and(warp::path::param::<BlockId>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid block ID".to_string(),
            ))
        }))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |block_id: BlockId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let (root, execution_optimistic, finalized) = block_id.root(&chain)?;
                    // Ignore the second `execution_optimistic` since the first one has more
                    // information about the original request.
                    let (block, _execution_optimistic, _finalized) =
                        BlockId::from_root(root).blinded_block(&chain)?;

                    let canonical = chain
                        .block_root_at_slot(block.slot(), WhenSlotSkipped::None)
                        .map_err(warp_utils::reject::unhandled_error)?
                        .is_some_and(|canonical| root == canonical);

                    let data = api_types::BlockHeaderData {
                        root,
                        canonical,
                        header: api_types::BlockHeaderAndSignature {
                            message: block.message().block_header(),
                            signature: block.signature().clone().into(),
                        },
                    };

                    Ok(api_types::ExecutionOptimisticFinalizedResponse {
                        execution_optimistic: Some(execution_optimistic),
                        finalized: Some(finalized),
                        data,
                    })
                })
            },
        );

    /*
     * beacon/blocks
     */
    let consensus_version_header_filter =
        warp::header::header::<ForkName>(CONSENSUS_VERSION_HEADER).boxed();

    let optional_consensus_version_header_filter =
        warp::header::optional::<ForkName>(CONSENSUS_VERSION_HEADER).boxed();

    // POST beacon/blocks
    let post_beacon_blocks = eth_v1
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("blocks"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(consensus_version_header_filter.clone())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .and(network_tx_filter.clone())
        .then(
            move |value: serde_json::Value,
                  consensus_version: ForkName,
                  task_spawner: TaskSpawner<T::EthSpec>,
                  chain: Arc<BeaconChain<T>>,
                  network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    let request = PublishBlockRequest::<T::EthSpec>::context_deserialize(
                        &value,
                        consensus_version,
                    )
                    .map_err(|e| {
                        warp_utils::reject::custom_bad_request(format!("invalid JSON: {e:?}"))
                    })?;
                    publish_blocks::publish_block(
                        None,
                        ProvenancedBlock::local_from_publish_request(request),
                        chain,
                        &network_tx,
                        BroadcastValidation::default(),
                        duplicate_block_status_code,
                    )
                    .await
                })
            },
        );

    let post_beacon_blocks_ssz = eth_v1
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("blocks"))
        .and(warp::path::end())
        .and(warp::body::bytes())
        .and(consensus_version_header_filter.clone())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .and(network_tx_filter.clone())
        .then(
            move |block_bytes: Bytes,
                  consensus_version: ForkName,
                  task_spawner: TaskSpawner<T::EthSpec>,
                  chain: Arc<BeaconChain<T>>,
                  network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    let block_contents = PublishBlockRequest::<T::EthSpec>::from_ssz_bytes(
                        &block_bytes,
                        consensus_version,
                    )
                    .map_err(|e| {
                        warp_utils::reject::custom_bad_request(format!("invalid SSZ: {e:?}"))
                    })?;
                    publish_blocks::publish_block(
                        None,
                        ProvenancedBlock::local_from_publish_request(block_contents),
                        chain,
                        &network_tx,
                        BroadcastValidation::default(),
                        duplicate_block_status_code,
                    )
                    .await
                })
            },
        );

    let post_beacon_blocks_v2 = eth_v2
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("blocks"))
        .and(warp::query::<api_types::BroadcastValidationQuery>())
        .and(warp::path::end())
        .and(warp::body::json())
        .and(consensus_version_header_filter.clone())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .and(network_tx_filter.clone())
        .then(
            move |validation_level: api_types::BroadcastValidationQuery,
                  value: serde_json::Value,
                  consensus_version: ForkName,
                  task_spawner: TaskSpawner<T::EthSpec>,
                  chain: Arc<BeaconChain<T>>,
                  network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    let request = PublishBlockRequest::<T::EthSpec>::context_deserialize(
                        &value,
                        consensus_version,
                    )
                    .map_err(|e| {
                        warp_utils::reject::custom_bad_request(format!("invalid JSON: {e:?}"))
                    })?;

                    publish_blocks::publish_block(
                        None,
                        ProvenancedBlock::local_from_publish_request(request),
                        chain,
                        &network_tx,
                        validation_level.broadcast_validation,
                        duplicate_block_status_code,
                    )
                    .await
                })
            },
        );

    let post_beacon_blocks_v2_ssz = eth_v2
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("blocks"))
        .and(warp::query::<api_types::BroadcastValidationQuery>())
        .and(warp::path::end())
        .and(warp::body::bytes())
        .and(consensus_version_header_filter.clone())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .and(network_tx_filter.clone())
        .then(
            move |validation_level: api_types::BroadcastValidationQuery,
                  block_bytes: Bytes,
                  consensus_version: ForkName,
                  task_spawner: TaskSpawner<T::EthSpec>,
                  chain: Arc<BeaconChain<T>>,
                  network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    let block_contents = PublishBlockRequest::<T::EthSpec>::from_ssz_bytes(
                        &block_bytes,
                        consensus_version,
                    )
                    .map_err(|e| {
                        warp_utils::reject::custom_bad_request(format!("invalid SSZ: {e:?}"))
                    })?;
                    publish_blocks::publish_block(
                        None,
                        ProvenancedBlock::local_from_publish_request(block_contents),
                        chain,
                        &network_tx,
                        validation_level.broadcast_validation,
                        duplicate_block_status_code,
                    )
                    .await
                })
            },
        );

    /*
     * beacon/blinded_blocks
     */

    // POST beacon/blinded_blocks
    let post_beacon_blinded_blocks = eth_v1
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("blinded_blocks"))
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .and(network_tx_filter.clone())
        .then(
            move |block_contents: Arc<SignedBlindedBeaconBlock<T::EthSpec>>,
                  task_spawner: TaskSpawner<T::EthSpec>,
                  chain: Arc<BeaconChain<T>>,
                  network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    publish_blocks::publish_blinded_block(
                        block_contents,
                        chain,
                        &network_tx,
                        BroadcastValidation::default(),
                        duplicate_block_status_code,
                    )
                    .await
                })
            },
        );

    // POST beacon/blocks
    let post_beacon_blinded_blocks_ssz = eth_v1
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("blinded_blocks"))
        .and(warp::path::end())
        .and(warp::body::bytes())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .and(network_tx_filter.clone())
        .then(
            move |block_bytes: Bytes,
                  task_spawner: TaskSpawner<T::EthSpec>,
                  chain: Arc<BeaconChain<T>>,
                  network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    let block = SignedBlindedBeaconBlock::<T::EthSpec>::from_ssz_bytes(
                        &block_bytes,
                        &chain.spec,
                    )
                    .map(Arc::new)
                    .map_err(|e| {
                        warp_utils::reject::custom_bad_request(format!("invalid SSZ: {e:?}"))
                    })?;
                    publish_blocks::publish_blinded_block(
                        block,
                        chain,
                        &network_tx,
                        BroadcastValidation::default(),
                        duplicate_block_status_code,
                    )
                    .await
                })
            },
        );

    let post_beacon_blinded_blocks_v2 = eth_v2
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("blinded_blocks"))
        .and(warp::query::<api_types::BroadcastValidationQuery>())
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .and(consensus_version_header_filter)
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .and(network_tx_filter.clone())
        .then(
            move |validation_level: api_types::BroadcastValidationQuery,
                  blinded_block_json: serde_json::Value,
                  consensus_version: ForkName,
                  task_spawner: TaskSpawner<T::EthSpec>,
                  chain: Arc<BeaconChain<T>>,
                  network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    let blinded_block =
                        SignedBlindedBeaconBlock::<T::EthSpec>::context_deserialize(
                            &blinded_block_json,
                            consensus_version,
                        )
                        .map(Arc::new)
                        .map_err(|e| {
                            warp_utils::reject::custom_bad_request(format!("invalid JSON: {e:?}"))
                        })?;
                    publish_blocks::publish_blinded_block(
                        blinded_block,
                        chain,
                        &network_tx,
                        validation_level.broadcast_validation,
                        duplicate_block_status_code,
                    )
                    .await
                })
            },
        );

    let post_beacon_blinded_blocks_v2_ssz = eth_v2
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("blinded_blocks"))
        .and(warp::query::<api_types::BroadcastValidationQuery>())
        .and(warp::path::end())
        .and(warp::body::bytes())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .and(network_tx_filter.clone())
        .then(
            move |validation_level: api_types::BroadcastValidationQuery,
                  block_bytes: Bytes,
                  task_spawner: TaskSpawner<T::EthSpec>,
                  chain: Arc<BeaconChain<T>>,
                  network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.spawn_async_with_rejection(Priority::P0, async move {
                    let block = SignedBlindedBeaconBlock::<T::EthSpec>::from_ssz_bytes(
                        &block_bytes,
                        &chain.spec,
                    )
                    .map(Arc::new)
                    .map_err(|e| {
                        warp_utils::reject::custom_bad_request(format!("invalid SSZ: {e:?}"))
                    })?;
                    publish_blocks::publish_blinded_block(
                        block,
                        chain,
                        &network_tx,
                        validation_level.broadcast_validation,
                        duplicate_block_status_code,
                    )
                    .await
                })
            },
        );

    let block_id_or_err = warp::path::param::<BlockId>().or_else(|_| async {
        Err(warp_utils::reject::custom_bad_request(
            "Invalid block ID".to_string(),
        ))
    });

    let beacon_blocks_path_v1 = eth_v1
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("blocks"))
        .and(block_id_or_err)
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone());

    let beacon_blocks_path_any = any_version
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("blocks"))
        .and(block_id_or_err)
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone());

    // GET beacon/blocks/{block_id}
    let get_beacon_block = beacon_blocks_path_any
        .clone()
        .and(warp::path::end())
        .and(warp::header::optional::<api_types::Accept>("accept"))
        .then(
            |endpoint_version: EndpointVersion,
             block_id: BlockId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             accept_header: Option<api_types::Accept>| {
                task_spawner.spawn_async_with_rejection(Priority::P1, async move {
                    let (block, execution_optimistic, finalized) =
                        block_id.full_block(&chain).await?;
                    let fork_name = block
                        .fork_name(&chain.spec)
                        .map_err(inconsistent_fork_rejection)?;

                    let require_version = match endpoint_version {
                        V1 => ResponseIncludesVersion::No,
                        V2 => ResponseIncludesVersion::Yes(fork_name),
                        _ => return Err(unsupported_version_rejection(endpoint_version)),
                    };

                    match accept_header {
                        Some(api_types::Accept::Ssz) => Response::builder()
                            .status(200)
                            .body(block.as_ssz_bytes().into())
                            .map(|res: Response<Body>| add_ssz_content_type_header(res))
                            .map_err(|e| {
                                warp_utils::reject::custom_server_error(format!(
                                    "failed to create response: {}",
                                    e
                                ))
                            }),
                        _ => execution_optimistic_finalized_beacon_response(
                            require_version,
                            execution_optimistic,
                            finalized,
                            block,
                        )
                        .map(|res| warp::reply::json(&res).into_response()),
                    }
                    .map(|resp| add_consensus_version_header(resp, fork_name))
                })
            },
        );

    // GET beacon/blocks/{block_id}/root
    let get_beacon_block_root = beacon_blocks_path_v1
        .clone()
        .and(warp::path("root"))
        .and(warp::path::end())
        .then(
            |block_id: BlockId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                // Prioritise requests for the head block root, as it is used by some VCs (including
                // the Lighthouse VC) to create sync committee messages.
                let priority = if let BlockId(eth2::types::BlockId::Head) = block_id {
                    Priority::P0
                } else {
                    Priority::P1
                };
                task_spawner.blocking_json_task(priority, move || {
                    // Fast-path for the head block root. We read from the early attester cache
                    // so that we can produce sync committee messages for the new head prior
                    // to it being fully imported (written to the DB/etc). We also check that the
                    // cache is not stale or out of date by comparing against the cached head
                    // prior to using it.
                    //
                    // See: https://github.com/sigp/lighthouse/issues/8667
                    let (block_root, execution_optimistic, finalized) =
                        if let BlockId(eth2::types::BlockId::Head) = block_id
                            && let Some((head_block_slot, head_block_root)) =
                                chain.early_attester_cache.get_head_block_root()
                            && head_block_slot >= chain.canonical_head.cached_head().head_slot()
                        {
                            // We know execution is NOT optimistic if the block is from the early
                            // attester cache because only properly validated blocks are added.
                            // Similarly we know it is NOT finalized.
                            let execution_optimistic = false;
                            let finalized = false;
                            (head_block_root, execution_optimistic, finalized)
                        } else {
                            block_id.root(&chain)?
                        };
                    Ok(
                        api_types::GenericResponse::from(api_types::RootData::from(block_root))
                            .add_execution_optimistic_finalized(execution_optimistic, finalized),
                    )
                })
            },
        );

    // GET beacon/blocks/{block_id}/attestations
    let get_beacon_block_attestations = beacon_blocks_path_any
        .clone()
        .and(warp::path("attestations"))
        .and(warp::path::end())
        .then(
            |endpoint_version: EndpointVersion,
             block_id: BlockId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    let (block, execution_optimistic, finalized) =
                        block_id.blinded_block(&chain)?;
                    let fork_name = block
                        .fork_name(&chain.spec)
                        .map_err(inconsistent_fork_rejection)?;
                    let atts = block
                        .message()
                        .body()
                        .attestations()
                        .map(|att| att.clone_as_attestation())
                        .collect::<Vec<_>>();

                    let require_version = match endpoint_version {
                        V1 => ResponseIncludesVersion::No,
                        V2 => ResponseIncludesVersion::Yes(fork_name),
                        _ => return Err(unsupported_version_rejection(endpoint_version)),
                    };

                    let res = execution_optimistic_finalized_beacon_response(
                        require_version,
                        execution_optimistic,
                        finalized,
                        &atts,
                    )?;
                    Ok(add_consensus_version_header(
                        warp::reply::json(&res).into_response(),
                        fork_name,
                    ))
                })
            },
        );

    // GET beacon/blinded_blocks/{block_id}
    let get_beacon_blinded_block = eth_v1
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("blinded_blocks"))
        .and(block_id_or_err)
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .and(warp::path::end())
        .and(warp::header::optional::<api_types::Accept>("accept"))
        .then(
            |block_id: BlockId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             accept_header: Option<api_types::Accept>| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    let (block, execution_optimistic, finalized) =
                        block_id.blinded_block(&chain)?;
                    let fork_name = block
                        .fork_name(&chain.spec)
                        .map_err(inconsistent_fork_rejection)?;

                    match accept_header {
                        Some(api_types::Accept::Ssz) => Response::builder()
                            .status(200)
                            .body(block.as_ssz_bytes().into())
                            .map(|res: Response<Body>| add_ssz_content_type_header(res))
                            .map_err(|e| {
                                warp_utils::reject::custom_server_error(format!(
                                    "failed to create response: {}",
                                    e
                                ))
                            }),
                        _ => {
                            // Post as a V2 endpoint so we return the fork version.
                            execution_optimistic_finalized_beacon_response(
                                ResponseIncludesVersion::Yes(fork_name),
                                execution_optimistic,
                                finalized,
                                block,
                            )
                            .map(|res| warp::reply::json(&res).into_response())
                        }
                    }
                    .map(|resp| add_consensus_version_header(resp, fork_name))
                })
            },
        );

    /*
     * beacon/blob_sidecars
     */

    // GET beacon/blob_sidecars/{block_id}
    let get_blob_sidecars = eth_v1
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("blob_sidecars"))
        .and(block_id_or_err)
        .and(warp::path::end())
        .and(multi_key_query::<api_types::BlobIndicesQuery>())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .and(warp::header::optional::<api_types::Accept>("accept"))
        .then(
            |block_id: BlockId,
             indices_res: Result<api_types::BlobIndicesQuery, warp::Rejection>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             accept_header: Option<api_types::Accept>| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    let indices = indices_res?;
                    let (block, blob_sidecar_list_filtered, execution_optimistic, finalized) =
                        block_id.get_blinded_block_and_blob_list_filtered(indices, &chain)?;
                    let fork_name = block
                        .fork_name(&chain.spec)
                        .map_err(inconsistent_fork_rejection)?;

                    match accept_header {
                        Some(api_types::Accept::Ssz) => Response::builder()
                            .status(200)
                            .body(blob_sidecar_list_filtered.as_ssz_bytes().into())
                            .map(|res: Response<Body>| add_ssz_content_type_header(res))
                            .map_err(|e| {
                                warp_utils::reject::custom_server_error(format!(
                                    "failed to create response: {}",
                                    e
                                ))
                            }),
                        _ => {
                            // Post as a V2 endpoint so we return the fork version.
                            let res = execution_optimistic_finalized_beacon_response(
                                ResponseIncludesVersion::Yes(fork_name),
                                execution_optimistic,
                                finalized,
                                &blob_sidecar_list_filtered,
                            )?;
                            Ok(warp::reply::json(&res).into_response())
                        }
                    }
                    .map(|resp| add_consensus_version_header(resp, fork_name))
                })
            },
        );

    // GET beacon/blobs/{block_id}
    let get_blobs = eth_v1
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("blobs"))
        .and(block_id_or_err)
        .and(warp::path::end())
        .and(multi_key_query::<api_types::BlobsVersionedHashesQuery>())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .and(warp::header::optional::<api_types::Accept>("accept"))
        .then(
            |block_id: BlockId,
             version_hashes_res: Result<api_types::BlobsVersionedHashesQuery, warp::Rejection>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             accept_header: Option<api_types::Accept>| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    let versioned_hashes = version_hashes_res?;
                    let response =
                        block_id.get_blobs_by_versioned_hashes(versioned_hashes, &chain)?;

                    match accept_header {
                        Some(api_types::Accept::Ssz) => Response::builder()
                            .status(200)
                            .body(response.data.as_ssz_bytes().into())
                            .map(|res: Response<Body>| add_ssz_content_type_header(res))
                            .map_err(|e| {
                                warp_utils::reject::custom_server_error(format!(
                                    "failed to create response: {}",
                                    e
                                ))
                            }),
                        _ => {
                            let res = execution_optimistic_finalized_beacon_response(
                                ResponseIncludesVersion::No,
                                response.metadata.execution_optimistic.unwrap_or(false),
                                response.metadata.finalized.unwrap_or(false),
                                response.data,
                            )?;
                            Ok(warp::reply::json(&res).into_response())
                        }
                    }
                })
            },
        );

    /*
     * beacon/pool
     */

    let beacon_pool_path = eth_v1
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("pool"))
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .boxed();

    let beacon_pool_path_v2 = eth_v2
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("pool"))
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .boxed();

    let beacon_pool_path_any = any_version
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("pool"))
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .boxed();

    let post_beacon_pool_attestations_v2 = post_beacon_pool_attestations_v2(
        &network_tx_filter,
        optional_consensus_version_header_filter,
        &beacon_pool_path_v2,
    );

    // GET beacon/pool/attestations?committee_index,slot
    let get_beacon_pool_attestations = get_beacon_pool_attestations(&beacon_pool_path_any);

    // POST beacon/pool/attester_slashings
    let post_beacon_pool_attester_slashings =
        post_beacon_pool_attester_slashings(&network_tx_filter, &beacon_pool_path_any);

    // GET beacon/pool/attester_slashings
    let get_beacon_pool_attester_slashings =
        get_beacon_pool_attester_slashings(&beacon_pool_path_any);

    // POST beacon/pool/proposer_slashings
    let post_beacon_pool_proposer_slashings =
        post_beacon_pool_proposer_slashings(&network_tx_filter, &beacon_pool_path);

    // GET beacon/pool/proposer_slashings
    let get_beacon_pool_proposer_slashings = get_beacon_pool_proposer_slashings(&beacon_pool_path);

    // POST beacon/pool/voluntary_exits
    let post_beacon_pool_voluntary_exits =
        post_beacon_pool_voluntary_exits(&network_tx_filter, &beacon_pool_path);

    // GET beacon/pool/voluntary_exits
    let get_beacon_pool_voluntary_exits = get_beacon_pool_voluntary_exits(&beacon_pool_path);

    // POST beacon/pool/sync_committees
    let post_beacon_pool_sync_committees =
        post_beacon_pool_sync_committees(&network_tx_filter, &beacon_pool_path);

    // GET beacon/pool/bls_to_execution_changes
    let get_beacon_pool_bls_to_execution_changes =
        get_beacon_pool_bls_to_execution_changes(&beacon_pool_path);

    // POST beacon/pool/bls_to_execution_changes
    let post_beacon_pool_bls_to_execution_changes =
        post_beacon_pool_bls_to_execution_changes(&network_tx_filter, &beacon_pool_path);

    let beacon_rewards_path = eth_v1
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("rewards"))
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone());

    // GET beacon/rewards/blocks/{block_id}
    let get_beacon_rewards_blocks = beacon_rewards_path
        .clone()
        .and(warp::path("blocks"))
        .and(block_id_or_err)
        .and(warp::path::end())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             block_id: BlockId| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let (rewards, execution_optimistic, finalized) =
                        standard_block_rewards::compute_beacon_block_rewards(chain, block_id)?;
                    Ok(api_types::GenericResponse::from(rewards)).map(|resp| {
                        resp.add_execution_optimistic_finalized(execution_optimistic, finalized)
                    })
                })
            },
        );

    /*
     * builder/states
     */

    let builder_states_path = eth_v1
        .clone()
        .and(warp::path("builder"))
        .and(warp::path("states"))
        .and(chain_filter.clone());

    // GET builder/states/{state_id}/expected_withdrawals
    let get_expected_withdrawals = builder_states_path
        .clone()
        .and(task_spawner_filter.clone())
        .and(warp::path::param::<StateId>())
        .and(warp::path("expected_withdrawals"))
        .and(warp::query::<api_types::ExpectedWithdrawalsQuery>())
        .and(warp::path::end())
        .and(warp::header::optional::<api_types::Accept>("accept"))
        .then(
            |chain: Arc<BeaconChain<T>>,
             task_spawner: TaskSpawner<T::EthSpec>,
             state_id: StateId,
             query: api_types::ExpectedWithdrawalsQuery,
             accept_header: Option<api_types::Accept>| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    let (state, execution_optimistic, finalized) = state_id.state(&chain)?;
                    let proposal_slot = query.proposal_slot.unwrap_or(state.slot() + 1);
                    let withdrawals =
                        get_next_withdrawals::<T>(&chain, state, state_id, proposal_slot)?;

                    match accept_header {
                        Some(api_types::Accept::Ssz) => Response::builder()
                            .status(200)
                            .body(withdrawals.as_ssz_bytes().into())
                            .map(|res: Response<Body>| add_ssz_content_type_header(res))
                            .map_err(|e| {
                                warp_utils::reject::custom_server_error(format!(
                                    "failed to create response: {}",
                                    e
                                ))
                            }),
                        _ => Ok(warp::reply::json(
                            &api_types::ExecutionOptimisticFinalizedResponse {
                                data: withdrawals,
                                execution_optimistic: Some(execution_optimistic),
                                finalized: Some(finalized),
                            },
                        )
                        .into_response()),
                    }
                })
            },
        );

    /*
     * beacon/light_client
     */

    let beacon_light_client_path = eth_v1
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("light_client"))
        .and(light_client_server_filter)
        .and(chain_filter.clone());

    // GET beacon/light_client/bootstrap/{block_root}
    let get_beacon_light_client_bootstrap = beacon_light_client_path
        .clone()
        .and(task_spawner_filter.clone())
        .and(warp::path("bootstrap"))
        .and(warp::path::param::<Hash256>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid block root value".to_string(),
            ))
        }))
        .and(warp::path::end())
        .and(warp::header::optional::<api_types::Accept>("accept"))
        .then(
            |light_client_server_enabled: Result<(), Rejection>,
             chain: Arc<BeaconChain<T>>,
             task_spawner: TaskSpawner<T::EthSpec>,
             block_root: Hash256,
             accept_header: Option<api_types::Accept>| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    light_client_server_enabled?;
                    get_light_client_bootstrap::<T>(chain, &block_root, accept_header)
                })
            },
        );

    // GET beacon/light_client/optimistic_update
    let get_beacon_light_client_optimistic_update = beacon_light_client_path
        .clone()
        .and(task_spawner_filter.clone())
        .and(warp::path("optimistic_update"))
        .and(warp::path::end())
        .and(warp::header::optional::<api_types::Accept>("accept"))
        .then(
            |light_client_server_enabled: Result<(), Rejection>,
             chain: Arc<BeaconChain<T>>,
             task_spawner: TaskSpawner<T::EthSpec>,
             accept_header: Option<api_types::Accept>| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    light_client_server_enabled?;
                    let update = chain
                        .light_client_server_cache
                        .get_latest_optimistic_update()
                        .ok_or_else(|| {
                            warp_utils::reject::custom_not_found(
                                "No LightClientOptimisticUpdate is available".to_string(),
                            )
                        })?;

                    let fork_name = chain
                        .spec
                        .fork_name_at_slot::<T::EthSpec>(update.get_slot());
                    match accept_header {
                        Some(api_types::Accept::Ssz) => Response::builder()
                            .status(200)
                            .body(update.as_ssz_bytes().into())
                            .map(|res: Response<Body>| add_ssz_content_type_header(res))
                            .map_err(|e| {
                                warp_utils::reject::custom_server_error(format!(
                                    "failed to create response: {}",
                                    e
                                ))
                            }),
                        _ => Ok(warp::reply::json(&beacon_response(
                            ResponseIncludesVersion::Yes(fork_name),
                            update,
                        ))
                        .into_response()),
                    }
                    .map(|resp| add_consensus_version_header(resp, fork_name))
                })
            },
        );

    // GET beacon/light_client/finality_update
    let get_beacon_light_client_finality_update = beacon_light_client_path
        .clone()
        .and(task_spawner_filter.clone())
        .and(warp::path("finality_update"))
        .and(warp::path::end())
        .and(warp::header::optional::<api_types::Accept>("accept"))
        .then(
            |light_client_server_enabled: Result<(), Rejection>,
             chain: Arc<BeaconChain<T>>,
             task_spawner: TaskSpawner<T::EthSpec>,
             accept_header: Option<api_types::Accept>| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    light_client_server_enabled?;
                    let update = chain
                        .light_client_server_cache
                        .get_latest_finality_update()
                        .ok_or_else(|| {
                            warp_utils::reject::custom_not_found(
                                "No LightClientFinalityUpdate is available".to_string(),
                            )
                        })?;

                    let fork_name = chain
                        .spec
                        .fork_name_at_slot::<T::EthSpec>(update.signature_slot());
                    match accept_header {
                        Some(api_types::Accept::Ssz) => Response::builder()
                            .status(200)
                            .body(update.as_ssz_bytes().into())
                            .map(|res: Response<Body>| add_ssz_content_type_header(res))
                            .map_err(|e| {
                                warp_utils::reject::custom_server_error(format!(
                                    "failed to create response: {}",
                                    e
                                ))
                            }),
                        _ => Ok(warp::reply::json(&beacon_response(
                            ResponseIncludesVersion::Yes(fork_name),
                            update,
                        ))
                        .into_response()),
                    }
                    .map(|resp| add_consensus_version_header(resp, fork_name))
                })
            },
        );

    // GET beacon/light_client/updates
    let get_beacon_light_client_updates = beacon_light_client_path
        .clone()
        .and(task_spawner_filter.clone())
        .and(warp::path("updates"))
        .and(warp::path::end())
        .and(warp::query::<api_types::LightClientUpdatesQuery>())
        .and(warp::header::optional::<api_types::Accept>("accept"))
        .then(
            |light_client_server_enabled: Result<(), Rejection>,
             chain: Arc<BeaconChain<T>>,
             task_spawner: TaskSpawner<T::EthSpec>,
             query: LightClientUpdatesQuery,
             accept_header: Option<api_types::Accept>| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    light_client_server_enabled?;
                    get_light_client_updates::<T>(chain, query, accept_header)
                })
            },
        );

    /*
     * beacon/rewards
     */

    let beacon_rewards_path = eth_v1
        .clone()
        .and(warp::path("beacon"))
        .and(warp::path("rewards"))
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone());

    // POST beacon/rewards/attestations/{epoch}
    let post_beacon_rewards_attestations = beacon_rewards_path
        .clone()
        .and(warp::path("attestations"))
        .and(warp::path::param::<Epoch>())
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             epoch: Epoch,
             validators: Vec<ValidatorId>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let attestation_rewards = chain
                        .compute_attestation_rewards(epoch, validators)
                        .map_err(|e| match e {
                            BeaconChainError::MissingBeaconState(root) => {
                                warp_utils::reject::custom_not_found(format!(
                                    "missing state {root:?}",
                                ))
                            }
                            BeaconChainError::NoStateForSlot(slot) => {
                                warp_utils::reject::custom_not_found(format!(
                                    "missing state at slot {slot}"
                                ))
                            }
                            BeaconChainError::BeaconStateError(
                                BeaconStateError::UnknownValidator(validator_index),
                            ) => warp_utils::reject::custom_bad_request(format!(
                                "validator is unknown: {validator_index}"
                            )),
                            BeaconChainError::ValidatorPubkeyUnknown(pubkey) => {
                                warp_utils::reject::custom_bad_request(format!(
                                    "validator pubkey is unknown: {pubkey:?}"
                                ))
                            }
                            e => warp_utils::reject::custom_server_error(format!(
                                "unexpected error: {:?}",
                                e
                            )),
                        })?;
                    let execution_optimistic =
                        chain.is_optimistic_or_invalid_head().unwrap_or_default();

                    Ok(api_types::GenericResponse::from(attestation_rewards))
                        .map(|resp| resp.add_execution_optimistic(execution_optimistic))
                })
            },
        );

    // POST beacon/rewards/sync_committee/{block_id}
    let post_beacon_rewards_sync_committee = beacon_rewards_path
        .clone()
        .and(warp::path("sync_committee"))
        .and(block_id_or_err)
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             block_id: BlockId,
             validators: Vec<ValidatorId>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let (rewards, execution_optimistic, finalized) =
                        sync_committee_rewards::compute_sync_committee_rewards(
                            chain, block_id, validators,
                        )?;

                    Ok(api_types::GenericResponse::from(rewards)).map(|resp| {
                        resp.add_execution_optimistic_finalized(execution_optimistic, finalized)
                    })
                })
            },
        );

    /*
     * config
     */

    let config_path = eth_v1.clone().and(warp::path("config"));

    // GET config/fork_schedule
    let get_config_fork_schedule = config_path
        .clone()
        .and(warp::path("fork_schedule"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>, chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let forks = ForkName::list_all()
                        .into_iter()
                        .filter_map(|fork_name| chain.spec.fork_for_name(fork_name))
                        .collect::<Vec<_>>();
                    Ok(api_types::GenericResponse::from(forks))
                })
            },
        );

    // GET config/spec
    let get_config_spec = config_path
        .clone()
        .and(warp::path("spec"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            move |task_spawner: TaskSpawner<T::EthSpec>, chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    let config_and_preset =
                        ConfigAndPreset::from_chain_spec::<T::EthSpec>(&chain.spec);
                    Ok(api_types::GenericResponse::from(config_and_preset))
                })
            },
        );

    // GET config/deposit_contract
    let get_config_deposit_contract = config_path
        .and(warp::path("deposit_contract"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>, chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    Ok(api_types::GenericResponse::from(
                        api_types::DepositContractData {
                            address: chain.spec.deposit_contract_address,
                            chain_id: chain.spec.deposit_chain_id,
                        },
                    ))
                })
            },
        );

    /*
     * debug
     */

    // GET debug/beacon/data_column_sidecars/{block_id}
    let get_debug_data_column_sidecars = eth_v1
        .clone()
        .and(warp::path("debug"))
        .and(warp::path("beacon"))
        .and(warp::path("data_column_sidecars"))
        .and(block_id_or_err)
        .and(warp::path::end())
        .and(multi_key_query::<api_types::DataColumnIndicesQuery>())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .and(warp::header::optional::<api_types::Accept>("accept"))
        .then(
            |block_id: BlockId,
             indices_res: Result<api_types::DataColumnIndicesQuery, warp::Rejection>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             accept_header: Option<api_types::Accept>| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    let indices = indices_res?;
                    let (data_columns, fork_name, execution_optimistic, finalized) =
                        block_id.get_data_columns(indices, &chain)?;

                    match accept_header {
                        Some(api_types::Accept::Ssz) => Response::builder()
                            .status(200)
                            .body(data_columns.as_ssz_bytes().into())
                            .map(|res: Response<Body>| add_ssz_content_type_header(res))
                            .map_err(|e| {
                                warp_utils::reject::custom_server_error(format!(
                                    "failed to create response: {}",
                                    e
                                ))
                            }),
                        _ => {
                            // Post as a V2 endpoint so we return the fork version.
                            let res = execution_optimistic_finalized_beacon_response(
                                ResponseIncludesVersion::Yes(fork_name),
                                execution_optimistic,
                                finalized,
                                &data_columns,
                            )?;
                            Ok(warp::reply::json(&res).into_response())
                        }
                    }
                    .map(|resp| add_consensus_version_header(resp, fork_name))
                })
            },
        );

    // GET debug/beacon/states/{state_id}
    let get_debug_beacon_states = any_version
        .clone()
        .and(warp::path("debug"))
        .and(warp::path("beacon"))
        .and(warp::path("states"))
        .and(warp::path::param::<StateId>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid state ID".to_string(),
            ))
        }))
        .and(warp::path::end())
        .and(warp::header::optional::<api_types::Accept>("accept"))
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |_endpoint_version: EndpointVersion,
             state_id: StateId,
             accept_header: Option<api_types::Accept>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_response_task(Priority::P1, move || match accept_header {
                    Some(api_types::Accept::Ssz) => {
                        // We can ignore the optimistic status for the "fork" since it's a
                        // specification constant that doesn't change across competing heads of the
                        // beacon chain.
                        let t = std::time::Instant::now();
                        let (state, _execution_optimistic, _finalized) = state_id.state(&chain)?;
                        let fork_name = state
                            .fork_name(&chain.spec)
                            .map_err(inconsistent_fork_rejection)?;
                        let timer = metrics::start_timer(&metrics::HTTP_API_STATE_SSZ_ENCODE_TIMES);
                        let response_bytes = state.as_ssz_bytes();
                        drop(timer);
                        debug!(
                            total_time_ms = t.elapsed().as_millis(),
                            target_slot = %state.slot(),
                            "HTTP state load"
                        );

                        Response::builder()
                            .status(200)
                            .body(response_bytes.into())
                            .map(|res: Response<Body>| add_ssz_content_type_header(res))
                            .map(|resp: warp::reply::Response| {
                                add_consensus_version_header(resp, fork_name)
                            })
                            .map_err(|e| {
                                warp_utils::reject::custom_server_error(format!(
                                    "failed to create response: {}",
                                    e
                                ))
                            })
                    }
                    _ => state_id.map_state_and_execution_optimistic_and_finalized(
                        &chain,
                        |state, execution_optimistic, finalized| {
                            let fork_name = state
                                .fork_name(&chain.spec)
                                .map_err(inconsistent_fork_rejection)?;
                            let res = execution_optimistic_finalized_beacon_response(
                                ResponseIncludesVersion::Yes(fork_name),
                                execution_optimistic,
                                finalized,
                                &state,
                            )?;
                            Ok(add_consensus_version_header(
                                warp::reply::json(&res).into_response(),
                                fork_name,
                            ))
                        },
                    ),
                })
            },
        );

    // GET debug/beacon/heads
    let get_debug_beacon_heads = any_version
        .clone()
        .and(warp::path("debug"))
        .and(warp::path("beacon"))
        .and(warp::path("heads"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |endpoint_version: EndpointVersion,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let heads = chain
                        .heads()
                        .into_iter()
                        .map(|(root, slot)| {
                            let execution_optimistic = if endpoint_version == V1 {
                                None
                            } else if endpoint_version == V2 {
                                chain
                                    .canonical_head
                                    .fork_choice_read_lock()
                                    .is_optimistic_or_invalid_block(&root)
                                    .ok()
                            } else {
                                return Err(unsupported_version_rejection(endpoint_version));
                            };
                            Ok(api_types::ChainHeadData {
                                slot,
                                root,
                                execution_optimistic,
                            })
                        })
                        .collect::<Result<Vec<_>, warp::Rejection>>();
                    Ok(api_types::GenericResponse::from(heads?))
                })
            },
        );

    // GET debug/fork_choice
    let get_debug_fork_choice = eth_v1
        .clone()
        .and(warp::path("debug"))
        .and(warp::path("fork_choice"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>, chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let beacon_fork_choice = chain.canonical_head.fork_choice_read_lock();

                    let proto_array = beacon_fork_choice.proto_array().core_proto_array();

                    let fork_choice_nodes = proto_array
                        .nodes
                        .iter()
                        .map(|node| {
                            let execution_status = if node.execution_status.is_execution_enabled() {
                                Some(node.execution_status.to_string())
                            } else {
                                None
                            };

                            ForkChoiceNode {
                                slot: node.slot,
                                block_root: node.root,
                                parent_root: node
                                    .parent
                                    .and_then(|index| proto_array.nodes.get(index))
                                    .map(|parent| parent.root),
                                justified_epoch: node.justified_checkpoint.epoch,
                                finalized_epoch: node.finalized_checkpoint.epoch,
                                weight: node.weight,
                                validity: execution_status,
                                execution_block_hash: node
                                    .execution_status
                                    .block_hash()
                                    .map(|block_hash| block_hash.into_root()),
                                extra_data: ForkChoiceExtraData {
                                    target_root: node.target_root,
                                    justified_root: node.justified_checkpoint.root,
                                    finalized_root: node.finalized_checkpoint.root,
                                    unrealized_justified_root: node
                                        .unrealized_justified_checkpoint
                                        .map(|checkpoint| checkpoint.root),
                                    unrealized_finalized_root: node
                                        .unrealized_finalized_checkpoint
                                        .map(|checkpoint| checkpoint.root),
                                    unrealized_justified_epoch: node
                                        .unrealized_justified_checkpoint
                                        .map(|checkpoint| checkpoint.epoch),
                                    unrealized_finalized_epoch: node
                                        .unrealized_finalized_checkpoint
                                        .map(|checkpoint| checkpoint.epoch),
                                    execution_status: node.execution_status.to_string(),
                                    best_child: node
                                        .best_child
                                        .and_then(|index| proto_array.nodes.get(index))
                                        .map(|child| child.root),
                                    best_descendant: node
                                        .best_descendant
                                        .and_then(|index| proto_array.nodes.get(index))
                                        .map(|descendant| descendant.root),
                                },
                            }
                        })
                        .collect::<Vec<_>>();
                    Ok(ForkChoice {
                        justified_checkpoint: beacon_fork_choice.justified_checkpoint(),
                        finalized_checkpoint: beacon_fork_choice.finalized_checkpoint(),
                        fork_choice_nodes,
                    })
                })
            },
        );

    /*
     * node
     */

    // GET node/identity
    let get_node_identity = eth_v1
        .clone()
        .and(warp::path("node"))
        .and(warp::path("identity"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(network_globals.clone())
        .and(chain_filter.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>,
             network_globals: Arc<NetworkGlobals<T::EthSpec>>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let enr = network_globals.local_enr();
                    let p2p_addresses = enr.multiaddr_p2p_tcp();
                    let discovery_addresses = enr.multiaddr_p2p_udp();
                    Ok(api_types::GenericResponse::from(api_types::IdentityData {
                        peer_id: network_globals.local_peer_id().to_base58(),
                        enr: enr.to_base64(),
                        p2p_addresses: p2p_addresses.iter().map(|a| a.to_string()).collect(),
                        discovery_addresses: discovery_addresses
                            .iter()
                            .map(|a| a.to_string())
                            .collect(),
                        metadata: utils::from_meta_data::<T::EthSpec>(
                            &network_globals.local_metadata,
                            &chain.spec,
                        ),
                    }))
                })
            },
        );

    // GET node/version
    let get_node_version = eth_v1
        .clone()
        .and(warp::path("node"))
        .and(warp::path("version"))
        .and(warp::path::end())
        // Bypass the `task_spawner` since this method returns a static string.
        .then(|| async {
            warp::reply::json(&api_types::GenericResponse::from(api_types::VersionData {
                version: version_with_platform(),
            }))
            .into_response()
        });

    // GET node/syncing
    let get_node_syncing = eth_v1
        .clone()
        .and(warp::path("node"))
        .and(warp::path("syncing"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(network_globals.clone())
        .and(chain_filter.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>,
             network_globals: Arc<NetworkGlobals<T::EthSpec>>,
             chain: Arc<BeaconChain<T>>| {
                async move {
                    let el_offline = if let Some(el) = &chain.execution_layer {
                        el.is_offline_or_erroring().await
                    } else {
                        true
                    };

                    task_spawner
                        .blocking_json_task(Priority::P0, move || {
                            let (head, head_execution_status) = chain
                                .canonical_head
                                .head_and_execution_status()
                                .map_err(warp_utils::reject::unhandled_error)?;
                            let head_slot = head.head_slot();
                            let current_slot =
                                chain.slot_clock.now_or_genesis().ok_or_else(|| {
                                    warp_utils::reject::custom_server_error(
                                        "Unable to read slot clock".into(),
                                    )
                                })?;

                            // Taking advantage of saturating subtraction on slot.
                            let sync_distance = current_slot - head_slot;

                            let is_optimistic = head_execution_status.is_optimistic_or_invalid();

                            // When determining sync status, make an exception for single-node
                            // testnets with 0 peers.
                            let sync_state = network_globals.sync_state.read();
                            let is_synced = sync_state.is_synced()
                                || (sync_state.is_stalled()
                                    && network_globals.config.target_peers == 0);
                            drop(sync_state);

                            let syncing_data = api_types::SyncingData {
                                is_syncing: !is_synced,
                                is_optimistic,
                                el_offline,
                                head_slot,
                                sync_distance,
                            };

                            Ok(api_types::GenericResponse::from(syncing_data))
                        })
                        .await
                }
            },
        );

    // GET node/health
    let get_node_health = eth_v1
        .clone()
        .and(warp::path("node"))
        .and(warp::path("health"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(network_globals.clone())
        .and(chain_filter.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>,
             network_globals: Arc<NetworkGlobals<T::EthSpec>>,
             chain: Arc<BeaconChain<T>>| {
                async move {
                    let el_offline = if let Some(el) = &chain.execution_layer {
                        el.is_offline_or_erroring().await
                    } else {
                        true
                    };

                    task_spawner
                        .blocking_response_task(Priority::P0, move || {
                            let is_optimistic = chain
                                .is_optimistic_or_invalid_head()
                                .map_err(warp_utils::reject::unhandled_error)?;

                            let is_syncing = !network_globals.sync_state.read().is_synced();

                            if el_offline {
                                Err(warp_utils::reject::not_synced(
                                    "execution layer is offline".to_string(),
                                ))
                            } else if is_syncing || is_optimistic {
                                Ok(warp::reply::with_status(
                                    warp::reply(),
                                    warp::http::StatusCode::PARTIAL_CONTENT,
                                ))
                            } else {
                                Ok(warp::reply::with_status(
                                    warp::reply(),
                                    warp::http::StatusCode::OK,
                                ))
                            }
                        })
                        .await
                }
            },
        );

    // GET node/peers/{peer_id}
    let get_node_peers_by_id = eth_v1
        .clone()
        .and(warp::path("node"))
        .and(warp::path("peers"))
        .and(warp::path::param::<String>())
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(network_globals.clone())
        .then(
            |requested_peer_id: String,
             task_spawner: TaskSpawner<T::EthSpec>,
             network_globals: Arc<NetworkGlobals<T::EthSpec>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let peer_id = PeerId::from_bytes(
                        &bs58::decode(requested_peer_id.as_str())
                            .into_vec()
                            .map_err(|e| {
                                warp_utils::reject::custom_bad_request(format!(
                                    "invalid peer id: {}",
                                    e
                                ))
                            })?,
                    )
                    .map_err(|_| {
                        warp_utils::reject::custom_bad_request("invalid peer id.".to_string())
                    })?;

                    if let Some(peer_info) = network_globals.peers.read().peer_info(&peer_id) {
                        let address = if let Some(multiaddr) = peer_info.seen_multiaddrs().next() {
                            multiaddr.to_string()
                        } else if let Some(addr) = peer_info.listening_addresses().first() {
                            addr.to_string()
                        } else {
                            String::new()
                        };

                        // the eth2 API spec implies only peers we have been connected to at some point should be included.
                        if let Some(&dir) = peer_info.connection_direction() {
                            return Ok(api_types::GenericResponse::from(api_types::PeerData {
                                peer_id: peer_id.to_string(),
                                enr: peer_info.enr().map(|enr| enr.to_base64()),
                                last_seen_p2p_address: address,
                                direction: dir.into(),
                                state: peer_info.connection_status().clone().into(),
                            }));
                        }
                    }
                    Err(warp_utils::reject::custom_not_found(
                        "peer not found.".to_string(),
                    ))
                })
            },
        );

    // GET node/peers
    let get_node_peers = eth_v1
        .clone()
        .and(warp::path("node"))
        .and(warp::path("peers"))
        .and(warp::path::end())
        .and(multi_key_query::<api_types::PeersQuery>())
        .and(task_spawner_filter.clone())
        .and(network_globals.clone())
        .then(
            |query_res: Result<api_types::PeersQuery, warp::Rejection>,
             task_spawner: TaskSpawner<T::EthSpec>,
             network_globals: Arc<NetworkGlobals<T::EthSpec>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let query = query_res?;
                    let mut peers: Vec<api_types::PeerData> = Vec::new();
                    network_globals
                        .peers
                        .read()
                        .peers()
                        .for_each(|(peer_id, peer_info)| {
                            let address =
                                if let Some(multiaddr) = peer_info.seen_multiaddrs().next() {
                                    multiaddr.to_string()
                                } else if let Some(addr) = peer_info.listening_addresses().first() {
                                    addr.to_string()
                                } else {
                                    String::new()
                                };

                            // the eth2 API spec implies only peers we have been connected to at some point should be included.
                            if let Some(&dir) = peer_info.connection_direction() {
                                let direction = dir.into();
                                let state = peer_info.connection_status().clone().into();

                                let state_matches = query
                                    .state
                                    .as_ref()
                                    .is_none_or(|states| states.contains(&state));
                                let direction_matches = query
                                    .direction
                                    .as_ref()
                                    .is_none_or(|directions| directions.contains(&direction));

                                if state_matches && direction_matches {
                                    peers.push(api_types::PeerData {
                                        peer_id: peer_id.to_string(),
                                        enr: peer_info.enr().map(|enr| enr.to_base64()),
                                        last_seen_p2p_address: address,
                                        direction,
                                        state,
                                    });
                                }
                            }
                        });
                    Ok(api_types::PeersData {
                        meta: api_types::PeersMetaData {
                            count: peers.len() as u64,
                        },
                        data: peers,
                    })
                })
            },
        );

    // GET node/peer_count
    let get_node_peer_count = eth_v1
        .clone()
        .and(warp::path("node"))
        .and(warp::path("peer_count"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(network_globals.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>,
             network_globals: Arc<NetworkGlobals<T::EthSpec>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let mut connected: u64 = 0;
                    let mut connecting: u64 = 0;
                    let mut disconnected: u64 = 0;
                    let mut disconnecting: u64 = 0;

                    network_globals
                        .peers
                        .read()
                        .peers()
                        .for_each(|(_, peer_info)| {
                            let state =
                                api_types::PeerState::from(peer_info.connection_status().clone());
                            match state {
                                api_types::PeerState::Connected => connected += 1,
                                api_types::PeerState::Connecting => connecting += 1,
                                api_types::PeerState::Disconnected => disconnected += 1,
                                api_types::PeerState::Disconnecting => disconnecting += 1,
                            }
                        });

                    Ok(api_types::GenericResponse::from(api_types::PeerCount {
                        connected,
                        connecting,
                        disconnected,
                        disconnecting,
                    }))
                })
            },
        );
    /*
     * validator
     */

    // GET validator/duties/proposer/{epoch}
    let get_validator_duties_proposer = get_validator_duties_proposer(
        eth_v1.clone().clone(),
        chain_filter.clone(),
        not_while_syncing_filter.clone(),
        task_spawner_filter.clone(),
    );

    // GET validator/blocks/{slot}
    let get_validator_blocks = get_validator_blocks(
        any_version.clone().clone(),
        chain_filter.clone(),
        not_while_syncing_filter.clone(),
        task_spawner_filter.clone(),
    );

    // GET validator/blinded_blocks/{slot}
    let get_validator_blinded_blocks = get_validator_blinded_blocks(
        eth_v1.clone().clone(),
        chain_filter.clone(),
        not_while_syncing_filter.clone(),
        task_spawner_filter.clone(),
    );

    // GET validator/attestation_data?slot,committee_index
    let get_validator_attestation_data = get_validator_attestation_data(
        eth_v1.clone().clone(),
        chain_filter.clone(),
        not_while_syncing_filter.clone(),
        task_spawner_filter.clone(),
    );

    // GET validator/aggregate_attestation?attestation_data_root,slot
    let get_validator_aggregate_attestation = get_validator_aggregate_attestation(
        any_version.clone().clone(),
        chain_filter.clone(),
        not_while_syncing_filter.clone(),
        task_spawner_filter.clone(),
    );

    // POST validator/duties/attester/{epoch}
    let post_validator_duties_attester = post_validator_duties_attester(
        eth_v1.clone().clone(),
        chain_filter.clone(),
        not_while_syncing_filter.clone(),
        task_spawner_filter.clone(),
    );

    // POST validator/duties/sync/{epoch}
    let post_validator_duties_sync = post_validator_duties_sync(
        eth_v1.clone().clone(),
        chain_filter.clone(),
        not_while_syncing_filter.clone(),
        task_spawner_filter.clone(),
    );

    // GET validator/sync_committee_contribution
    let get_validator_sync_committee_contribution = get_validator_sync_committee_contribution(
        eth_v1.clone().clone(),
        chain_filter.clone(),
        not_while_syncing_filter.clone(),
        task_spawner_filter.clone(),
    );

    // POST validator/aggregate_and_proofs
    let post_validator_aggregate_and_proofs = post_validator_aggregate_and_proofs(
        any_version.clone().clone(),
        chain_filter.clone(),
        network_tx_filter.clone(),
        not_while_syncing_filter.clone(),
        task_spawner_filter.clone(),
    );

    let post_validator_contribution_and_proofs = post_validator_contribution_and_proofs(
        eth_v1.clone().clone(),
        chain_filter.clone(),
        network_tx_filter.clone(),
        not_while_syncing_filter.clone(),
        task_spawner_filter.clone(),
    );

    // POST validator/beacon_committee_subscriptions
    let post_validator_beacon_committee_subscriptions =
        post_validator_beacon_committee_subscriptions(
            eth_v1.clone().clone(),
            chain_filter.clone(),
            validator_subscription_tx_filter.clone(),
            task_spawner_filter.clone(),
        );

    // POST validator/prepare_beacon_proposer
    let post_validator_prepare_beacon_proposer = post_validator_prepare_beacon_proposer(
        eth_v1.clone().clone(),
        chain_filter.clone(),
        network_tx_filter.clone(),
        not_while_syncing_filter.clone(),
        task_spawner_filter.clone(),
    );

    // POST validator/register_validator
    let post_validator_register_validator = post_validator_register_validator(
        eth_v1.clone().clone(),
        chain_filter.clone(),
        task_spawner_filter.clone(),
    );
    // POST validator/sync_committee_subscriptions
    let post_validator_sync_committee_subscriptions = post_validator_sync_committee_subscriptions(
        eth_v1.clone().clone(),
        chain_filter.clone(),
        validator_subscription_tx_filter.clone(),
        task_spawner_filter.clone(),
    );

    // POST validator/liveness/{epoch}
    let post_validator_liveness_epoch = post_validator_liveness_epoch(
        eth_v1.clone().clone(),
        chain_filter.clone(),
        task_spawner_filter.clone(),
    );

    // POST lighthouse/finalize
    let post_lighthouse_finalize = warp::path("lighthouse")
        .and(warp::path("finalize"))
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |request_data: api_types::ManualFinalizationRequestData,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    let checkpoint = Checkpoint {
                        epoch: request_data.epoch,
                        root: request_data.block_root,
                    };

                    chain
                        .manually_finalize_state(request_data.state_root, checkpoint)
                        .map(|_| api_types::GenericResponse::from(request_data))
                        .map_err(|e| {
                            warp_utils::reject::custom_bad_request(format!(
                                "Failed to finalize state due to error: {e:?}"
                            ))
                        })
                })
            },
        );

    // POST lighthouse/compaction
    let post_lighthouse_compaction = warp::path("lighthouse")
        .and(warp::path("compaction"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>, chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    chain.manually_compact_database();
                    Ok(api_types::GenericResponse::from(String::from(
                        "Triggered manual compaction",
                    )))
                })
            },
        );

    // POST lighthouse/add_peer
    let post_lighthouse_add_peer = warp::path("lighthouse")
        .and(warp::path("add_peer"))
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .and(task_spawner_filter.clone())
        .and(network_globals.clone())
        .and(network_tx_filter.clone())
        .then(
            |request_data: api_types::AdminPeer,
             task_spawner: TaskSpawner<T::EthSpec>,
             network_globals: Arc<NetworkGlobals<T::EthSpec>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    let enr = Enr::from_str(&request_data.enr).map_err(|e| {
                        warp_utils::reject::custom_bad_request(format!("invalid enr error {}", e))
                    })?;
                    info!(
                        peer_id = %enr.peer_id(),
                        multiaddr = ?enr.multiaddr(),
                        "Adding trusted peer"
                    );
                    network_globals.add_trusted_peer(enr.clone());

                    utils::publish_network_message(
                        &network_tx,
                        NetworkMessage::ConnectTrustedPeer(enr),
                    )?;

                    Ok(())
                })
            },
        );

    // POST lighthouse/remove_peer
    let post_lighthouse_remove_peer = warp::path("lighthouse")
        .and(warp::path("remove_peer"))
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .and(task_spawner_filter.clone())
        .and(network_globals.clone())
        .and(network_tx_filter.clone())
        .then(
            |request_data: api_types::AdminPeer,
             task_spawner: TaskSpawner<T::EthSpec>,
             network_globals: Arc<NetworkGlobals<T::EthSpec>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    let enr = Enr::from_str(&request_data.enr).map_err(|e| {
                        warp_utils::reject::custom_bad_request(format!("invalid enr error {}", e))
                    })?;
                    info!(
                        peer_id = %enr.peer_id(),
                        multiaddr = ?enr.multiaddr(),
                        "Removing trusted peer"
                    );
                    network_globals.remove_trusted_peer(enr.clone());

                    utils::publish_network_message(
                        &network_tx,
                        NetworkMessage::DisconnectTrustedPeer(enr),
                    )?;

                    Ok(())
                })
            },
        );

    // POST lighthouse/liveness
    let post_lighthouse_liveness = warp::path("lighthouse")
        .and(warp::path("liveness"))
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |request_data: api_types::LivenessRequestData,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    // Ensure the request is for either the current, previous or next epoch.
                    let current_epoch =
                        chain.epoch().map_err(warp_utils::reject::unhandled_error)?;
                    let prev_epoch = current_epoch.saturating_sub(Epoch::new(1));
                    let next_epoch = current_epoch.saturating_add(Epoch::new(1));

                    if request_data.epoch < prev_epoch || request_data.epoch > next_epoch {
                        return Err(warp_utils::reject::custom_bad_request(format!(
                            "request epoch {} is more than one epoch from the current epoch {}",
                            request_data.epoch, current_epoch
                        )));
                    }

                    let liveness: Vec<api_types::LivenessResponseData> = request_data
                        .indices
                        .iter()
                        .cloned()
                        .map(|index| {
                            let is_live =
                                chain.validator_seen_at_epoch(index as usize, request_data.epoch);
                            api_types::LivenessResponseData {
                                index,
                                epoch: request_data.epoch,
                                is_live,
                            }
                        })
                        .collect();

                    Ok(api_types::GenericResponse::from(liveness))
                })
            },
        );

    // GET lighthouse/health
    let get_lighthouse_health = warp::path("lighthouse")
        .and(warp::path("health"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .then(|task_spawner: TaskSpawner<T::EthSpec>| {
            task_spawner.blocking_json_task(Priority::P0, move || {
                eth2::lighthouse::Health::observe()
                    .map(api_types::GenericResponse::from)
                    .map_err(warp_utils::reject::custom_bad_request)
            })
        });

    // GET lighthouse/ui/health
    let get_lighthouse_ui_health = warp::path("lighthouse")
        .and(warp::path("ui"))
        .and(warp::path("health"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(system_info_filter)
        .and(app_start_filter)
        .and(data_dir_filter)
        .and(network_globals.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>,
             sysinfo,
             app_start: std::time::Instant,
             data_dir,
             network_globals| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    let app_uptime = app_start.elapsed().as_secs();
                    Ok(api_types::GenericResponse::from(observe_system_health_bn(
                        sysinfo,
                        data_dir,
                        app_uptime,
                        network_globals,
                    )))
                })
            },
        );

    // GET lighthouse/ui/validator_count
    let get_lighthouse_ui_validator_count = warp::path("lighthouse")
        .and(warp::path("ui"))
        .and(warp::path("validator_count"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>, chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    ui::get_validator_count(chain).map(api_types::GenericResponse::from)
                })
            },
        );

    // POST lighthouse/ui/validator_metrics
    let post_lighthouse_ui_validator_metrics = warp::path("lighthouse")
        .and(warp::path("ui"))
        .and(warp::path("validator_metrics"))
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |request_data: ui::ValidatorMetricsRequestData,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    ui::post_validator_monitor_metrics(request_data, chain)
                        .map(api_types::GenericResponse::from)
                })
            },
        );

    // POST lighthouse/ui/validator_info
    let post_lighthouse_ui_validator_info = warp::path("lighthouse")
        .and(warp::path("ui"))
        .and(warp::path("validator_info"))
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |request_data: ui::ValidatorInfoRequestData,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    ui::get_validator_info(request_data, chain)
                        .map(api_types::GenericResponse::from)
                })
            },
        );

    // GET lighthouse/syncing
    let get_lighthouse_syncing = warp::path("lighthouse")
        .and(warp::path("syncing"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(network_globals.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>,
             network_globals: Arc<NetworkGlobals<T::EthSpec>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    Ok(api_types::GenericResponse::from(
                        network_globals.sync_state(),
                    ))
                })
            },
        );

    // GET lighthouse/nat
    let get_lighthouse_nat = warp::path("lighthouse")
        .and(warp::path("nat"))
        .and(task_spawner_filter.clone())
        .and(warp::path::end())
        .then(|task_spawner: TaskSpawner<T::EthSpec>| {
            task_spawner.blocking_json_task(Priority::P1, move || {
                Ok(api_types::GenericResponse::from(observe_nat()))
            })
        });

    // GET lighthouse/peers
    let get_lighthouse_peers = warp::path("lighthouse")
        .and(warp::path("peers"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(network_globals.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>,
             network_globals: Arc<NetworkGlobals<T::EthSpec>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    Ok(network_globals
                        .peers
                        .read()
                        .peers()
                        .map(|(peer_id, peer_info)| peer::Peer {
                            peer_id: peer_id.to_string(),
                            peer_info: peer_info.clone(),
                        })
                        .collect::<Vec<_>>())
                })
            },
        );

    // GET lighthouse/peers/connected
    let get_lighthouse_peers_connected = warp::path("lighthouse")
        .and(warp::path("peers"))
        .and(warp::path("connected"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(network_globals)
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>,
             network_globals: Arc<NetworkGlobals<T::EthSpec>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let mut peers = vec![];
                    for (peer_id, peer_info) in network_globals.peers.read().connected_peers() {
                        peers.push(peer::Peer {
                            peer_id: peer_id.to_string(),
                            peer_info: peer_info.clone(),
                        });
                    }
                    Ok(peers)
                })
            },
        );

    // GET lighthouse/proto_array
    let get_lighthouse_proto_array = warp::path("lighthouse")
        .and(warp::path("proto_array"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>, chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    Ok::<_, warp::Rejection>(warp::reply::json(
                        &api_types::GenericResponseRef::from(
                            chain
                                .canonical_head
                                .fork_choice_read_lock()
                                .proto_array()
                                .core_proto_array(),
                        ),
                    ))
                })
            },
        );

    // GET lighthouse/validator_inclusion/{epoch}/{validator_id}
    let get_lighthouse_validator_inclusion_global = warp::path("lighthouse")
        .and(warp::path("validator_inclusion"))
        .and(warp::path::param::<Epoch>())
        .and(warp::path::param::<ValidatorId>())
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |epoch: Epoch,
             validator_id: ValidatorId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    validator_inclusion::validator_inclusion_data(epoch, &validator_id, &chain)
                        .map(api_types::GenericResponse::from)
                })
            },
        );

    // GET lighthouse/validator_inclusion/{epoch}/global
    let get_lighthouse_validator_inclusion = warp::path("lighthouse")
        .and(warp::path("validator_inclusion"))
        .and(warp::path::param::<Epoch>())
        .and(warp::path("global"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |epoch: Epoch, task_spawner: TaskSpawner<T::EthSpec>, chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    validator_inclusion::global_validator_inclusion_data(epoch, &chain)
                        .map(api_types::GenericResponse::from)
                })
            },
        );

    // GET lighthouse/staking
    let get_lighthouse_staking = warp::path("lighthouse")
        .and(warp::path("staking"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .then(|task_spawner: TaskSpawner<T::EthSpec>| {
            // This API is fairly useless since we abolished the distinction between staking and
            // non-staking nodes. We keep it for backwards-compatibility with LH v7.0.0, and in case
            // we want to reintroduce the distinction in future.
            task_spawner.blocking_json_task(Priority::P1, move || Ok(()))
        });

    let database_path = warp::path("lighthouse").and(warp::path("database"));

    // GET lighthouse/database/info
    let get_lighthouse_database_info = database_path
        .and(warp::path("info"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>, chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || database::info(chain))
            },
        );

    // POST lighthouse/database/reconstruct
    let post_lighthouse_database_reconstruct = database_path
        .and(warp::path("reconstruct"))
        .and(warp::path::end())
        .and(not_while_syncing_filter)
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |not_synced_filter: Result<(), Rejection>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    not_synced_filter?;
                    chain.store_migrator.process_reconstruction();
                    Ok("success")
                })
            },
        );

    // GET lighthouse/custody/info
    let get_lighthouse_custody_info = warp::path("lighthouse")
        .and(warp::path("custody"))
        .and(warp::path("info"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>, chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || custody::info(chain))
            },
        );

    // POST lighthouse/custody/backfill
    let post_lighthouse_custody_backfill = warp::path("lighthouse")
        .and(warp::path("custody"))
        .and(warp::path("backfill"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>, chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    // Calling this endpoint will trigger custody backfill once `effective_epoch``
                    // is finalized.
                    let effective_epoch = chain
                        .canonical_head
                        .cached_head()
                        .head_slot()
                        .epoch(T::EthSpec::slots_per_epoch())
                        + 1;
                    let custody_context = chain.data_availability_checker.custody_context();
                    // Reset validator custody requirements to `effective_epoch` with the latest
                    // cgc requiremnets.
                    custody_context.reset_validator_custody_requirements(effective_epoch);
                    // Update `DataColumnCustodyInfo` to reflect the custody change.
                    chain.update_data_column_custody_info(Some(
                        effective_epoch.start_slot(T::EthSpec::slots_per_epoch()),
                    ));
                    Ok(())
                })
            },
        );

    // GET lighthouse/analysis/block_rewards
    let get_lighthouse_block_rewards = warp::path("lighthouse")
        .and(warp::path("analysis"))
        .and(warp::path("block_rewards"))
        .and(warp::query::<eth2::lighthouse::BlockRewardsQuery>())
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(|query, task_spawner: TaskSpawner<T::EthSpec>, chain| {
            task_spawner.blocking_json_task(Priority::P1, move || {
                block_rewards::get_block_rewards(query, chain)
            })
        });

    // POST lighthouse/analysis/block_rewards
    let post_lighthouse_block_rewards = warp::path("lighthouse")
        .and(warp::path("analysis"))
        .and(warp::path("block_rewards"))
        .and(warp_utils::json::json())
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(|blocks, task_spawner: TaskSpawner<T::EthSpec>, chain| {
            task_spawner.blocking_json_task(Priority::P1, move || {
                block_rewards::compute_block_rewards(blocks, chain)
            })
        });

    // GET lighthouse/analysis/attestation_performance/{index}
    let get_lighthouse_attestation_performance = warp::path("lighthouse")
        .and(warp::path("analysis"))
        .and(warp::path("attestation_performance"))
        .and(warp::path::param::<String>())
        .and(warp::query::<eth2::lighthouse::AttestationPerformanceQuery>())
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |target, query, task_spawner: TaskSpawner<T::EthSpec>, chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    attestation_performance::get_attestation_performance(target, query, chain)
                })
            },
        );

    // GET lighthouse/analysis/block_packing_efficiency
    let get_lighthouse_block_packing_efficiency = warp::path("lighthouse")
        .and(warp::path("analysis"))
        .and(warp::path("block_packing_efficiency"))
        .and(warp::query::<eth2::lighthouse::BlockPackingEfficiencyQuery>())
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |query, task_spawner: TaskSpawner<T::EthSpec>, chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    block_packing_efficiency::get_block_packing_efficiency(query, chain)
                })
            },
        );

    // GET lighthouse/merge_readiness
    let get_lighthouse_merge_readiness = warp::path("lighthouse")
        .and(warp::path("merge_readiness"))
        .and(warp::path::end())
        .and(task_spawner_filter.clone())
        .and(chain_filter.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>, chain: Arc<BeaconChain<T>>| {
                task_spawner.spawn_async_with_rejection(Priority::P1, async move {
                    let current_slot = chain.slot_clock.now_or_genesis().unwrap_or(Slot::new(0));
                    let merge_readiness = chain.check_bellatrix_readiness(current_slot).await;
                    Ok::<_, warp::reject::Rejection>(
                        warp::reply::json(&api_types::GenericResponse::from(merge_readiness))
                            .into_response(),
                    )
                })
            },
        );

    let get_events = eth_v1
        .clone()
        .and(warp::path("events"))
        .and(warp::path::end())
        .and(multi_key_query::<api_types::EventQuery>())
        .and(task_spawner_filter.clone())
        .and(chain_filter)
        .then(
            |topics_res: Result<api_types::EventQuery, warp::Rejection>,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_response_task(Priority::P0, move || {
                    let topics = topics_res?;
                    // for each topic subscribed spawn a new subscription
                    let mut receivers = Vec::with_capacity(topics.topics.len());

                    if let Some(event_handler) = chain.event_handler.as_ref() {
                        for topic in topics.topics {
                            let receiver = match topic {
                                api_types::EventTopic::Head => event_handler.subscribe_head(),
                                api_types::EventTopic::Block => event_handler.subscribe_block(),
                                api_types::EventTopic::BlobSidecar => {
                                    event_handler.subscribe_blob_sidecar()
                                }
                                api_types::EventTopic::DataColumnSidecar => {
                                    event_handler.subscribe_data_column_sidecar()
                                }
                                api_types::EventTopic::Attestation => {
                                    event_handler.subscribe_attestation()
                                }
                                api_types::EventTopic::SingleAttestation => {
                                    event_handler.subscribe_single_attestation()
                                }
                                api_types::EventTopic::VoluntaryExit => {
                                    event_handler.subscribe_exit()
                                }
                                api_types::EventTopic::FinalizedCheckpoint => {
                                    event_handler.subscribe_finalized()
                                }
                                api_types::EventTopic::ChainReorg => {
                                    event_handler.subscribe_reorgs()
                                }
                                api_types::EventTopic::ContributionAndProof => {
                                    event_handler.subscribe_contributions()
                                }
                                api_types::EventTopic::PayloadAttributes => {
                                    event_handler.subscribe_payload_attributes()
                                }
                                api_types::EventTopic::LateHead => {
                                    event_handler.subscribe_late_head()
                                }
                                api_types::EventTopic::LightClientFinalityUpdate => {
                                    event_handler.subscribe_light_client_finality_update()
                                }
                                api_types::EventTopic::LightClientOptimisticUpdate => {
                                    event_handler.subscribe_light_client_optimistic_update()
                                }
                                api_types::EventTopic::BlockReward => {
                                    event_handler.subscribe_block_reward()
                                }
                                api_types::EventTopic::AttesterSlashing => {
                                    event_handler.subscribe_attester_slashing()
                                }
                                api_types::EventTopic::ProposerSlashing => {
                                    event_handler.subscribe_proposer_slashing()
                                }
                                api_types::EventTopic::BlsToExecutionChange => {
                                    event_handler.subscribe_bls_to_execution_change()
                                }
                                api_types::EventTopic::BlockGossip => {
                                    event_handler.subscribe_block_gossip()
                                }
                            };

                            receivers.push(
                                BroadcastStream::new(receiver)
                                    .map(|msg| {
                                        match msg {
                                            Ok(data) => Event::default()
                                                .event(data.topic_name())
                                                .json_data(data)
                                                .unwrap_or_else(|e| {
                                                    Event::default()
                                                        .comment(format!("error - bad json: {e:?}"))
                                                }),
                                            // Do not terminate the stream if the channel fills
                                            // up. Just drop some messages and send a comment to
                                            // the client.
                                            Err(BroadcastStreamRecvError::Lagged(n)) => {
                                                Event::default().comment(format!(
                                                    "error - dropped {n} messages"
                                                ))
                                            }
                                        }
                                    })
                                    .map(Ok::<_, std::convert::Infallible>),
                            );
                        }
                    } else {
                        return Err(warp_utils::reject::custom_server_error(
                            "event handler was not initialized".to_string(),
                        ));
                    }

                    let s = futures::stream::select_all(receivers);

                    let response = warp::sse::reply(warp::sse::keep_alive().stream(s));

                    // Set headers to bypass nginx caching and buffering, which breaks realtime
                    // delivery.
                    let response = warp::reply::with_header(response, "X-Accel-Buffering", "no");
                    let response = warp::reply::with_header(response, "X-Accel-Expires", "0");
                    let response = warp::reply::with_header(
                        response,
                        "Cache-Control",
                        "no-cache, no-store, must-revalidate",
                    );

                    Ok(response)
                })
            },
        );

    // Subscribe to logs via Server Side Events
    // /lighthouse/logs
    let lighthouse_log_events = warp::path("lighthouse")
        .and(warp::path("logs"))
        .and(warp::path::end())
        .and(task_spawner_filter)
        .and(sse_component_filter)
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>, sse_component: Option<SSELoggingComponents>| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    if let Some(logging_components) = sse_component {
                        // Build a JSON stream
                        let s = BroadcastStream::new(logging_components.sender.subscribe()).map(
                            |msg| {
                                match msg {
                                    Ok(data) => {
                                        // Serialize to json
                                        match serde_json::to_string(&data)
                                            .map_err(|e| format!("{:?}", e))
                                        {
                                            // Send the json as a Server Side Event
                                            Ok(json) => Ok(Event::default().data(json)),
                                            Err(e) => {
                                                Err(warp_utils::reject::server_sent_event_error(
                                                    format!("Unable to serialize to JSON {}", e),
                                                ))
                                            }
                                        }
                                    }
                                    Err(e) => Err(warp_utils::reject::server_sent_event_error(
                                        format!("Unable to receive event {}", e),
                                    )),
                                }
                            },
                        );

                        Ok::<_, warp::Rejection>(warp::sse::reply(
                            warp::sse::keep_alive().stream(s),
                        ))
                    } else {
                        Err(warp_utils::reject::custom_server_error(
                            "SSE Logging is not enabled".to_string(),
                        ))
                    }
                })
            },
        );

    // Define the ultimate set of routes that will be provided to the server.
    // Use `uor` rather than `or` in order to simplify types (see `UnifyingOrFilter`).
    let routes = warp::get()
        .and(
            get_beacon_genesis
                .uor(get_beacon_state_root)
                .uor(get_beacon_state_fork)
                .uor(get_beacon_state_finality_checkpoints)
                .uor(get_beacon_state_validator_balances)
                .uor(get_beacon_state_validators_id)
                .uor(get_beacon_state_validators)
                .uor(get_beacon_state_committees)
                .uor(get_beacon_state_sync_committees)
                .uor(get_beacon_state_randao)
                .uor(get_beacon_state_pending_deposits)
                .uor(get_beacon_state_pending_partial_withdrawals)
                .uor(get_beacon_state_pending_consolidations)
                .uor(get_beacon_headers)
                .uor(get_beacon_headers_block_id)
                .uor(get_beacon_block)
                .uor(get_beacon_block_attestations)
                .uor(get_beacon_blinded_block)
                .uor(get_beacon_block_root)
                .uor(get_blob_sidecars)
                .uor(get_blobs)
                .uor(get_beacon_pool_attestations)
                .uor(get_beacon_pool_attester_slashings)
                .uor(get_beacon_pool_proposer_slashings)
                .uor(get_beacon_pool_voluntary_exits)
                .uor(get_beacon_pool_bls_to_execution_changes)
                .uor(get_beacon_rewards_blocks)
                .uor(get_config_fork_schedule)
                .uor(get_config_spec)
                .uor(get_config_deposit_contract)
                .uor(get_debug_beacon_states)
                .uor(get_debug_data_column_sidecars)
                .uor(get_debug_beacon_heads)
                .uor(get_debug_fork_choice)
                .uor(get_node_identity)
                .uor(get_node_version)
                .uor(get_node_syncing)
                .uor(get_node_health)
                .uor(get_node_peers_by_id)
                .uor(get_node_peers)
                .uor(get_node_peer_count)
                .uor(get_validator_duties_proposer)
                .uor(get_validator_blocks)
                .uor(get_validator_blinded_blocks)
                .uor(get_validator_attestation_data)
                .uor(get_validator_aggregate_attestation)
                .uor(get_validator_sync_committee_contribution)
                .uor(get_lighthouse_health)
                .uor(get_lighthouse_ui_health)
                .uor(get_lighthouse_ui_validator_count)
                .uor(get_lighthouse_syncing)
                .uor(get_lighthouse_nat)
                .uor(get_lighthouse_peers)
                .uor(get_lighthouse_peers_connected)
                .uor(get_lighthouse_proto_array)
                .uor(get_lighthouse_validator_inclusion_global)
                .uor(get_lighthouse_validator_inclusion)
                .uor(get_lighthouse_staking)
                .uor(get_lighthouse_database_info)
                .uor(get_lighthouse_custody_info)
                .uor(get_lighthouse_block_rewards)
                .uor(get_lighthouse_attestation_performance)
                .uor(get_beacon_light_client_optimistic_update)
                .uor(get_beacon_light_client_finality_update)
                .uor(get_beacon_light_client_bootstrap)
                .uor(get_beacon_light_client_updates)
                .uor(get_lighthouse_block_packing_efficiency)
                .uor(get_lighthouse_merge_readiness)
                .uor(get_events)
                .uor(get_expected_withdrawals)
                .uor(lighthouse_log_events.boxed())
                .recover(warp_utils::reject::handle_rejection),
        )
        .boxed()
        .uor(
            warp::post().and(
                warp::header::exact(CONTENT_TYPE_HEADER, SSZ_CONTENT_TYPE_HEADER)
                    // Routes which expect `application/octet-stream` go within this `and`.
                    .and(
                        post_beacon_blocks_ssz
                            .uor(post_beacon_blocks_v2_ssz)
                            .uor(post_beacon_blinded_blocks_ssz)
                            .uor(post_beacon_blinded_blocks_v2_ssz),
                    )
                    .uor(post_beacon_blocks)
                    .uor(post_beacon_blinded_blocks)
                    .uor(post_beacon_blocks_v2)
                    .uor(post_beacon_blinded_blocks_v2)
                    .uor(post_beacon_pool_attestations_v2)
                    .uor(post_beacon_pool_attester_slashings)
                    .uor(post_beacon_pool_proposer_slashings)
                    .uor(post_beacon_pool_voluntary_exits)
                    .uor(post_beacon_pool_sync_committees)
                    .uor(post_beacon_pool_bls_to_execution_changes)
                    .uor(post_beacon_state_validators)
                    .uor(post_beacon_state_validator_balances)
                    .uor(post_beacon_state_validator_identities)
                    .uor(post_beacon_rewards_attestations)
                    .uor(post_beacon_rewards_sync_committee)
                    .uor(post_validator_duties_attester)
                    .uor(post_validator_duties_sync)
                    .uor(post_validator_aggregate_and_proofs)
                    .uor(post_validator_contribution_and_proofs)
                    .uor(post_validator_beacon_committee_subscriptions)
                    .uor(post_validator_sync_committee_subscriptions)
                    .uor(post_validator_prepare_beacon_proposer)
                    .uor(post_validator_register_validator)
                    .uor(post_validator_liveness_epoch)
                    .uor(post_lighthouse_liveness)
                    .uor(post_lighthouse_database_reconstruct)
                    .uor(post_lighthouse_block_rewards)
                    .uor(post_lighthouse_ui_validator_metrics)
                    .uor(post_lighthouse_ui_validator_info)
                    .uor(post_lighthouse_finalize)
                    .uor(post_lighthouse_compaction)
                    .uor(post_lighthouse_add_peer)
                    .uor(post_lighthouse_remove_peer)
                    .uor(post_lighthouse_custody_backfill)
                    .recover(warp_utils::reject::handle_rejection),
            ),
        )
        .recover(warp_utils::reject::handle_rejection)
        .with(tracing_logging())
        .with(prometheus_metrics())
        // Add a `Server` header.
        .map(|reply| warp::reply::with_header(reply, "Server", &version_with_platform()))
        .with(cors_builder.build())
        .boxed();

    let http_socket: SocketAddr = SocketAddr::new(config.listen_addr, config.listen_port);
    let http_server: HttpServer = match config.tls_config {
        Some(tls_config) => {
            let (socket, server) = warp::serve(routes)
                .tls()
                .cert_path(tls_config.cert)
                .key_path(tls_config.key)
                .try_bind_with_graceful_shutdown(http_socket, async {
                    shutdown.await;
                })?;

            info!("HTTP API is being served over TLS");

            (socket, Box::pin(server))
        }
        None => {
            let (socket, server) =
                warp::serve(routes).try_bind_with_graceful_shutdown(http_socket, async {
                    shutdown.await;
                })?;
            (socket, Box::pin(server))
        }
    };

    info!(
        listen_address = %http_server.0,
        "HTTP API started"
    );

    Ok(http_server)
}
