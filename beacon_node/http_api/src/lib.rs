#![recursion_limit = "256"]
//! This crate contains a HTTP server which serves the endpoints listed here:
//!
//! https://github.com/ethereum/beacon-APIs
//!
//! There are also some additional, non-standard endpoints behind the `/lighthouse/` path which are
//! used for development.

mod attestation_performance;
mod attester_duties;
mod block_id;
mod block_packing_efficiency;
mod block_rewards;
mod database;
mod metrics;
mod proposer_duties;
mod publish_blocks;
mod state_id;
mod sync_committees;
mod ui;
mod validator_inclusion;
mod version;

use beacon_chain::{
    attestation_verification::VerifiedAttestation, observed_operations::ObservationOutcome,
    validator_monitor::timestamp_now, AttestationError as AttnError, BeaconChain, BeaconChainError,
    BeaconChainTypes, ProduceBlockVerification, WhenSlotSkipped,
};
pub use block_id::BlockId;
use directory::DEFAULT_ROOT_DIR;
use eth2::types::{
    self as api_types, EndpointVersion, SkipRandaoVerification, ValidatorId, ValidatorStatus,
};
use lighthouse_network::{types::SyncState, EnrExt, NetworkGlobals, PeerId, PubsubMessage};
use lighthouse_version::version_with_platform;
use network::{NetworkMessage, NetworkSenders, ValidatorSubscriptionMessage};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use slog::{crit, debug, error, info, warn, Logger};
use slot_clock::SlotClock;
use ssz::Encode;
pub use state_id::StateId;
use std::borrow::Cow;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use sysinfo::{System, SystemExt};
use system_health::observe_system_health_bn;
use tokio::sync::mpsc::{Sender, UnboundedSender};
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use types::{
    Attestation, AttestationData, AttesterSlashing, BeaconStateError, BlindedPayload,
    CommitteeCache, ConfigAndPreset, Epoch, EthSpec, ForkName, FullPayload,
    ProposerPreparationData, ProposerSlashing, RelativeEpoch, SignedAggregateAndProof,
    SignedBeaconBlock, SignedBlindedBeaconBlock, SignedBlsToExecutionChange,
    SignedContributionAndProof, SignedValidatorRegistrationData, SignedVoluntaryExit, Slot,
    SyncCommitteeMessage, SyncContributionData,
};
use version::{
    add_consensus_version_header, execution_optimistic_fork_versioned_response,
    fork_versioned_response, inconsistent_fork_rejection, unsupported_version_rejection, V1, V2,
};
use warp::http::StatusCode;
use warp::sse::Event;
use warp::Reply;
use warp::{http::Response, Filter};
use warp_utils::{
    query::multi_key_query,
    task::{blocking_json_task, blocking_task},
};

const API_PREFIX: &str = "eth";

/// If the node is within this many epochs from the head, we declare it to be synced regardless of
/// the network sync state.
///
/// This helps prevent attacks where nodes can convince us that we're syncing some non-existent
/// finalized head.
const SYNC_TOLERANCE_EPOCHS: u64 = 8;

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
    pub eth1_service: Option<eth1::Service>,
    pub log: Logger,
}

/// Configuration for the HTTP server.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub enabled: bool,
    pub listen_addr: IpAddr,
    pub listen_port: u16,
    pub allow_origin: Option<String>,
    pub tls_config: Option<TlsConfig>,
    pub allow_sync_stalled: bool,
    pub spec_fork_name: Option<ForkName>,
    pub data_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            listen_port: 5052,
            allow_origin: None,
            tls_config: None,
            allow_sync_stalled: false,
            spec_fork_name: None,
            data_dir: PathBuf::from(DEFAULT_ROOT_DIR),
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

/// Creates a `warp` logging wrapper which we use to create `slog` logs.
pub fn slog_logging(
    log: Logger,
) -> warp::filters::log::Log<impl Fn(warp::filters::log::Info) + Clone> {
    warp::log::custom(move |info| {
        match info.status() {
            status
                if status == StatusCode::OK
                    || status == StatusCode::NOT_FOUND
                    || status == StatusCode::PARTIAL_CONTENT =>
            {
                debug!(
                    log,
                    "Processed HTTP API request";
                    "elapsed" => format!("{:?}", info.elapsed()),
                    "status" => status.to_string(),
                    "path" => info.path(),
                    "method" => info.method().to_string(),
                );
            }
            status => {
                warn!(
                    log,
                    "Error processing HTTP API request";
                    "elapsed" => format!("{:?}", info.elapsed()),
                    "status" => status.to_string(),
                    "path" => info.path(),
                    "method" => info.method().to_string(),
                );
            }
        };
    })
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
                .or_else(|| starts_with("v1/validator/blocks"))
                .or_else(|| starts_with("v2/validator/blocks"))
                .or_else(|| starts_with("v1/validator/blinded_blocks"))
                .or_else(|| starts_with("v1/validator/duties/attester"))
                .or_else(|| starts_with("v1/validator/duties/proposer"))
                .or_else(|| starts_with("v1/validator/duties/sync"))
                .or_else(|| starts_with("v1/validator/attestation_data"))
                .or_else(|| starts_with("v1/validator/aggregate_attestation"))
                .or_else(|| starts_with("v1/validator/aggregate_and_proofs"))
                .or_else(|| starts_with("v1/validator/sync_committee_contribution"))
                .or_else(|| starts_with("v1/validator/contribution_and_proofs"))
                .or_else(|| starts_with("v1/validator/beacon_committee_subscriptions"))
                .or_else(|| starts_with("v1/validator/sync_committee_subscriptions"))
                .or_else(|| starts_with("v1/beacon/pool/attestations"))
                .or_else(|| starts_with("v1/beacon/pool/sync_committees"))
                .or_else(|| starts_with("v1/beacon/blocks/head/root"))
                .or_else(|| starts_with("v1/validator/prepare_beacon_proposer"))
                .or_else(|| starts_with("v1/validator/register_validator"))
                .or_else(|| starts_with("v1/beacon/"))
                .or_else(|| starts_with("v2/beacon/"))
                .or_else(|| starts_with("v1/config/"))
                .or_else(|| starts_with("v1/debug/"))
                .or_else(|| starts_with("v2/debug/"))
                .or_else(|| starts_with("v1/events/"))
                .or_else(|| starts_with("v1/node/"))
                .or_else(|| starts_with("v1/validator/"))
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
    let allow_sync_stalled = config.allow_sync_stalled;
    let log = ctx.log.clone();

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
        crit!(log, "Cannot start disabled HTTP server");
        return Err(Error::Other(
            "A disabled server should not be started".to_string(),
        ));
    }

    // Create a filter that extracts the endpoint version.
    let any_version = warp::path(API_PREFIX).and(warp::path::param::<EndpointVersion>().or_else(
        |_| async move {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid version identifier".to_string(),
            ))
        },
    ));

    // Filter that enforces a single endpoint version and then discards the `EndpointVersion`.
    let single_version = |reqd: EndpointVersion| {
        any_version
            .and_then(move |version| async move {
                if version == reqd {
                    Ok(())
                } else {
                    Err(unsupported_version_rejection(version))
                }
            })
            .untuple_one()
    };

    let eth_v1 = single_version(V1);

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
    let chain_filter =
        warp::any()
            .map(move || inner_ctx.chain.clone())
            .and_then(|chain| async move {
                match chain {
                    Some(chain) => Ok(chain),
                    None => Err(warp_utils::reject::custom_not_found(
                        "Beacon chain genesis has not yet been observed.".to_string(),
                    )),
                }
            });

    // Create a `warp` filter that provides access to the network sender channel.
    let network_tx = ctx
        .network_senders
        .as_ref()
        .map(|senders| senders.network_send());
    let network_tx_filter =
        warp::any()
            .map(move || network_tx.clone())
            .and_then(|network_tx| async move {
                match network_tx {
                    Some(network_tx) => Ok(network_tx),
                    None => Err(warp_utils::reject::custom_not_found(
                        "The networking stack has not yet started (network_tx).".to_string(),
                    )),
                }
            });

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
        });

    // Create a `warp` filter that provides access to the Eth1 service.
    let inner_ctx = ctx.clone();
    let eth1_service_filter = warp::any()
        .map(move || inner_ctx.eth1_service.clone())
        .and_then(|eth1_service| async move {
            match eth1_service {
                Some(eth1_service) => Ok(eth1_service),
                None => Err(warp_utils::reject::custom_not_found(
                    "The Eth1 service is not started. Use --eth1 on the CLI.".to_string(),
                )),
            }
        });

    // Create a `warp` filter that rejects requests whilst the node is syncing.
    let not_while_syncing_filter =
        warp::any()
            .and(network_globals.clone())
            .and(chain_filter.clone())
            .and_then(
                move |network_globals: Arc<NetworkGlobals<T::EthSpec>>,
                      chain: Arc<BeaconChain<T>>| async move {
                    match *network_globals.sync_state.read() {
                        SyncState::SyncingFinalized { .. } => {
                            let head_slot = chain.canonical_head.cached_head().head_slot();

                            let current_slot =
                                chain.slot_clock.now_or_genesis().ok_or_else(|| {
                                    warp_utils::reject::custom_server_error(
                                        "unable to read slot clock".to_string(),
                                    )
                                })?;

                            let tolerance = SYNC_TOLERANCE_EPOCHS * T::EthSpec::slots_per_epoch();

                            if head_slot + tolerance >= current_slot {
                                Ok(())
                            } else {
                                Err(warp_utils::reject::not_synced(format!(
                                    "head slot is {}, current slot is {}",
                                    head_slot, current_slot
                                )))
                            }
                        }
                        SyncState::SyncingHead { .. }
                        | SyncState::SyncTransition
                        | SyncState::BackFillSyncing { .. } => Ok(()),
                        SyncState::Synced => Ok(()),
                        SyncState::Stalled if allow_sync_stalled => Ok(()),
                        SyncState::Stalled => Err(warp_utils::reject::not_synced(
                            "sync is stalled".to_string(),
                        )),
                    }
                },
            )
            .untuple_one();

    // Create a `warp` filter that provides access to the logger.
    let inner_ctx = ctx.clone();
    let log_filter = warp::any().map(move || inner_ctx.log.clone());

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

    /*
     *
     * Start of HTTP method definitions.
     *
     */

    // GET beacon/genesis
    let get_beacon_genesis = eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("genesis"))
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(|chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                let genesis_data = api_types::GenesisData {
                    genesis_time: chain.genesis_time,
                    genesis_validators_root: chain.genesis_validators_root,
                    genesis_fork_version: chain.spec.genesis_fork_version,
                };
                Ok(api_types::GenericResponse::from(genesis_data))
            })
        });

    /*
     * beacon/states/{state_id}
     */

    let beacon_states_path = eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("states"))
        .and(warp::path::param::<StateId>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid state ID".to_string(),
            ))
        }))
        .and(chain_filter.clone());

    // GET beacon/states/{state_id}/root
    let get_beacon_state_root = beacon_states_path
        .clone()
        .and(warp::path("root"))
        .and(warp::path::end())
        .and_then(|state_id: StateId, chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                let (root, execution_optimistic) = state_id.root(&chain)?;

                Ok(root)
                    .map(api_types::RootData::from)
                    .map(api_types::GenericResponse::from)
                    .map(|resp| resp.add_execution_optimistic(execution_optimistic))
            })
        });

    // GET beacon/states/{state_id}/fork
    let get_beacon_state_fork = beacon_states_path
        .clone()
        .and(warp::path("fork"))
        .and(warp::path::end())
        .and_then(|state_id: StateId, chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                let (fork, execution_optimistic) =
                    state_id.fork_and_execution_optimistic(&chain)?;
                Ok(api_types::ExecutionOptimisticResponse {
                    data: fork,
                    execution_optimistic: Some(execution_optimistic),
                })
            })
        });

    // GET beacon/states/{state_id}/finality_checkpoints
    let get_beacon_state_finality_checkpoints = beacon_states_path
        .clone()
        .and(warp::path("finality_checkpoints"))
        .and(warp::path::end())
        .and_then(|state_id: StateId, chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                let (data, execution_optimistic) = state_id.map_state_and_execution_optimistic(
                    &chain,
                    |state, execution_optimistic| {
                        Ok((
                            api_types::FinalityCheckpointsData {
                                previous_justified: state.previous_justified_checkpoint(),
                                current_justified: state.current_justified_checkpoint(),
                                finalized: state.finalized_checkpoint(),
                            },
                            execution_optimistic,
                        ))
                    },
                )?;

                Ok(api_types::ExecutionOptimisticResponse {
                    data,
                    execution_optimistic: Some(execution_optimistic),
                })
            })
        });

    // GET beacon/states/{state_id}/validator_balances?id
    let get_beacon_state_validator_balances = beacon_states_path
        .clone()
        .and(warp::path("validator_balances"))
        .and(warp::path::end())
        .and(multi_key_query::<api_types::ValidatorBalancesQuery>())
        .and_then(
            |state_id: StateId,
             chain: Arc<BeaconChain<T>>,
             query_res: Result<api_types::ValidatorBalancesQuery, warp::Rejection>| {
                blocking_json_task(move || {
                    let query = query_res?;
                    let (data, execution_optimistic) = state_id
                        .map_state_and_execution_optimistic(
                            &chain,
                            |state, execution_optimistic| {
                                Ok((
                                    state
                                        .validators()
                                        .iter()
                                        .zip(state.balances().iter())
                                        .enumerate()
                                        // filter by validator id(s) if provided
                                        .filter(|(index, (validator, _))| {
                                            query.id.as_ref().map_or(true, |ids| {
                                                ids.iter().any(|id| match id {
                                                    ValidatorId::PublicKey(pubkey) => {
                                                        &validator.pubkey == pubkey
                                                    }
                                                    ValidatorId::Index(param_index) => {
                                                        *param_index == *index as u64
                                                    }
                                                })
                                            })
                                        })
                                        .map(|(index, (_, balance))| {
                                            Some(api_types::ValidatorBalanceData {
                                                index: index as u64,
                                                balance: *balance,
                                            })
                                        })
                                        .collect::<Vec<_>>(),
                                    execution_optimistic,
                                ))
                            },
                        )?;

                    Ok(api_types::ExecutionOptimisticResponse {
                        data,
                        execution_optimistic: Some(execution_optimistic),
                    })
                })
            },
        );

    // GET beacon/states/{state_id}/validators?id,status
    let get_beacon_state_validators = beacon_states_path
        .clone()
        .and(warp::path("validators"))
        .and(warp::path::end())
        .and(multi_key_query::<api_types::ValidatorsQuery>())
        .and_then(
            |state_id: StateId,
             chain: Arc<BeaconChain<T>>,
             query_res: Result<api_types::ValidatorsQuery, warp::Rejection>| {
                blocking_json_task(move || {
                    let query = query_res?;
                    let (data, execution_optimistic) = state_id
                        .map_state_and_execution_optimistic(
                            &chain,
                            |state, execution_optimistic| {
                                let epoch = state.current_epoch();
                                let far_future_epoch = chain.spec.far_future_epoch;

                                Ok((
                                    state
                                        .validators()
                                        .iter()
                                        .zip(state.balances().iter())
                                        .enumerate()
                                        // filter by validator id(s) if provided
                                        .filter(|(index, (validator, _))| {
                                            query.id.as_ref().map_or(true, |ids| {
                                                ids.iter().any(|id| match id {
                                                    ValidatorId::PublicKey(pubkey) => {
                                                        &validator.pubkey == pubkey
                                                    }
                                                    ValidatorId::Index(param_index) => {
                                                        *param_index == *index as u64
                                                    }
                                                })
                                            })
                                        })
                                        // filter by status(es) if provided and map the result
                                        .filter_map(|(index, (validator, balance))| {
                                            let status = api_types::ValidatorStatus::from_validator(
                                                validator,
                                                epoch,
                                                far_future_epoch,
                                            );

                                            let status_matches =
                                                query.status.as_ref().map_or(true, |statuses| {
                                                    statuses.contains(&status)
                                                        || statuses.contains(&status.superstatus())
                                                });

                                            if status_matches {
                                                Some(api_types::ValidatorData {
                                                    index: index as u64,
                                                    balance: *balance,
                                                    status,
                                                    validator: validator.clone(),
                                                })
                                            } else {
                                                None
                                            }
                                        })
                                        .collect::<Vec<_>>(),
                                    execution_optimistic,
                                ))
                            },
                        )?;

                    Ok(api_types::ExecutionOptimisticResponse {
                        data,
                        execution_optimistic: Some(execution_optimistic),
                    })
                })
            },
        );

    // GET beacon/states/{state_id}/validators/{validator_id}
    let get_beacon_state_validators_id = beacon_states_path
        .clone()
        .and(warp::path("validators"))
        .and(warp::path::param::<ValidatorId>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid validator ID".to_string(),
            ))
        }))
        .and(warp::path::end())
        .and_then(
            |state_id: StateId, chain: Arc<BeaconChain<T>>, validator_id: ValidatorId| {
                blocking_json_task(move || {
                    let (data, execution_optimistic) = state_id
                        .map_state_and_execution_optimistic(
                            &chain,
                            |state, execution_optimistic| {
                                let index_opt = match &validator_id {
                                    ValidatorId::PublicKey(pubkey) => {
                                        state.validators().iter().position(|v| v.pubkey == *pubkey)
                                    }
                                    ValidatorId::Index(index) => Some(*index as usize),
                                };

                                Ok((
                                    index_opt
                                        .and_then(|index| {
                                            let validator = state.validators().get(index)?;
                                            let balance = *state.balances().get(index)?;
                                            let epoch = state.current_epoch();
                                            let far_future_epoch = chain.spec.far_future_epoch;

                                            Some(api_types::ValidatorData {
                                                index: index as u64,
                                                balance,
                                                status: api_types::ValidatorStatus::from_validator(
                                                    validator,
                                                    epoch,
                                                    far_future_epoch,
                                                ),
                                                validator: validator.clone(),
                                            })
                                        })
                                        .ok_or_else(|| {
                                            warp_utils::reject::custom_not_found(format!(
                                                "unknown validator: {}",
                                                validator_id
                                            ))
                                        })?,
                                    execution_optimistic,
                                ))
                            },
                        )?;

                    Ok(api_types::ExecutionOptimisticResponse {
                        data,
                        execution_optimistic: Some(execution_optimistic),
                    })
                })
            },
        );

    // GET beacon/states/{state_id}/committees?slot,index,epoch
    let get_beacon_state_committees = beacon_states_path
        .clone()
        .and(warp::path("committees"))
        .and(warp::query::<api_types::CommitteesQuery>())
        .and(warp::path::end())
        .and_then(
            |state_id: StateId, chain: Arc<BeaconChain<T>>, query: api_types::CommitteesQuery| {
                blocking_json_task(move || {
                    let (data, execution_optimistic) = state_id
                        .map_state_and_execution_optimistic(
                            &chain,
                            |state, execution_optimistic| {
                                let current_epoch = state.current_epoch();
                                let epoch = query.epoch.unwrap_or(current_epoch);

                                let committee_cache =
                                    match RelativeEpoch::from_epoch(current_epoch, epoch) {
                                        Ok(relative_epoch)
                                            if state
                                                .committee_cache_is_initialized(relative_epoch) =>
                                        {
                                            state.committee_cache(relative_epoch).map(Cow::Borrowed)
                                        }
                                        _ => CommitteeCache::initialized(state, epoch, &chain.spec)
                                            .map(Cow::Owned),
                                    }
                                    .map_err(|e| match e {
                                        BeaconStateError::EpochOutOfBounds => {
                                            let max_sprp =
                                                T::EthSpec::slots_per_historical_root() as u64;
                                            let first_subsequent_restore_point_slot = ((epoch
                                                .start_slot(T::EthSpec::slots_per_epoch())
                                                / max_sprp)
                                                + 1)
                                                * max_sprp;
                                            if epoch < current_epoch {
                                                warp_utils::reject::custom_bad_request(format!(
                                                    "epoch out of bounds, try state at slot {}",
                                                    first_subsequent_restore_point_slot,
                                                ))
                                            } else {
                                                warp_utils::reject::custom_bad_request(
                                                    "epoch out of bounds, too far in future".into(),
                                                )
                                            }
                                        }
                                        _ => warp_utils::reject::beacon_chain_error(e.into()),
                                    })?;

                                // Use either the supplied slot or all slots in the epoch.
                                let slots =
                                    query.slot.map(|slot| vec![slot]).unwrap_or_else(|| {
                                        epoch.slot_iter(T::EthSpec::slots_per_epoch()).collect()
                                    });

                                // Use either the supplied committee index or all available indices.
                                let indices =
                                    query.index.map(|index| vec![index]).unwrap_or_else(|| {
                                        (0..committee_cache.committees_per_slot()).collect()
                                    });

                                let mut response = Vec::with_capacity(slots.len() * indices.len());

                                for slot in slots {
                                    // It is not acceptable to query with a slot that is not within the
                                    // specified epoch.
                                    if slot.epoch(T::EthSpec::slots_per_epoch()) != epoch {
                                        return Err(warp_utils::reject::custom_bad_request(
                                            format!("{} is not in epoch {}", slot, epoch),
                                        ));
                                    }

                                    for &index in &indices {
                                        let committee = committee_cache
                                            .get_beacon_committee(slot, index)
                                            .ok_or_else(|| {
                                                warp_utils::reject::custom_bad_request(format!(
                                                    "committee index {} does not exist in epoch {}",
                                                    index, epoch
                                                ))
                                            })?;

                                        response.push(api_types::CommitteeData {
                                            index,
                                            slot,
                                            validators: committee
                                                .committee
                                                .iter()
                                                .map(|i| *i as u64)
                                                .collect(),
                                        });
                                    }
                                }

                                Ok((response, execution_optimistic))
                            },
                        )?;
                    Ok(api_types::ExecutionOptimisticResponse {
                        data,
                        execution_optimistic: Some(execution_optimistic),
                    })
                })
            },
        );

    // GET beacon/states/{state_id}/sync_committees?epoch
    let get_beacon_state_sync_committees = beacon_states_path
        .clone()
        .and(warp::path("sync_committees"))
        .and(warp::query::<api_types::SyncCommitteesQuery>())
        .and(warp::path::end())
        .and_then(
            |state_id: StateId,
             chain: Arc<BeaconChain<T>>,
             query: api_types::SyncCommitteesQuery| {
                blocking_json_task(move || {
                    let (sync_committee, execution_optimistic) = state_id
                        .map_state_and_execution_optimistic(
                            &chain,
                            |state, execution_optimistic| {
                                let current_epoch = state.current_epoch();
                                let epoch = query.epoch.unwrap_or(current_epoch);
                                Ok((
                                    state
                                        .get_built_sync_committee(epoch, &chain.spec)
                                        .map(|committee| committee.clone())
                                        .map_err(|e| match e {
                                            BeaconStateError::SyncCommitteeNotKnown { .. } => {
                                                warp_utils::reject::custom_bad_request(format!(
                                        "state at epoch {} has no sync committee for epoch {}",
                                        current_epoch, epoch
                                    ))
                                            }
                                            BeaconStateError::IncorrectStateVariant => {
                                                warp_utils::reject::custom_bad_request(format!(
                                                    "state at epoch {} is not activated for Altair",
                                                    current_epoch,
                                                ))
                                            }
                                            e => warp_utils::reject::beacon_state_error(e),
                                        })?,
                                    execution_optimistic,
                                ))
                            },
                        )?;

                    let validators = chain
                        .validator_indices(sync_committee.pubkeys.iter())
                        .map_err(warp_utils::reject::beacon_chain_error)?;

                    let validator_aggregates = validators
                        .chunks_exact(T::EthSpec::sync_subcommittee_size())
                        .map(|indices| api_types::SyncSubcommittee {
                            indices: indices.to_vec(),
                        })
                        .collect();

                    let response = api_types::SyncCommitteeByValidatorIndices {
                        validators,
                        validator_aggregates,
                    };

                    Ok(api_types::GenericResponse::from(response)
                        .add_execution_optimistic(execution_optimistic))
                })
            },
        );

    // GET beacon/states/{state_id}/randao?epoch
    let get_beacon_state_randao = beacon_states_path
        .clone()
        .and(warp::path("randao"))
        .and(warp::query::<api_types::RandaoQuery>())
        .and(warp::path::end())
        .and_then(
            |state_id: StateId, chain: Arc<BeaconChain<T>>, query: api_types::RandaoQuery| {
                blocking_json_task(move || {
                    let (randao, execution_optimistic) = state_id
                        .map_state_and_execution_optimistic(
                            &chain,
                            |state, execution_optimistic| {
                                let epoch = query.epoch.unwrap_or_else(|| state.current_epoch());
                                let randao = *state.get_randao_mix(epoch).map_err(|e| {
                                    warp_utils::reject::custom_bad_request(format!(
                                        "epoch out of range: {e:?}"
                                    ))
                                })?;
                                Ok((randao, execution_optimistic))
                            },
                        )?;

                    Ok(
                        api_types::GenericResponse::from(api_types::RandaoMix { randao })
                            .add_execution_optimistic(execution_optimistic),
                    )
                })
            },
        );

    // GET beacon/headers
    //
    // Note: this endpoint only returns information about blocks in the canonical chain. Given that
    // there's a `canonical` flag on the response, I assume it should also return non-canonical
    // things. Returning non-canonical things is hard for us since we don't already have a
    // mechanism for arbitrary forwards block iteration, we only support iterating forwards along
    // the canonical chain.
    let get_beacon_headers = eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("headers"))
        .and(warp::query::<api_types::HeadersQuery>())
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(
            |query: api_types::HeadersQuery, chain: Arc<BeaconChain<T>>| {
                blocking_json_task(move || {
                    let (root, block, execution_optimistic) = match (query.slot, query.parent_root)
                    {
                        // No query parameters, return the canonical head block.
                        (None, None) => {
                            let (cached_head, execution_status) = chain
                                .canonical_head
                                .head_and_execution_status()
                                .map_err(warp_utils::reject::beacon_chain_error)?;
                            (
                                cached_head.head_block_root(),
                                cached_head.snapshot.beacon_block.clone_as_blinded(),
                                execution_status.is_optimistic_or_invalid(),
                            )
                        }
                        // Only the parent root parameter, do a forwards-iterator lookup.
                        (None, Some(parent_root)) => {
                            let (parent, execution_optimistic) =
                                BlockId::from_root(parent_root).blinded_block(&chain)?;
                            let (root, _slot) = chain
                                .forwards_iter_block_roots(parent.slot())
                                .map_err(warp_utils::reject::beacon_chain_error)?
                                // Ignore any skip-slots immediately following the parent.
                                .find(|res| {
                                    res.as_ref().map_or(false, |(root, _)| *root != parent_root)
                                })
                                .transpose()
                                .map_err(warp_utils::reject::beacon_chain_error)?
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
                                .map(|(block, _execution_optimistic)| {
                                    (root, block, execution_optimistic)
                                })?
                        }
                        // Slot is supplied, search by slot and optionally filter by
                        // parent root.
                        (Some(slot), parent_root_opt) => {
                            let (root, execution_optimistic) =
                                BlockId::from_slot(slot).root(&chain)?;
                            // Ignore the second `execution_optimistic`, the first one is the
                            // most relevant since it knows that we queried by slot.
                            let (block, _execution_optimistic) =
                                BlockId::from_root(root).blinded_block(&chain)?;

                            // If the parent root was supplied, check that it matches the block
                            // obtained via a slot lookup.
                            if let Some(parent_root) = parent_root_opt {
                                if block.parent_root() != parent_root {
                                    return Err(warp_utils::reject::custom_not_found(format!(
                                        "no canonical block at slot {} with parent root {}",
                                        slot, parent_root
                                    )));
                                }
                            }

                            (root, block, execution_optimistic)
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
                        .add_execution_optimistic(execution_optimistic))
                })
            },
        );

    // GET beacon/headers/{block_id}
    let get_beacon_headers_block_id = eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("headers"))
        .and(warp::path::param::<BlockId>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid block ID".to_string(),
            ))
        }))
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(|block_id: BlockId, chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                let (root, execution_optimistic) = block_id.root(&chain)?;
                // Ignore the second `execution_optimistic` since the first one has more
                // information about the original request.
                let (block, _execution_optimistic) =
                    BlockId::from_root(root).blinded_block(&chain)?;

                let canonical = chain
                    .block_root_at_slot(block.slot(), WhenSlotSkipped::None)
                    .map_err(warp_utils::reject::beacon_chain_error)?
                    .map_or(false, |canonical| root == canonical);

                let data = api_types::BlockHeaderData {
                    root,
                    canonical,
                    header: api_types::BlockHeaderAndSignature {
                        message: block.message().block_header(),
                        signature: block.signature().clone().into(),
                    },
                };

                Ok(api_types::ExecutionOptimisticResponse {
                    execution_optimistic: Some(execution_optimistic),
                    data,
                })
            })
        });

    /*
     * beacon/blocks
     */

    // POST beacon/blocks
    let post_beacon_blocks = eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("blocks"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(chain_filter.clone())
        .and(network_tx_filter.clone())
        .and(log_filter.clone())
        .and_then(
            |block: Arc<SignedBeaconBlock<T::EthSpec>>,
             chain: Arc<BeaconChain<T>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
             log: Logger| async move {
                // need to have cached the blob sidecar somewhere in the beacon chain
                // to publish
                publish_blocks::publish_block(None, block, None, chain, &network_tx, log)
                    .await
                    .map(|()| warp::reply())
            },
        );

    /*
     * beacon/blocks
     */

    // POST beacon/blocks
    let post_beacon_blinded_blocks = eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("blinded_blocks"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(chain_filter.clone())
        .and(network_tx_filter.clone())
        .and(log_filter.clone())
        .and_then(
            |block: SignedBeaconBlock<T::EthSpec, BlindedPayload<_>>,
             chain: Arc<BeaconChain<T>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
             log: Logger| async move {
                publish_blocks::publish_blinded_block(block, chain, &network_tx, log)
                    .await
                    .map(|()| warp::reply())
            },
        );

    let block_id_or_err = warp::path::param::<BlockId>().or_else(|_| async {
        Err(warp_utils::reject::custom_bad_request(
            "Invalid block ID".to_string(),
        ))
    });

    let beacon_blocks_path_v1 = eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("blocks"))
        .and(block_id_or_err)
        .and(chain_filter.clone());

    let beacon_blocks_path_any = any_version
        .and(warp::path("beacon"))
        .and(warp::path("blocks"))
        .and(block_id_or_err)
        .and(chain_filter.clone());

    // GET beacon/blocks/{block_id}
    let get_beacon_block = beacon_blocks_path_any
        .clone()
        .and(warp::path::end())
        .and(warp::header::optional::<api_types::Accept>("accept"))
        .and_then(
            |endpoint_version: EndpointVersion,
             block_id: BlockId,
             chain: Arc<BeaconChain<T>>,
             accept_header: Option<api_types::Accept>| {
                async move {
                    let (block, execution_optimistic) = block_id.full_block(&chain).await?;
                    let fork_name = block
                        .fork_name(&chain.spec)
                        .map_err(inconsistent_fork_rejection)?;

                    match accept_header {
                        Some(api_types::Accept::Ssz) => Response::builder()
                            .status(200)
                            .header("Content-Type", "application/octet-stream")
                            .body(block.as_ssz_bytes().into())
                            .map_err(|e| {
                                warp_utils::reject::custom_server_error(format!(
                                    "failed to create response: {}",
                                    e
                                ))
                            }),
                        _ => execution_optimistic_fork_versioned_response(
                            endpoint_version,
                            fork_name,
                            execution_optimistic,
                            block,
                        )
                        .map(|res| warp::reply::json(&res).into_response()),
                    }
                    .map(|resp| add_consensus_version_header(resp, fork_name))
                }
            },
        );

    // GET beacon/blocks/{block_id}/root
    let get_beacon_block_root = beacon_blocks_path_v1
        .clone()
        .and(warp::path("root"))
        .and(warp::path::end())
        .and_then(|block_id: BlockId, chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                let (block, execution_optimistic) = block_id.blinded_block(&chain)?;

                Ok(api_types::GenericResponse::from(api_types::RootData::from(
                    block.canonical_root(),
                ))
                .add_execution_optimistic(execution_optimistic))
            })
        });

    // GET beacon/blocks/{block_id}/attestations
    let get_beacon_block_attestations = beacon_blocks_path_v1
        .clone()
        .and(warp::path("attestations"))
        .and(warp::path::end())
        .and_then(|block_id: BlockId, chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                let (block, execution_optimistic) = block_id.blinded_block(&chain)?;

                Ok(
                    api_types::GenericResponse::from(block.message().body().attestations().clone())
                        .add_execution_optimistic(execution_optimistic),
                )
            })
        });

    // GET beacon/blinded_blocks/{block_id}
    let get_beacon_blinded_block = eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("blinded_blocks"))
        .and(block_id_or_err)
        .and(chain_filter.clone())
        .and(warp::path::end())
        .and(warp::header::optional::<api_types::Accept>("accept"))
        .and_then(
            |block_id: BlockId,
             chain: Arc<BeaconChain<T>>,
             accept_header: Option<api_types::Accept>| {
                blocking_task(move || {
                    let (block, execution_optimistic) = block_id.blinded_block(&chain)?;
                    let fork_name = block
                        .fork_name(&chain.spec)
                        .map_err(inconsistent_fork_rejection)?;

                    match accept_header {
                        Some(api_types::Accept::Ssz) => Response::builder()
                            .status(200)
                            .header("Content-Type", "application/octet-stream")
                            .body(block.as_ssz_bytes().into())
                            .map_err(|e| {
                                warp_utils::reject::custom_server_error(format!(
                                    "failed to create response: {}",
                                    e
                                ))
                            }),
                        _ => {
                            // Post as a V2 endpoint so we return the fork version.
                            execution_optimistic_fork_versioned_response(
                                V2,
                                fork_name,
                                execution_optimistic,
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
     * beacon/pool
     */

    let beacon_pool_path = eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("pool"))
        .and(chain_filter.clone());

    // POST beacon/pool/attestations
    let post_beacon_pool_attestations = beacon_pool_path
        .clone()
        .and(warp::path("attestations"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(network_tx_filter.clone())
        .and(log_filter.clone())
        .and_then(
            |chain: Arc<BeaconChain<T>>,
             attestations: Vec<Attestation<T::EthSpec>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
             log: Logger| {
                blocking_json_task(move || {
                    let seen_timestamp = timestamp_now();
                    let mut failures = Vec::new();
                    let mut num_already_known = 0;

                    for (index, attestation) in attestations.as_slice().iter().enumerate() {
                        let attestation = match chain
                            .verify_unaggregated_attestation_for_gossip(attestation, None)
                        {
                            Ok(attestation) => attestation,
                            Err(AttnError::PriorAttestationKnown { .. }) => {
                                num_already_known += 1;

                                // Skip to the next attestation since an attestation for this
                                // validator is already known in this epoch.
                                //
                                // There's little value for the network in validating a second
                                // attestation for another validator since it is either:
                                //
                                // 1. A duplicate.
                                // 2. Slashable.
                                // 3. Invalid.
                                //
                                // We are likely to get duplicates in the case where a VC is using
                                // fallback BNs. If the first BN actually publishes some/all of a
                                // batch of attestations but fails to respond in a timely fashion,
                                // the VC is likely to try publishing the attestations on another
                                // BN. That second BN may have already seen the attestations from
                                // the first BN and therefore indicate that the attestations are
                                // "already seen". An attestation that has already been seen has
                                // been published on the network so there's no actual error from
                                // the perspective of the user.
                                //
                                // It's better to prevent slashable attestations from ever
                                // appearing on the network than trying to slash validators,
                                // especially those validators connected to the local API.
                                //
                                // There might be *some* value in determining that this attestation
                                // is invalid, but since a valid attestation already it exists it
                                // appears that this validator is capable of producing valid
                                // attestations and there's no immediate cause for concern.
                                continue;
                            }
                            Err(e) => {
                                error!(log,
                                    "Failure verifying attestation for gossip";
                                    "error" => ?e,
                                    "request_index" => index,
                                    "committee_index" => attestation.data.index,
                                    "attestation_slot" => attestation.data.slot,
                                );
                                failures.push(api_types::Failure::new(
                                    index,
                                    format!("Verification: {:?}", e),
                                ));
                                // skip to the next attestation so we do not publish this one to gossip
                                continue;
                            }
                        };

                        // Notify the validator monitor.
                        chain
                            .validator_monitor
                            .read()
                            .register_api_unaggregated_attestation(
                                seen_timestamp,
                                attestation.indexed_attestation(),
                                &chain.slot_clock,
                            );

                        publish_pubsub_message(
                            &network_tx,
                            PubsubMessage::Attestation(Box::new((
                                attestation.subnet_id(),
                                attestation.attestation().clone(),
                            ))),
                        )?;

                        let committee_index = attestation.attestation().data.index;
                        let slot = attestation.attestation().data.slot;

                        if let Err(e) = chain.apply_attestation_to_fork_choice(&attestation) {
                            error!(log,
                                "Failure applying verified attestation to fork choice";
                                "error" => ?e,
                                "request_index" => index,
                                "committee_index" => committee_index,
                                "slot" => slot,
                            );
                            failures.push(api_types::Failure::new(
                                index,
                                format!("Fork choice: {:?}", e),
                            ));
                        };

                        if let Err(e) = chain.add_to_naive_aggregation_pool(&attestation) {
                            error!(log,
                                "Failure adding verified attestation to the naive aggregation pool";
                                "error" => ?e,
                                "request_index" => index,
                                "committee_index" => committee_index,
                                "slot" => slot,
                            );
                            failures.push(api_types::Failure::new(
                                index,
                                format!("Naive aggregation pool: {:?}", e),
                            ));
                        }
                    }

                    if num_already_known > 0 {
                        debug!(
                            log,
                            "Some unagg attestations already known";
                            "count" => num_already_known
                        );
                    }

                    if failures.is_empty() {
                        Ok(())
                    } else {
                        Err(warp_utils::reject::indexed_bad_request(
                            "error processing attestations".to_string(),
                            failures,
                        ))
                    }
                })
            },
        );

    // GET beacon/pool/attestations?committee_index,slot
    let get_beacon_pool_attestations = beacon_pool_path
        .clone()
        .and(warp::path("attestations"))
        .and(warp::path::end())
        .and(warp::query::<api_types::AttestationPoolQuery>())
        .and_then(
            |chain: Arc<BeaconChain<T>>, query: api_types::AttestationPoolQuery| {
                blocking_json_task(move || {
                    let query_filter = |data: &AttestationData| {
                        query.slot.map_or(true, |slot| slot == data.slot)
                            && query
                                .committee_index
                                .map_or(true, |index| index == data.index)
                    };

                    let mut attestations = chain.op_pool.get_filtered_attestations(query_filter);
                    attestations.extend(
                        chain
                            .naive_aggregation_pool
                            .read()
                            .iter()
                            .cloned()
                            .filter(|att| query_filter(&att.data)),
                    );
                    Ok(api_types::GenericResponse::from(attestations))
                })
            },
        );

    // POST beacon/pool/attester_slashings
    let post_beacon_pool_attester_slashings = beacon_pool_path
        .clone()
        .and(warp::path("attester_slashings"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(network_tx_filter.clone())
        .and_then(
            |chain: Arc<BeaconChain<T>>,
             slashing: AttesterSlashing<T::EthSpec>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                blocking_json_task(move || {
                    let outcome = chain
                        .verify_attester_slashing_for_gossip(slashing.clone())
                        .map_err(|e| {
                            warp_utils::reject::object_invalid(format!(
                                "gossip verification failed: {:?}",
                                e
                            ))
                        })?;

                    // Notify the validator monitor.
                    chain
                        .validator_monitor
                        .read()
                        .register_api_attester_slashing(&slashing);

                    if let ObservationOutcome::New(slashing) = outcome {
                        publish_pubsub_message(
                            &network_tx,
                            PubsubMessage::AttesterSlashing(Box::new(
                                slashing.clone().into_inner(),
                            )),
                        )?;

                        chain.import_attester_slashing(slashing);
                    }

                    Ok(())
                })
            },
        );

    // GET beacon/pool/attester_slashings
    let get_beacon_pool_attester_slashings = beacon_pool_path
        .clone()
        .and(warp::path("attester_slashings"))
        .and(warp::path::end())
        .and_then(|chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                let attestations = chain.op_pool.get_all_attester_slashings();
                Ok(api_types::GenericResponse::from(attestations))
            })
        });

    // POST beacon/pool/proposer_slashings
    let post_beacon_pool_proposer_slashings = beacon_pool_path
        .clone()
        .and(warp::path("proposer_slashings"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(network_tx_filter.clone())
        .and_then(
            |chain: Arc<BeaconChain<T>>,
             slashing: ProposerSlashing,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                blocking_json_task(move || {
                    let outcome = chain
                        .verify_proposer_slashing_for_gossip(slashing.clone())
                        .map_err(|e| {
                            warp_utils::reject::object_invalid(format!(
                                "gossip verification failed: {:?}",
                                e
                            ))
                        })?;

                    // Notify the validator monitor.
                    chain
                        .validator_monitor
                        .read()
                        .register_api_proposer_slashing(&slashing);

                    if let ObservationOutcome::New(slashing) = outcome {
                        publish_pubsub_message(
                            &network_tx,
                            PubsubMessage::ProposerSlashing(Box::new(
                                slashing.clone().into_inner(),
                            )),
                        )?;

                        chain.import_proposer_slashing(slashing);
                    }

                    Ok(())
                })
            },
        );

    // GET beacon/pool/proposer_slashings
    let get_beacon_pool_proposer_slashings = beacon_pool_path
        .clone()
        .and(warp::path("proposer_slashings"))
        .and(warp::path::end())
        .and_then(|chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                let attestations = chain.op_pool.get_all_proposer_slashings();
                Ok(api_types::GenericResponse::from(attestations))
            })
        });

    // POST beacon/pool/voluntary_exits
    let post_beacon_pool_voluntary_exits = beacon_pool_path
        .clone()
        .and(warp::path("voluntary_exits"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(network_tx_filter.clone())
        .and_then(
            |chain: Arc<BeaconChain<T>>,
             exit: SignedVoluntaryExit,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                blocking_json_task(move || {
                    let outcome = chain
                        .verify_voluntary_exit_for_gossip(exit.clone())
                        .map_err(|e| {
                            warp_utils::reject::object_invalid(format!(
                                "gossip verification failed: {:?}",
                                e
                            ))
                        })?;

                    // Notify the validator monitor.
                    chain
                        .validator_monitor
                        .read()
                        .register_api_voluntary_exit(&exit.message);

                    if let ObservationOutcome::New(exit) = outcome {
                        publish_pubsub_message(
                            &network_tx,
                            PubsubMessage::VoluntaryExit(Box::new(exit.clone().into_inner())),
                        )?;

                        chain.import_voluntary_exit(exit);
                    }

                    Ok(())
                })
            },
        );

    // GET beacon/pool/voluntary_exits
    let get_beacon_pool_voluntary_exits = beacon_pool_path
        .clone()
        .and(warp::path("voluntary_exits"))
        .and(warp::path::end())
        .and_then(|chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                let attestations = chain.op_pool.get_all_voluntary_exits();
                Ok(api_types::GenericResponse::from(attestations))
            })
        });

    // POST beacon/pool/sync_committees
    let post_beacon_pool_sync_committees = beacon_pool_path
        .clone()
        .and(warp::path("sync_committees"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(network_tx_filter.clone())
        .and(log_filter.clone())
        .and_then(
            |chain: Arc<BeaconChain<T>>,
             signatures: Vec<SyncCommitteeMessage>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
             log: Logger| {
                blocking_json_task(move || {
                    sync_committees::process_sync_committee_signatures(
                        signatures, network_tx, &chain, log,
                    )?;
                    Ok(api_types::GenericResponse::from(()))
                })
            },
        );

    // GET beacon/pool/bls_to_execution_changes
    let get_beacon_pool_bls_to_execution_changes = beacon_pool_path
        .clone()
        .and(warp::path("bls_to_execution_changes"))
        .and(warp::path::end())
        .and_then(|chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                let address_changes = chain.op_pool.get_all_bls_to_execution_changes();
                Ok(api_types::GenericResponse::from(address_changes))
            })
        });

    // POST beacon/pool/bls_to_execution_changes
    let post_beacon_pool_bls_to_execution_changes = beacon_pool_path
        .clone()
        .and(warp::path("bls_to_execution_changes"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(network_tx_filter.clone())
        .and(log_filter.clone())
        .and_then(
            |chain: Arc<BeaconChain<T>>,
             address_changes: Vec<SignedBlsToExecutionChange>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
             log: Logger| {
                blocking_json_task(move || {
                    let mut failures = vec![];

                    for (index, address_change) in address_changes.into_iter().enumerate() {
                        let validator_index = address_change.message.validator_index;

                        match chain.verify_bls_to_execution_change_for_gossip(address_change) {
                            Ok(ObservationOutcome::New(verified_address_change)) => {
                                #[cfg(feature = "withdrawals-processing")]
                                {
                                    publish_pubsub_message(
                                        &network_tx,
                                        PubsubMessage::BlsToExecutionChange(Box::new(
                                            verified_address_change.as_inner().clone(),
                                        )),
                                    )?;
                                }

                                chain.import_bls_to_execution_change(verified_address_change);
                            }
                            Ok(ObservationOutcome::AlreadyKnown) => {
                                debug!(
                                    log,
                                    "BLS to execution change already known";
                                    "validator_index" => validator_index,
                                );
                            }
                            Err(e) => {
                                error!(
                                    log,
                                    "Invalid BLS to execution change";
                                    "validator_index" => validator_index,
                                    "source" => "HTTP API",
                                );
                                failures.push(api_types::Failure::new(
                                    index,
                                    format!("invalid: {e:?}"),
                                ));
                            }
                        }
                    }

                    if failures.is_empty() {
                        Ok(())
                    } else {
                        Err(warp_utils::reject::indexed_bad_request(
                            "some BLS to execution changes failed to verify".into(),
                            failures,
                        ))
                    }
                })
            },
        );

    // GET beacon/deposit_snapshot
    let get_beacon_deposit_snapshot = eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("deposit_snapshot"))
        .and(warp::path::end())
        .and(warp::header::optional::<api_types::Accept>("accept"))
        .and(eth1_service_filter.clone())
        .and_then(
            |accept_header: Option<api_types::Accept>, eth1_service: eth1::Service| {
                blocking_task(move || match accept_header {
                    Some(api_types::Accept::Json) | None => {
                        let snapshot = eth1_service.get_deposit_snapshot();
                        Ok(
                            warp::reply::json(&api_types::GenericResponse::from(snapshot))
                                .into_response(),
                        )
                    }
                    _ => eth1_service
                        .get_deposit_snapshot()
                        .map(|snapshot| {
                            Response::builder()
                                .status(200)
                                .header("Content-Type", "application/octet-stream")
                                .body(snapshot.as_ssz_bytes().into())
                                .map_err(|e| {
                                    warp_utils::reject::custom_server_error(format!(
                                        "failed to create response: {}",
                                        e
                                    ))
                                })
                        })
                        .unwrap_or_else(|| {
                            Response::builder()
                                .status(503)
                                .header("Content-Type", "application/octet-stream")
                                .body(Vec::new().into())
                                .map_err(|e| {
                                    warp_utils::reject::custom_server_error(format!(
                                        "failed to create response: {}",
                                        e
                                    ))
                                })
                        }),
                })
            },
        );

    /*
     * config
     */

    let config_path = eth_v1.and(warp::path("config"));

    // GET config/fork_schedule
    let get_config_fork_schedule = config_path
        .and(warp::path("fork_schedule"))
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(|chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                let forks = ForkName::list_all()
                    .into_iter()
                    .filter_map(|fork_name| chain.spec.fork_for_name(fork_name))
                    .collect::<Vec<_>>();
                Ok(api_types::GenericResponse::from(forks))
            })
        });

    // GET config/spec
    let spec_fork_name = ctx.config.spec_fork_name;
    let get_config_spec = config_path
        .and(warp::path("spec"))
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(move |chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                let config_and_preset =
                    ConfigAndPreset::from_chain_spec::<T::EthSpec>(&chain.spec, spec_fork_name);
                Ok(api_types::GenericResponse::from(config_and_preset))
            })
        });

    // GET config/deposit_contract
    let get_config_deposit_contract = config_path
        .and(warp::path("deposit_contract"))
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(|chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                Ok(api_types::GenericResponse::from(
                    api_types::DepositContractData {
                        address: chain.spec.deposit_contract_address,
                        chain_id: chain.spec.deposit_chain_id,
                    },
                ))
            })
        });

    /*
     * debug
     */

    // GET debug/beacon/states/{state_id}
    let get_debug_beacon_states = any_version
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
        .and(chain_filter.clone())
        .and_then(
            |endpoint_version: EndpointVersion,
             state_id: StateId,
             accept_header: Option<api_types::Accept>,
             chain: Arc<BeaconChain<T>>| {
                blocking_task(move || match accept_header {
                    Some(api_types::Accept::Ssz) => {
                        // We can ignore the optimistic status for the "fork" since it's a
                        // specification constant that doesn't change across competing heads of the
                        // beacon chain.
                        let (state, _execution_optimistic) = state_id.state(&chain)?;
                        let fork_name = state
                            .fork_name(&chain.spec)
                            .map_err(inconsistent_fork_rejection)?;
                        Response::builder()
                            .status(200)
                            .header("Content-Type", "application/octet-stream")
                            .body(state.as_ssz_bytes().into())
                            .map(|resp| add_consensus_version_header(resp, fork_name))
                            .map_err(|e| {
                                warp_utils::reject::custom_server_error(format!(
                                    "failed to create response: {}",
                                    e
                                ))
                            })
                    }
                    _ => state_id.map_state_and_execution_optimistic(
                        &chain,
                        |state, execution_optimistic| {
                            let fork_name = state
                                .fork_name(&chain.spec)
                                .map_err(inconsistent_fork_rejection)?;
                            let res = execution_optimistic_fork_versioned_response(
                                endpoint_version,
                                fork_name,
                                execution_optimistic,
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
        .and(warp::path("debug"))
        .and(warp::path("beacon"))
        .and(warp::path("heads"))
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(
            |endpoint_version: EndpointVersion, chain: Arc<BeaconChain<T>>| {
                blocking_json_task(move || {
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

    /*
     * node
     */

    // GET node/identity
    let get_node_identity = eth_v1
        .and(warp::path("node"))
        .and(warp::path("identity"))
        .and(warp::path::end())
        .and(network_globals.clone())
        .and_then(|network_globals: Arc<NetworkGlobals<T::EthSpec>>| {
            blocking_json_task(move || {
                let enr = network_globals.local_enr();
                let p2p_addresses = enr.multiaddr_p2p_tcp();
                let discovery_addresses = enr.multiaddr_p2p_udp();
                let meta_data = network_globals.local_metadata.read();
                Ok(api_types::GenericResponse::from(api_types::IdentityData {
                    peer_id: network_globals.local_peer_id().to_base58(),
                    enr,
                    p2p_addresses,
                    discovery_addresses,
                    metadata: api_types::MetaData {
                        seq_number: *meta_data.seq_number(),
                        attnets: format!(
                            "0x{}",
                            hex::encode(meta_data.attnets().clone().into_bytes()),
                        ),
                        syncnets: format!(
                            "0x{}",
                            hex::encode(
                                meta_data
                                    .syncnets()
                                    .map(|x| x.clone())
                                    .unwrap_or_default()
                                    .into_bytes()
                            )
                        ),
                    },
                }))
            })
        });

    // GET node/version
    let get_node_version = eth_v1
        .and(warp::path("node"))
        .and(warp::path("version"))
        .and(warp::path::end())
        .and_then(|| {
            blocking_json_task(move || {
                Ok(api_types::GenericResponse::from(api_types::VersionData {
                    version: version_with_platform(),
                }))
            })
        });

    // GET node/syncing
    let get_node_syncing = eth_v1
        .and(warp::path("node"))
        .and(warp::path("syncing"))
        .and(warp::path::end())
        .and(network_globals.clone())
        .and(chain_filter.clone())
        .and_then(
            |network_globals: Arc<NetworkGlobals<T::EthSpec>>, chain: Arc<BeaconChain<T>>| {
                blocking_json_task(move || {
                    let head_slot = chain.canonical_head.cached_head().head_slot();
                    let current_slot = chain.slot_clock.now_or_genesis().ok_or_else(|| {
                        warp_utils::reject::custom_server_error("Unable to read slot clock".into())
                    })?;

                    // Taking advantage of saturating subtraction on slot.
                    let sync_distance = current_slot - head_slot;

                    let is_optimistic = chain
                        .is_optimistic_or_invalid_head()
                        .map_err(warp_utils::reject::beacon_chain_error)?;

                    let syncing_data = api_types::SyncingData {
                        is_syncing: network_globals.sync_state.read().is_syncing(),
                        is_optimistic: Some(is_optimistic),
                        head_slot,
                        sync_distance,
                    };

                    Ok(api_types::GenericResponse::from(syncing_data))
                })
            },
        );

    // GET node/health
    let get_node_health = eth_v1
        .and(warp::path("node"))
        .and(warp::path("health"))
        .and(warp::path::end())
        .and(network_globals.clone())
        .and_then(|network_globals: Arc<NetworkGlobals<T::EthSpec>>| {
            blocking_task(move || match *network_globals.sync_state.read() {
                SyncState::SyncingFinalized { .. }
                | SyncState::SyncingHead { .. }
                | SyncState::SyncTransition
                | SyncState::BackFillSyncing { .. } => Ok(warp::reply::with_status(
                    warp::reply(),
                    warp::http::StatusCode::PARTIAL_CONTENT,
                )),
                SyncState::Synced => Ok(warp::reply::with_status(
                    warp::reply(),
                    warp::http::StatusCode::OK,
                )),
                SyncState::Stalled => Err(warp_utils::reject::not_synced(
                    "sync stalled, beacon chain may not yet be initialized.".to_string(),
                )),
            })
        });

    // GET node/peers/{peer_id}
    let get_node_peers_by_id = eth_v1
        .and(warp::path("node"))
        .and(warp::path("peers"))
        .and(warp::path::param::<String>())
        .and(warp::path::end())
        .and(network_globals.clone())
        .and_then(
            |requested_peer_id: String, network_globals: Arc<NetworkGlobals<T::EthSpec>>| {
                blocking_json_task(move || {
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
                        let address = if let Some(socket_addr) = peer_info.seen_addresses().next() {
                            let mut addr = lighthouse_network::Multiaddr::from(socket_addr.ip());
                            addr.push(lighthouse_network::multiaddr::Protocol::Tcp(
                                socket_addr.port(),
                            ));
                            addr.to_string()
                        } else if let Some(addr) = peer_info.listening_addresses().first() {
                            addr.to_string()
                        } else {
                            String::new()
                        };

                        // the eth2 API spec implies only peers we have been connected to at some point should be included.
                        if let Some(dir) = peer_info.connection_direction().as_ref() {
                            return Ok(api_types::GenericResponse::from(api_types::PeerData {
                                peer_id: peer_id.to_string(),
                                enr: peer_info.enr().map(|enr| enr.to_base64()),
                                last_seen_p2p_address: address,
                                direction: api_types::PeerDirection::from_connection_direction(dir),
                                state: api_types::PeerState::from_peer_connection_status(
                                    peer_info.connection_status(),
                                ),
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
        .and(warp::path("node"))
        .and(warp::path("peers"))
        .and(warp::path::end())
        .and(multi_key_query::<api_types::PeersQuery>())
        .and(network_globals.clone())
        .and_then(
            |query_res: Result<api_types::PeersQuery, warp::Rejection>,
             network_globals: Arc<NetworkGlobals<T::EthSpec>>| {
                blocking_json_task(move || {
                    let query = query_res?;
                    let mut peers: Vec<api_types::PeerData> = Vec::new();
                    network_globals
                        .peers
                        .read()
                        .peers()
                        .for_each(|(peer_id, peer_info)| {
                            let address =
                                if let Some(socket_addr) = peer_info.seen_addresses().next() {
                                    let mut addr =
                                        lighthouse_network::Multiaddr::from(socket_addr.ip());
                                    addr.push(lighthouse_network::multiaddr::Protocol::Tcp(
                                        socket_addr.port(),
                                    ));
                                    addr.to_string()
                                } else if let Some(addr) = peer_info.listening_addresses().first() {
                                    addr.to_string()
                                } else {
                                    String::new()
                                };

                            // the eth2 API spec implies only peers we have been connected to at some point should be included.
                            if let Some(dir) = peer_info.connection_direction() {
                                let direction =
                                    api_types::PeerDirection::from_connection_direction(dir);
                                let state = api_types::PeerState::from_peer_connection_status(
                                    peer_info.connection_status(),
                                );

                                let state_matches = query.state.as_ref().map_or(true, |states| {
                                    states.iter().any(|state_param| *state_param == state)
                                });
                                let direction_matches =
                                    query.direction.as_ref().map_or(true, |directions| {
                                        directions.iter().any(|dir_param| *dir_param == direction)
                                    });

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
        .and(warp::path("node"))
        .and(warp::path("peer_count"))
        .and(warp::path::end())
        .and(network_globals.clone())
        .and_then(|network_globals: Arc<NetworkGlobals<T::EthSpec>>| {
            blocking_json_task(move || {
                let mut connected: u64 = 0;
                let mut connecting: u64 = 0;
                let mut disconnected: u64 = 0;
                let mut disconnecting: u64 = 0;

                network_globals
                    .peers
                    .read()
                    .peers()
                    .for_each(|(_, peer_info)| {
                        let state = api_types::PeerState::from_peer_connection_status(
                            peer_info.connection_status(),
                        );
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
        });
    /*
     * validator
     */

    // GET validator/duties/proposer/{epoch}
    let get_validator_duties_proposer = eth_v1
        .and(warp::path("validator"))
        .and(warp::path("duties"))
        .and(warp::path("proposer"))
        .and(warp::path::param::<Epoch>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid epoch".to_string(),
            ))
        }))
        .and(warp::path::end())
        .and(not_while_syncing_filter.clone())
        .and(chain_filter.clone())
        .and(log_filter.clone())
        .and_then(|epoch: Epoch, chain: Arc<BeaconChain<T>>, log: Logger| {
            blocking_json_task(move || proposer_duties::proposer_duties(epoch, &chain, &log))
        });

    // GET validator/blocks/{slot}
    let get_validator_blocks = any_version
        .and(warp::path("validator"))
        .and(warp::path("blocks"))
        .and(warp::path::param::<Slot>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid slot".to_string(),
            ))
        }))
        .and(warp::path::end())
        .and(not_while_syncing_filter.clone())
        .and(warp::query::<api_types::ValidatorBlocksQuery>())
        .and(chain_filter.clone())
        .and_then(
            |endpoint_version: EndpointVersion,
             slot: Slot,
             query: api_types::ValidatorBlocksQuery,
             chain: Arc<BeaconChain<T>>| async move {
                let randao_reveal = query.randao_reveal.decompress().map_err(|e| {
                    warp_utils::reject::custom_bad_request(format!(
                        "randao reveal is not a valid BLS signature: {:?}",
                        e
                    ))
                })?;

                let randao_verification =
                    if query.skip_randao_verification == SkipRandaoVerification::Yes {
                        if !randao_reveal.is_infinity() {
                            return Err(warp_utils::reject::custom_bad_request(
                                "randao_reveal must be point-at-infinity if verification is skipped"
                                    .into(),
                            ));
                        }
                        ProduceBlockVerification::NoVerification
                    } else {
                        ProduceBlockVerification::VerifyRandao
                    };

                let (block, _) = chain
                    .produce_block_with_verification::<FullPayload<T::EthSpec>>(
                        randao_reveal,
                        slot,
                        query.graffiti.map(Into::into),
                        randao_verification,
                    )
                    .await
                    .map_err(warp_utils::reject::block_production_error)?;
                let fork_name = block
                    .to_ref()
                    .fork_name(&chain.spec)
                    .map_err(inconsistent_fork_rejection)?;

                fork_versioned_response(endpoint_version, fork_name, block)
                    .map(|response| warp::reply::json(&response))
            },
        );

    // GET validator/blinded_blocks/{slot}
    let get_validator_blinded_blocks = eth_v1
        .and(warp::path("validator"))
        .and(warp::path("blinded_blocks"))
        .and(warp::path::param::<Slot>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid slot".to_string(),
            ))
        }))
        .and(warp::path::end())
        .and(not_while_syncing_filter.clone())
        .and(warp::query::<api_types::ValidatorBlocksQuery>())
        .and(chain_filter.clone())
        .and_then(
            |slot: Slot,
             query: api_types::ValidatorBlocksQuery,
             chain: Arc<BeaconChain<T>>| async move {
                let randao_reveal = query.randao_reveal.decompress().map_err(|e| {
                    warp_utils::reject::custom_bad_request(format!(
                        "randao reveal is not a valid BLS signature: {:?}",
                        e
                    ))
                })?;

                let randao_verification =
                    if query.skip_randao_verification == SkipRandaoVerification::Yes {
                        if !randao_reveal.is_infinity() {
                            return Err(warp_utils::reject::custom_bad_request(
                                "randao_reveal must be point-at-infinity if verification is skipped"
                                    .into()
                            ));
                        }
                        ProduceBlockVerification::NoVerification
                    } else {
                        ProduceBlockVerification::VerifyRandao
                    };

                let (block, _) = chain
                    .produce_block_with_verification::<BlindedPayload<T::EthSpec>>(
                        randao_reveal,
                        slot,
                        query.graffiti.map(Into::into),
                        randao_verification,
                    )
                    .await
                    .map_err(warp_utils::reject::block_production_error)?;
                let fork_name = block
                    .to_ref()
                    .fork_name(&chain.spec)
                    .map_err(inconsistent_fork_rejection)?;

                // Pose as a V2 endpoint so we return the fork `version`.
                fork_versioned_response(V2, fork_name, block)
                    .map(|response| warp::reply::json(&response))
            },
        );

    // GET validator/attestation_data?slot,committee_index
    let get_validator_attestation_data = eth_v1
        .and(warp::path("validator"))
        .and(warp::path("attestation_data"))
        .and(warp::path::end())
        .and(warp::query::<api_types::ValidatorAttestationDataQuery>())
        .and(not_while_syncing_filter.clone())
        .and(chain_filter.clone())
        .and_then(
            |query: api_types::ValidatorAttestationDataQuery, chain: Arc<BeaconChain<T>>| {
                blocking_json_task(move || {
                    let current_slot = chain
                        .slot()
                        .map_err(warp_utils::reject::beacon_chain_error)?;

                    // allow a tolerance of one slot to account for clock skew
                    if query.slot > current_slot + 1 {
                        return Err(warp_utils::reject::custom_bad_request(format!(
                            "request slot {} is more than one slot past the current slot {}",
                            query.slot, current_slot
                        )));
                    }

                    chain
                        .produce_unaggregated_attestation(query.slot, query.committee_index)
                        .map(|attestation| attestation.data)
                        .map(api_types::GenericResponse::from)
                        .map_err(warp_utils::reject::beacon_chain_error)
                })
            },
        );

    // GET validator/aggregate_attestation?attestation_data_root,slot
    let get_validator_aggregate_attestation = eth_v1
        .and(warp::path("validator"))
        .and(warp::path("aggregate_attestation"))
        .and(warp::path::end())
        .and(warp::query::<api_types::ValidatorAggregateAttestationQuery>())
        .and(not_while_syncing_filter.clone())
        .and(chain_filter.clone())
        .and_then(
            |query: api_types::ValidatorAggregateAttestationQuery, chain: Arc<BeaconChain<T>>| {
                blocking_json_task(move || {
                    chain
                        .get_aggregated_attestation_by_slot_and_root(
                            query.slot,
                            &query.attestation_data_root,
                        )
                        .map_err(|e| {
                            warp_utils::reject::custom_bad_request(format!(
                                "unable to fetch aggregate: {:?}",
                                e
                            ))
                        })?
                        .map(api_types::GenericResponse::from)
                        .ok_or_else(|| {
                            warp_utils::reject::custom_not_found(
                                "no matching aggregate found".to_string(),
                            )
                        })
                })
            },
        );

    // POST validator/duties/attester/{epoch}
    let post_validator_duties_attester = eth_v1
        .and(warp::path("validator"))
        .and(warp::path("duties"))
        .and(warp::path("attester"))
        .and(warp::path::param::<Epoch>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid epoch".to_string(),
            ))
        }))
        .and(warp::path::end())
        .and(not_while_syncing_filter.clone())
        .and(warp::body::json())
        .and(chain_filter.clone())
        .and_then(
            |epoch: Epoch, indices: api_types::ValidatorIndexData, chain: Arc<BeaconChain<T>>| {
                blocking_json_task(move || {
                    attester_duties::attester_duties(epoch, &indices.0, &chain)
                })
            },
        );

    // POST validator/duties/sync
    let post_validator_duties_sync = eth_v1
        .and(warp::path("validator"))
        .and(warp::path("duties"))
        .and(warp::path("sync"))
        .and(warp::path::param::<Epoch>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid epoch".to_string(),
            ))
        }))
        .and(warp::path::end())
        .and(not_while_syncing_filter.clone())
        .and(warp::body::json())
        .and(chain_filter.clone())
        .and_then(
            |epoch: Epoch, indices: api_types::ValidatorIndexData, chain: Arc<BeaconChain<T>>| {
                blocking_json_task(move || {
                    sync_committees::sync_committee_duties(epoch, &indices.0, &chain)
                })
            },
        );

    // GET validator/sync_committee_contribution
    let get_validator_sync_committee_contribution = eth_v1
        .and(warp::path("validator"))
        .and(warp::path("sync_committee_contribution"))
        .and(warp::path::end())
        .and(warp::query::<SyncContributionData>())
        .and(not_while_syncing_filter.clone())
        .and(chain_filter.clone())
        .and_then(
            |sync_committee_data: SyncContributionData, chain: Arc<BeaconChain<T>>| {
                blocking_json_task(move || {
                    chain
                        .get_aggregated_sync_committee_contribution(&sync_committee_data)
                        .map_err(|e| {
                            warp_utils::reject::custom_bad_request(format!(
                                "unable to fetch sync contribution: {:?}",
                                e
                            ))
                        })?
                        .map(api_types::GenericResponse::from)
                        .ok_or_else(|| {
                            warp_utils::reject::custom_not_found(
                                "no matching sync contribution found".to_string(),
                            )
                        })
                })
            },
        );

    // POST validator/aggregate_and_proofs
    let post_validator_aggregate_and_proofs = eth_v1
        .and(warp::path("validator"))
        .and(warp::path("aggregate_and_proofs"))
        .and(warp::path::end())
        .and(not_while_syncing_filter.clone())
        .and(chain_filter.clone())
        .and(warp::body::json())
        .and(network_tx_filter.clone())
        .and(log_filter.clone())
        .and_then(
            |chain: Arc<BeaconChain<T>>,
             aggregates: Vec<SignedAggregateAndProof<T::EthSpec>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>, log: Logger| {
                blocking_json_task(move || {
                    let seen_timestamp = timestamp_now();
                    let mut verified_aggregates = Vec::with_capacity(aggregates.len());
                    let mut messages = Vec::with_capacity(aggregates.len());
                    let mut failures = Vec::new();

                    // Verify that all messages in the post are valid before processing further
                    for (index, aggregate) in aggregates.iter().enumerate() {
                        match chain.verify_aggregated_attestation_for_gossip(aggregate) {
                            Ok(verified_aggregate) => {
                                messages.push(PubsubMessage::AggregateAndProofAttestation(Box::new(
                                    verified_aggregate.aggregate().clone(),
                                )));

                                // Notify the validator monitor.
                                chain
                                    .validator_monitor
                                    .read()
                                    .register_api_aggregated_attestation(
                                        seen_timestamp,
                                        verified_aggregate.aggregate(),
                                        verified_aggregate.indexed_attestation(),
                                        &chain.slot_clock,
                                    );

                                verified_aggregates.push((index, verified_aggregate));
                            }
                            // If we already know the attestation, don't broadcast it or attempt to
                            // further verify it. Return success.
                            //
                            // It's reasonably likely that two different validators produce
                            // identical aggregates, especially if they're using the same beacon
                            // node.
                            Err(AttnError::AttestationAlreadyKnown(_)) => continue,
                            // If we've already seen this aggregator produce an aggregate, just
                            // skip this one.
                            //
                            // We're likely to see this with VCs that use fallback BNs. The first
                            // BN might time-out *after* publishing the aggregate and then the
                            // second BN will indicate it's already seen the aggregate.
                            //
                            // There's no actual error for the user or the network since the
                            // aggregate has been successfully published by some other node.
                            Err(AttnError::AggregatorAlreadyKnown(_)) => continue,
                            Err(e) => {
                                error!(log,
                                    "Failure verifying aggregate and proofs";
                                    "error" => format!("{:?}", e),
                                    "request_index" => index,
                                    "aggregator_index" => aggregate.message.aggregator_index,
                                    "attestation_index" => aggregate.message.aggregate.data.index,
                                    "attestation_slot" => aggregate.message.aggregate.data.slot,
                                );
                                failures.push(api_types::Failure::new(index, format!("Verification: {:?}", e)));
                            }
                        }
                    }

                    // Publish aggregate attestations to the libp2p network
                    if !messages.is_empty() {
                        publish_network_message(&network_tx, NetworkMessage::Publish { messages })?;
                    }

                    // Import aggregate attestations
                    for (index, verified_aggregate) in verified_aggregates {
                        if let Err(e) = chain.apply_attestation_to_fork_choice(&verified_aggregate) {
                            error!(log,
                                    "Failure applying verified aggregate attestation to fork choice";
                                    "error" => format!("{:?}", e),
                                    "request_index" => index,
                                    "aggregator_index" => verified_aggregate.aggregate().message.aggregator_index,
                                    "attestation_index" => verified_aggregate.attestation().data.index,
                                    "attestation_slot" => verified_aggregate.attestation().data.slot,
                                );
                            failures.push(api_types::Failure::new(index, format!("Fork choice: {:?}", e)));
                        }
                        if let Err(e) = chain.add_to_block_inclusion_pool(verified_aggregate) {
                            warn!(
                                log,
                                "Could not add verified aggregate attestation to the inclusion pool";
                                "error" => ?e,
                                "request_index" => index,
                            );
                            failures.push(api_types::Failure::new(index, format!("Op pool: {:?}", e)));
                        }
                    }

                    if !failures.is_empty() {
                        Err(warp_utils::reject::indexed_bad_request("error processing aggregate and proofs".to_string(),
                                                                    failures,
                        ))
                    } else {
                        Ok(())
                    }
                })
            },
        );

    let post_validator_contribution_and_proofs = eth_v1
        .and(warp::path("validator"))
        .and(warp::path("contribution_and_proofs"))
        .and(warp::path::end())
        .and(not_while_syncing_filter.clone())
        .and(chain_filter.clone())
        .and(warp::body::json())
        .and(network_tx_filter)
        .and(log_filter.clone())
        .and_then(
            |chain: Arc<BeaconChain<T>>,
             contributions: Vec<SignedContributionAndProof<T::EthSpec>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
             log: Logger| {
                blocking_json_task(move || {
                    sync_committees::process_signed_contribution_and_proofs(
                        contributions,
                        network_tx,
                        &chain,
                        log,
                    )?;
                    Ok(api_types::GenericResponse::from(()))
                })
            },
        );

    // POST validator/beacon_committee_subscriptions
    let post_validator_beacon_committee_subscriptions = eth_v1
        .and(warp::path("validator"))
        .and(warp::path("beacon_committee_subscriptions"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(validator_subscription_tx_filter.clone())
        .and(chain_filter.clone())
        .and(log_filter.clone())
        .and_then(
            |subscriptions: Vec<api_types::BeaconCommitteeSubscription>,
             validator_subscription_tx: Sender<ValidatorSubscriptionMessage>,
             chain: Arc<BeaconChain<T>>,
             log: Logger| {
                blocking_json_task(move || {
                    for subscription in &subscriptions {
                        chain
                            .validator_monitor
                            .write()
                            .auto_register_local_validator(subscription.validator_index);

                        let validator_subscription = api_types::ValidatorSubscription {
                            validator_index: subscription.validator_index,
                            attestation_committee_index: subscription.committee_index,
                            slot: subscription.slot,
                            committee_count_at_slot: subscription.committees_at_slot,
                            is_aggregator: subscription.is_aggregator,
                        };

                        let message = ValidatorSubscriptionMessage::AttestationSubscribe {
                            subscriptions: vec![validator_subscription],
                        };
                        if let Err(e) = validator_subscription_tx.try_send(message) {
                            warn!(
                                log,
                                "Unable to process committee subscriptions";
                                "info" => "the host may be overloaded or resource-constrained",
                                "error" => ?e,
                            );
                            return Err(warp_utils::reject::custom_server_error(
                                "unable to queue subscription, host may be overloaded or shutting down".to_string(),
                            ));
                        }
                    }

                    Ok(())
                })
            },
        );

    // POST validator/prepare_beacon_proposer
    let post_validator_prepare_beacon_proposer = eth_v1
        .and(warp::path("validator"))
        .and(warp::path("prepare_beacon_proposer"))
        .and(warp::path::end())
        .and(not_while_syncing_filter.clone())
        .and(chain_filter.clone())
        .and(log_filter.clone())
        .and(warp::body::json())
        .and_then(
            |chain: Arc<BeaconChain<T>>,
             log: Logger,
             preparation_data: Vec<ProposerPreparationData>| async move {
                let execution_layer = chain
                    .execution_layer
                    .as_ref()
                    .ok_or(BeaconChainError::ExecutionLayerMissing)
                    .map_err(warp_utils::reject::beacon_chain_error)?;

                let current_slot = chain
                    .slot()
                    .map_err(warp_utils::reject::beacon_chain_error)?;
                let current_epoch = current_slot.epoch(T::EthSpec::slots_per_epoch());

                debug!(
                    log,
                    "Received proposer preparation data";
                    "count" => preparation_data.len(),
                );

                execution_layer
                    .update_proposer_preparation(current_epoch, &preparation_data)
                    .await;

                chain
                    .prepare_beacon_proposer(current_slot)
                    .await
                    .map_err(|e| {
                        warp_utils::reject::custom_bad_request(format!(
                            "error updating proposer preparations: {:?}",
                            e
                        ))
                    })?;

                Ok::<_, warp::reject::Rejection>(warp::reply::json(&()))
            },
        );

    // POST validator/register_validator
    let post_validator_register_validator = eth_v1
        .and(warp::path("validator"))
        .and(warp::path("register_validator"))
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and(log_filter.clone())
        .and(warp::body::json())
        .and_then(
            |chain: Arc<BeaconChain<T>>,
             log: Logger,
             register_val_data: Vec<SignedValidatorRegistrationData>| async move {
                let execution_layer = chain
                    .execution_layer
                    .as_ref()
                    .ok_or(BeaconChainError::ExecutionLayerMissing)
                    .map_err(warp_utils::reject::beacon_chain_error)?;
                let current_slot = chain
                    .slot_clock
                    .now_or_genesis()
                    .ok_or(BeaconChainError::UnableToReadSlot)
                    .map_err(warp_utils::reject::beacon_chain_error)?;
                let current_epoch = current_slot.epoch(T::EthSpec::slots_per_epoch());

                debug!(
                    log,
                    "Received register validator request";
                    "count" => register_val_data.len(),
                );

                let head_snapshot = chain.head_snapshot();
                let spec = &chain.spec;

                let (preparation_data, filtered_registration_data): (
                    Vec<ProposerPreparationData>,
                    Vec<SignedValidatorRegistrationData>,
                ) = register_val_data
                    .into_iter()
                    .filter_map(|register_data| {
                        chain
                            .validator_index(&register_data.message.pubkey)
                            .ok()
                            .flatten()
                            .and_then(|validator_index| {
                                let validator = head_snapshot
                                    .beacon_state
                                    .get_validator(validator_index)
                                    .ok()?;
                                let validator_status = ValidatorStatus::from_validator(
                                    validator,
                                    current_epoch,
                                    spec.far_future_epoch,
                                )
                                .superstatus();
                                let is_active_or_pending =
                                    matches!(validator_status, ValidatorStatus::Pending)
                                        || matches!(validator_status, ValidatorStatus::Active);

                                // Filter out validators who are not 'active' or 'pending'.
                                is_active_or_pending.then_some({
                                    (
                                        ProposerPreparationData {
                                            validator_index: validator_index as u64,
                                            fee_recipient: register_data.message.fee_recipient,
                                        },
                                        register_data,
                                    )
                                })
                            })
                    })
                    .unzip();

                // Update the prepare beacon proposer cache based on this request.
                execution_layer
                    .update_proposer_preparation(current_epoch, &preparation_data)
                    .await;

                // Call prepare beacon proposer blocking with the latest update in order to make
                // sure we have a local payload to fall back to in the event of the blinded block
                // flow failing.
                chain
                    .prepare_beacon_proposer(current_slot)
                    .await
                    .map_err(|e| {
                        warp_utils::reject::custom_bad_request(format!(
                            "error updating proposer preparations: {:?}",
                            e
                        ))
                    })?;

                let builder = execution_layer
                    .builder()
                    .as_ref()
                    .ok_or(BeaconChainError::BuilderMissing)
                    .map_err(warp_utils::reject::beacon_chain_error)?;

                info!(
                    log,
                    "Forwarding register validator request to connected builder";
                    "count" => filtered_registration_data.len(),
                );

                builder
                    .post_builder_validators(&filtered_registration_data)
                    .await
                    .map(|resp| warp::reply::json(&resp))
                    .map_err(|e| {
                        error!(
                            log,
                            "Relay error when registering validator(s)";
                            "num_registrations" => filtered_registration_data.len(),
                            "error" => ?e
                        );
                        // Forward the HTTP status code if we are able to, otherwise fall back
                        // to a server error.
                        if let eth2::Error::ServerMessage(message) = e {
                            if message.code == StatusCode::BAD_REQUEST.as_u16() {
                                return warp_utils::reject::custom_bad_request(message.message);
                            } else {
                                // According to the spec this response should only be a 400 or 500,
                                // so we fall back to a 500 here.
                                return warp_utils::reject::custom_server_error(message.message);
                            }
                        }
                        warp_utils::reject::custom_server_error(format!("{e:?}"))
                    })
            },
        );
    // POST validator/sync_committee_subscriptions
    let post_validator_sync_committee_subscriptions = eth_v1
        .and(warp::path("validator"))
        .and(warp::path("sync_committee_subscriptions"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(validator_subscription_tx_filter)
        .and(chain_filter.clone())
        .and(log_filter.clone())
        .and_then(
            |subscriptions: Vec<types::SyncCommitteeSubscription>,
             validator_subscription_tx: Sender<ValidatorSubscriptionMessage>,
             chain: Arc<BeaconChain<T>>,
             log: Logger
             | {
                blocking_json_task(move || {
                    for subscription in subscriptions {
                        chain
                            .validator_monitor
                            .write()
                            .auto_register_local_validator(subscription.validator_index);

                        let message = ValidatorSubscriptionMessage::SyncCommitteeSubscribe {
                                subscriptions: vec![subscription],
                            };
                        if let Err(e) = validator_subscription_tx.try_send(message) {
                            warn!(
                                log,
                                "Unable to process sync subscriptions";
                                "info" => "the host may be overloaded or resource-constrained",
                                "error" => ?e
                            );
                            return Err(warp_utils::reject::custom_server_error(
                                "unable to queue subscription, host may be overloaded or shutting down".to_string(),
                            ));
                        }
                    }

                    Ok(())
                })
            },
        );

    // POST lighthouse/liveness
    let post_lighthouse_liveness = warp::path("lighthouse")
        .and(warp::path("liveness"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(chain_filter.clone())
        .and_then(
            |request_data: api_types::LivenessRequestData, chain: Arc<BeaconChain<T>>| {
                blocking_json_task(move || {
                    // Ensure the request is for either the current, previous or next epoch.
                    let current_epoch = chain
                        .epoch()
                        .map_err(warp_utils::reject::beacon_chain_error)?;
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
                                index: index as u64,
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
        .and_then(|| {
            blocking_json_task(move || {
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
        .and(system_info_filter)
        .and(app_start_filter)
        .and(data_dir_filter)
        .and(network_globals.clone())
        .and_then(
            |sysinfo, app_start: std::time::Instant, data_dir, network_globals| {
                blocking_json_task(move || {
                    let app_uptime = app_start.elapsed().as_secs() as u64;
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
        .and(chain_filter.clone())
        .and_then(|chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                ui::get_validator_count(chain).map(api_types::GenericResponse::from)
            })
        });

    // GET lighthouse/syncing
    let get_lighthouse_syncing = warp::path("lighthouse")
        .and(warp::path("syncing"))
        .and(warp::path::end())
        .and(network_globals.clone())
        .and_then(|network_globals: Arc<NetworkGlobals<T::EthSpec>>| {
            blocking_json_task(move || {
                Ok(api_types::GenericResponse::from(
                    network_globals.sync_state(),
                ))
            })
        });

    // GET lighthouse/nat
    let get_lighthouse_nat = warp::path("lighthouse")
        .and(warp::path("nat"))
        .and(warp::path::end())
        .and_then(|| {
            blocking_json_task(move || {
                Ok(api_types::GenericResponse::from(
                    lighthouse_network::metrics::NAT_OPEN
                        .as_ref()
                        .map(|v| v.get())
                        .unwrap_or(0)
                        != 0,
                ))
            })
        });

    // GET lighthouse/peers
    let get_lighthouse_peers = warp::path("lighthouse")
        .and(warp::path("peers"))
        .and(warp::path::end())
        .and(network_globals.clone())
        .and_then(|network_globals: Arc<NetworkGlobals<T::EthSpec>>| {
            blocking_json_task(move || {
                Ok(network_globals
                    .peers
                    .read()
                    .peers()
                    .map(|(peer_id, peer_info)| eth2::lighthouse::Peer {
                        peer_id: peer_id.to_string(),
                        peer_info: peer_info.clone(),
                    })
                    .collect::<Vec<_>>())
            })
        });

    // GET lighthouse/peers/connected
    let get_lighthouse_peers_connected = warp::path("lighthouse")
        .and(warp::path("peers"))
        .and(warp::path("connected"))
        .and(warp::path::end())
        .and(network_globals)
        .and_then(|network_globals: Arc<NetworkGlobals<T::EthSpec>>| {
            blocking_json_task(move || {
                Ok(network_globals
                    .peers
                    .read()
                    .connected_peers()
                    .map(|(peer_id, peer_info)| eth2::lighthouse::Peer {
                        peer_id: peer_id.to_string(),
                        peer_info: peer_info.clone(),
                    })
                    .collect::<Vec<_>>())
            })
        });

    // GET lighthouse/proto_array
    let get_lighthouse_proto_array = warp::path("lighthouse")
        .and(warp::path("proto_array"))
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(|chain: Arc<BeaconChain<T>>| {
            blocking_task(move || {
                Ok::<_, warp::Rejection>(warp::reply::json(&api_types::GenericResponseRef::from(
                    chain
                        .canonical_head
                        .fork_choice_read_lock()
                        .proto_array()
                        .core_proto_array(),
                )))
            })
        });

    // GET lighthouse/validator_inclusion/{epoch}/{validator_id}
    let get_lighthouse_validator_inclusion_global = warp::path("lighthouse")
        .and(warp::path("validator_inclusion"))
        .and(warp::path::param::<Epoch>())
        .and(warp::path::param::<ValidatorId>())
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(
            |epoch: Epoch, validator_id: ValidatorId, chain: Arc<BeaconChain<T>>| {
                blocking_json_task(move || {
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
        .and(chain_filter.clone())
        .and_then(|epoch: Epoch, chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                validator_inclusion::global_validator_inclusion_data(epoch, &chain)
                    .map(api_types::GenericResponse::from)
            })
        });

    // GET lighthouse/eth1/syncing
    let get_lighthouse_eth1_syncing = warp::path("lighthouse")
        .and(warp::path("eth1"))
        .and(warp::path("syncing"))
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(|chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                let current_slot_opt = chain.slot().ok();

                chain
                    .eth1_chain
                    .as_ref()
                    .ok_or_else(|| {
                        warp_utils::reject::custom_not_found(
                            "Eth1 sync is disabled. See the --eth1 CLI flag.".to_string(),
                        )
                    })
                    .and_then(|eth1| {
                        eth1.sync_status(chain.genesis_time, current_slot_opt, &chain.spec)
                            .ok_or_else(|| {
                                warp_utils::reject::custom_server_error(
                                    "Unable to determine Eth1 sync status".to_string(),
                                )
                            })
                    })
                    .map(api_types::GenericResponse::from)
            })
        });

    // GET lighthouse/eth1/block_cache
    let get_lighthouse_eth1_block_cache = warp::path("lighthouse")
        .and(warp::path("eth1"))
        .and(warp::path("block_cache"))
        .and(warp::path::end())
        .and(eth1_service_filter.clone())
        .and_then(|eth1_service: eth1::Service| {
            blocking_json_task(move || {
                Ok(api_types::GenericResponse::from(
                    eth1_service
                        .blocks()
                        .read()
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>(),
                ))
            })
        });

    // GET lighthouse/eth1/deposit_cache
    let get_lighthouse_eth1_deposit_cache = warp::path("lighthouse")
        .and(warp::path("eth1"))
        .and(warp::path("deposit_cache"))
        .and(warp::path::end())
        .and(eth1_service_filter)
        .and_then(|eth1_service: eth1::Service| {
            blocking_json_task(move || {
                Ok(api_types::GenericResponse::from(
                    eth1_service
                        .deposits()
                        .read()
                        .cache
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>(),
                ))
            })
        });

    // GET lighthouse/beacon/states/{state_id}/ssz
    let get_lighthouse_beacon_states_ssz = warp::path("lighthouse")
        .and(warp::path("beacon"))
        .and(warp::path("states"))
        .and(warp::path::param::<StateId>())
        .and(warp::path("ssz"))
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(|state_id: StateId, chain: Arc<BeaconChain<T>>| {
            blocking_task(move || {
                // This debug endpoint provides no indication of optimistic status.
                let (state, _execution_optimistic) = state_id.state(&chain)?;
                Response::builder()
                    .status(200)
                    .header("Content-Type", "application/ssz")
                    .body(state.as_ssz_bytes())
                    .map_err(|e| {
                        warp_utils::reject::custom_server_error(format!(
                            "failed to create response: {}",
                            e
                        ))
                    })
            })
        });

    // GET lighthouse/staking
    let get_lighthouse_staking = warp::path("lighthouse")
        .and(warp::path("staking"))
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(|chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                if chain.eth1_chain.is_some() {
                    Ok(())
                } else {
                    Err(warp_utils::reject::custom_not_found(
                        "staking is not enabled, \
                        see the --staking CLI flag"
                            .to_string(),
                    ))
                }
            })
        });

    let database_path = warp::path("lighthouse").and(warp::path("database"));

    // GET lighthouse/database/info
    let get_lighthouse_database_info = database_path
        .and(warp::path("info"))
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(|chain: Arc<BeaconChain<T>>| blocking_json_task(move || database::info(chain)));

    // POST lighthouse/database/reconstruct
    let post_lighthouse_database_reconstruct = database_path
        .and(warp::path("reconstruct"))
        .and(warp::path::end())
        .and(not_while_syncing_filter)
        .and(chain_filter.clone())
        .and_then(|chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                chain.store_migrator.process_reconstruction();
                Ok("success")
            })
        });

    // POST lighthouse/database/historical_blocks
    let post_lighthouse_database_historical_blocks = database_path
        .and(warp::path("historical_blocks"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(chain_filter.clone())
        .and(log_filter.clone())
        .and_then(
            |blocks: Vec<Arc<SignedBlindedBeaconBlock<T::EthSpec>>>,
             chain: Arc<BeaconChain<T>>,
             log: Logger| {
                info!(
                    log,
                    "Importing historical blocks";
                    "count" => blocks.len(),
                    "source" => "http_api"
                );
                blocking_json_task(move || database::historical_blocks(chain, blocks))
            },
        );

    // GET lighthouse/analysis/block_rewards
    let get_lighthouse_block_rewards = warp::path("lighthouse")
        .and(warp::path("analysis"))
        .and(warp::path("block_rewards"))
        .and(warp::query::<eth2::lighthouse::BlockRewardsQuery>())
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and(log_filter.clone())
        .and_then(|query, chain, log| {
            blocking_json_task(move || block_rewards::get_block_rewards(query, chain, log))
        });

    // POST lighthouse/analysis/block_rewards
    let post_lighthouse_block_rewards = warp::path("lighthouse")
        .and(warp::path("analysis"))
        .and(warp::path("block_rewards"))
        .and(warp::body::json())
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and(log_filter.clone())
        .and_then(|blocks, chain, log| {
            blocking_json_task(move || block_rewards::compute_block_rewards(blocks, chain, log))
        });

    // GET lighthouse/analysis/attestation_performance/{index}
    let get_lighthouse_attestation_performance = warp::path("lighthouse")
        .and(warp::path("analysis"))
        .and(warp::path("attestation_performance"))
        .and(warp::path::param::<String>())
        .and(warp::query::<eth2::lighthouse::AttestationPerformanceQuery>())
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(|target, query, chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                attestation_performance::get_attestation_performance(target, query, chain)
            })
        });

    // GET lighthouse/analysis/block_packing_efficiency
    let get_lighthouse_block_packing_efficiency = warp::path("lighthouse")
        .and(warp::path("analysis"))
        .and(warp::path("block_packing_efficiency"))
        .and(warp::query::<eth2::lighthouse::BlockPackingEfficiencyQuery>())
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(|query, chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                block_packing_efficiency::get_block_packing_efficiency(query, chain)
            })
        });

    // GET lighthouse/merge_readiness
    let get_lighthouse_merge_readiness = warp::path("lighthouse")
        .and(warp::path("merge_readiness"))
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(|chain: Arc<BeaconChain<T>>| async move {
            let merge_readiness = chain.check_merge_readiness().await;
            Ok::<_, warp::reject::Rejection>(warp::reply::json(&api_types::GenericResponse::from(
                merge_readiness,
            )))
        });

    let get_events = eth_v1
        .and(warp::path("events"))
        .and(warp::path::end())
        .and(multi_key_query::<api_types::EventQuery>())
        .and(chain_filter)
        .and_then(
            |topics_res: Result<api_types::EventQuery, warp::Rejection>,
             chain: Arc<BeaconChain<T>>| {
                blocking_task(move || {
                    let topics = topics_res?;
                    // for each topic subscribed spawn a new subscription
                    let mut receivers = Vec::with_capacity(topics.topics.len());

                    if let Some(event_handler) = chain.event_handler.as_ref() {
                        for topic in topics.topics {
                            let receiver = match topic {
                                api_types::EventTopic::Head => event_handler.subscribe_head(),
                                api_types::EventTopic::Block => event_handler.subscribe_block(),
                                api_types::EventTopic::Attestation => {
                                    event_handler.subscribe_attestation()
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
                                api_types::EventTopic::LateHead => {
                                    event_handler.subscribe_late_head()
                                }
                                api_types::EventTopic::BlockReward => {
                                    event_handler.subscribe_block_reward()
                                }
                            };

                            receivers.push(BroadcastStream::new(receiver).map(|msg| {
                                match msg {
                                    Ok(data) => Event::default()
                                        .event(data.topic_name())
                                        .json_data(data)
                                        .map_err(|e| {
                                            warp_utils::reject::server_sent_event_error(format!(
                                                "{:?}",
                                                e
                                            ))
                                        }),
                                    Err(e) => Err(warp_utils::reject::server_sent_event_error(
                                        format!("{:?}", e),
                                    )),
                                }
                            }));
                        }
                    } else {
                        return Err(warp_utils::reject::custom_server_error(
                            "event handler was not initialized".to_string(),
                        ));
                    }

                    let s = futures::stream::select_all(receivers);

                    Ok::<_, warp::Rejection>(warp::sse::reply(warp::sse::keep_alive().stream(s)))
                })
            },
        );

    // Define the ultimate set of routes that will be provided to the server.
    let routes = warp::get()
        .and(
            get_beacon_genesis
                .boxed()
                .or(get_beacon_state_root.boxed())
                .or(get_beacon_state_fork.boxed())
                .or(get_beacon_state_finality_checkpoints.boxed())
                .or(get_beacon_state_validator_balances.boxed())
                .or(get_beacon_state_validators_id.boxed())
                .or(get_beacon_state_validators.boxed())
                .or(get_beacon_state_committees.boxed())
                .or(get_beacon_state_sync_committees.boxed())
                .or(get_beacon_state_randao.boxed())
                .or(get_beacon_headers.boxed())
                .or(get_beacon_headers_block_id.boxed())
                .or(get_beacon_block.boxed())
                .or(get_beacon_block_attestations.boxed())
                .or(get_beacon_blinded_block.boxed())
                .or(get_beacon_block_root.boxed())
                .or(get_beacon_pool_attestations.boxed())
                .or(get_beacon_pool_attester_slashings.boxed())
                .or(get_beacon_pool_proposer_slashings.boxed())
                .or(get_beacon_pool_voluntary_exits.boxed())
                .or(get_beacon_pool_bls_to_execution_changes.boxed())
                .or(get_beacon_deposit_snapshot.boxed())
                .or(get_config_fork_schedule.boxed())
                .or(get_config_spec.boxed())
                .or(get_config_deposit_contract.boxed())
                .or(get_debug_beacon_states.boxed())
                .or(get_debug_beacon_heads.boxed())
                .or(get_node_identity.boxed())
                .or(get_node_version.boxed())
                .or(get_node_syncing.boxed())
                .or(get_node_health.boxed())
                .or(get_node_peers_by_id.boxed())
                .or(get_node_peers.boxed())
                .or(get_node_peer_count.boxed())
                .or(get_validator_duties_proposer.boxed())
                .or(get_validator_blocks.boxed())
                .or(get_validator_blinded_blocks.boxed())
                .or(get_validator_attestation_data.boxed())
                .or(get_validator_aggregate_attestation.boxed())
                .or(get_validator_sync_committee_contribution.boxed())
                .or(get_lighthouse_health.boxed())
                .or(get_lighthouse_ui_health.boxed())
                .or(get_lighthouse_syncing.boxed())
                .or(get_lighthouse_nat.boxed())
                .or(get_lighthouse_peers.boxed())
                .or(get_lighthouse_peers_connected.boxed())
                .or(get_lighthouse_proto_array.boxed())
                .or(get_lighthouse_validator_inclusion_global.boxed())
                .or(get_lighthouse_validator_inclusion.boxed())
                .or(get_lighthouse_eth1_syncing.boxed())
                .or(get_lighthouse_eth1_block_cache.boxed())
                .or(get_lighthouse_eth1_deposit_cache.boxed())
                .or(get_lighthouse_beacon_states_ssz.boxed())
                .or(get_lighthouse_staking.boxed())
                .or(get_lighthouse_database_info.boxed())
                .or(get_lighthouse_block_rewards.boxed())
                .or(get_lighthouse_attestation_performance.boxed())
                .or(get_lighthouse_block_packing_efficiency.boxed())
                .or(get_lighthouse_merge_readiness.boxed())
                .or(get_lighthouse_ui_validator_count.boxed())
                .or(get_events.boxed()),
        )
        .boxed()
        .or(warp::post().and(
            post_beacon_blocks
                .boxed()
                .or(post_beacon_blinded_blocks.boxed())
                .or(post_beacon_pool_attestations.boxed())
                .or(post_beacon_pool_attester_slashings.boxed())
                .or(post_beacon_pool_proposer_slashings.boxed())
                .or(post_beacon_pool_voluntary_exits.boxed())
                .or(post_beacon_pool_sync_committees.boxed())
                .or(post_beacon_pool_bls_to_execution_changes.boxed())
                .or(post_validator_duties_attester.boxed())
                .or(post_validator_duties_sync.boxed())
                .or(post_validator_aggregate_and_proofs.boxed())
                .or(post_validator_contribution_and_proofs.boxed())
                .or(post_validator_beacon_committee_subscriptions.boxed())
                .or(post_validator_sync_committee_subscriptions.boxed())
                .or(post_validator_prepare_beacon_proposer.boxed())
                .or(post_validator_register_validator.boxed())
                .or(post_lighthouse_liveness.boxed())
                .or(post_lighthouse_database_reconstruct.boxed())
                .or(post_lighthouse_database_historical_blocks.boxed())
                .or(post_lighthouse_block_rewards.boxed()),
        ))
        .recover(warp_utils::reject::handle_rejection)
        .with(slog_logging(log.clone()))
        .with(prometheus_metrics())
        // Add a `Server` header.
        .map(|reply| warp::reply::with_header(reply, "Server", &version_with_platform()))
        .with(cors_builder.build());

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

            info!(log, "HTTP API is being served over TLS";);

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
        log,
        "HTTP API started";
        "listen_address" => %http_server.0,
    );

    Ok(http_server)
}

/// Publish a message to the libp2p pubsub network.
fn publish_pubsub_message<T: EthSpec>(
    network_tx: &UnboundedSender<NetworkMessage<T>>,
    message: PubsubMessage<T>,
) -> Result<(), warp::Rejection> {
    publish_network_message(
        network_tx,
        NetworkMessage::Publish {
            messages: vec![message],
        },
    )
}

/// Publish a message to the libp2p network.
fn publish_network_message<T: EthSpec>(
    network_tx: &UnboundedSender<NetworkMessage<T>>,
    message: NetworkMessage<T>,
) -> Result<(), warp::Rejection> {
    network_tx.send(message).map_err(|e| {
        warp_utils::reject::custom_server_error(format!(
            "unable to publish to network channel: {}",
            e
        ))
    })
}
