//! This crate contains a HTTP server which serves the endpoints listed here:
//!
//! https://github.com/ethereum/eth2.0-APIs
//!
//! There are also some additional, non-standard endpoints behind the `/lighthouse/` path which are
//! used for development.

mod attester_duties;
mod block_id;
mod metrics;
mod proposer_duties;
mod state_id;
mod validator_inclusion;

use beacon_chain::{
    attestation_verification::SignatureVerifiedAttestation,
    observed_operations::ObservationOutcome,
    validator_monitor::{get_block_delay_ms, timestamp_now},
    AttestationError as AttnError, BeaconChain, BeaconChainError, BeaconChainTypes,
    WhenSlotSkipped,
};
use block_id::BlockId;
use eth2::types::{self as api_types, ValidatorId};
use eth2_libp2p::{types::SyncState, EnrExt, NetworkGlobals, PeerId, PubsubMessage};
use lighthouse_version::version_with_platform;
use network::NetworkMessage;
use serde::{Deserialize, Serialize};
use slog::{crit, debug, error, info, warn, Logger};
use slot_clock::SlotClock;
use ssz::Encode;
use state_id::StateId;
use std::borrow::Cow;
use std::convert::TryInto;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use types::{
    Attestation, AttesterSlashing, CommitteeCache, Epoch, EthSpec, ProposerSlashing, RelativeEpoch,
    SignedAggregateAndProof, SignedBeaconBlock, SignedVoluntaryExit, Slot, YamlConfig,
};
use warp::http::StatusCode;
use warp::sse::Event;
use warp::Reply;
use warp::{http::Response, Filter};
use warp_utils::task::{blocking_json_task, blocking_task};

const API_PREFIX: &str = "eth";
const API_VERSION: &str = "v1";

/// If the node is within this many epochs from the head, we declare it to be synced regardless of
/// the network sync state.
///
/// This helps prevent attacks where nodes can convince us that we're syncing some non-existent
/// finalized head.
const SYNC_TOLERANCE_EPOCHS: u64 = 8;

/// A wrapper around all the items required to spawn the HTTP server.
///
/// The server will gracefully handle the case where any fields are `None`.
pub struct Context<T: BeaconChainTypes> {
    pub config: Config,
    pub chain: Option<Arc<BeaconChain<T>>>,
    pub network_tx: Option<UnboundedSender<NetworkMessage<T::EthSpec>>>,
    pub network_globals: Option<Arc<NetworkGlobals<T::EthSpec>>>,
    pub eth1_service: Option<eth1::Service>,
    pub log: Logger,
}

/// Configuration for the HTTP server.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub enabled: bool,
    pub listen_addr: Ipv4Addr,
    pub listen_port: u16,
    pub allow_origin: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: Ipv4Addr::new(127, 0, 0, 1),
            listen_port: 5052,
            allow_origin: None,
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
                if info.path() == format!("/{}/{}/{}", API_PREFIX, API_VERSION, s) {
                    Some(s)
                } else {
                    None
                }
            };

            let starts_with = |s: &'static str| -> Option<&'static str> {
                if info
                    .path()
                    .starts_with(&format!("/{}/{}/{}", API_PREFIX, API_VERSION, s))
                {
                    Some(s)
                } else {
                    None
                }
            };

            equals("beacon/blocks")
                .or_else(|| starts_with("validator/duties/attester"))
                .or_else(|| starts_with("validator/duties/proposer"))
                .or_else(|| starts_with("validator/attestation_data"))
                .or_else(|| starts_with("validator/blocks"))
                .or_else(|| starts_with("validator/aggregate_attestation"))
                .or_else(|| starts_with("validator/aggregate_and_proofs"))
                .or_else(|| starts_with("validator/beacon_committee_subscriptions"))
                .or_else(|| starts_with("beacon/"))
                .or_else(|| starts_with("config/"))
                .or_else(|| starts_with("debug/"))
                .or_else(|| starts_with("events/"))
                .or_else(|| starts_with("node/"))
                .or_else(|| starts_with("validator/"))
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
) -> Result<(SocketAddr, impl Future<Output = ()>), Error> {
    let config = ctx.config.clone();
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

    let eth1_v1 = warp::path(API_PREFIX).and(warp::path(API_VERSION));

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
    let inner_ctx = ctx.clone();
    let network_tx_filter = warp::any()
        .map(move || inner_ctx.network_tx.clone())
        .and_then(|network_tx| async move {
            match network_tx {
                Some(network_tx) => Ok(network_tx),
                None => Err(warp_utils::reject::custom_not_found(
                    "The networking stack has not yet started.".to_string(),
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

    // Create a `warp` filter that rejects request whilst the node is syncing.
    let not_while_syncing_filter = warp::any()
        .and(network_globals.clone())
        .and(chain_filter.clone())
        .and_then(
            |network_globals: Arc<NetworkGlobals<T::EthSpec>>, chain: Arc<BeaconChain<T>>| async move {
                match *network_globals.sync_state.read() {
                    SyncState::SyncingFinalized { .. } => {
                        let head_slot = chain.best_slot().map_err(warp_utils::reject::beacon_chain_error)?;

                        let current_slot = chain
                            .slot_clock
                            .now_or_genesis()
                            .ok_or_else(|| {
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
                    SyncState::SyncingHead { .. } | SyncState::SyncTransition => Ok(()),
                    SyncState::Synced => Ok(()),
                    SyncState::Stalled => Err(warp_utils::reject::not_synced(
                        "sync is stalled".to_string(),
                    )),
                }
            },
        )
        .untuple_one();

    // Create a `warp` filter that provides access to the logger.
    let log_filter = warp::any().map(move || ctx.log.clone());

    /*
     *
     * Start of HTTP method definitions.
     *
     */

    // GET beacon/genesis
    let get_beacon_genesis = eth1_v1
        .and(warp::path("beacon"))
        .and(warp::path("genesis"))
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(|chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                chain
                    .head_info()
                    .map_err(warp_utils::reject::beacon_chain_error)
                    .map(|head| api_types::GenesisData {
                        genesis_time: head.genesis_time,
                        genesis_validators_root: head.genesis_validators_root,
                        genesis_fork_version: chain.spec.genesis_fork_version,
                    })
                    .map(api_types::GenericResponse::from)
            })
        });

    /*
     * beacon/states/{state_id}
     */

    let beacon_states_path = eth1_v1
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
                state_id
                    .root(&chain)
                    .map(api_types::RootData::from)
                    .map(api_types::GenericResponse::from)
            })
        });

    // GET beacon/states/{state_id}/fork
    let get_beacon_state_fork = beacon_states_path
        .clone()
        .and(warp::path("fork"))
        .and(warp::path::end())
        .and_then(|state_id: StateId, chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || state_id.fork(&chain).map(api_types::GenericResponse::from))
        });

    // GET beacon/states/{state_id}/finality_checkpoints
    let get_beacon_state_finality_checkpoints = beacon_states_path
        .clone()
        .and(warp::path("finality_checkpoints"))
        .and(warp::path::end())
        .and_then(|state_id: StateId, chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                state_id
                    .map_state(&chain, |state| {
                        Ok(api_types::FinalityCheckpointsData {
                            previous_justified: state.previous_justified_checkpoint,
                            current_justified: state.current_justified_checkpoint,
                            finalized: state.finalized_checkpoint,
                        })
                    })
                    .map(api_types::GenericResponse::from)
            })
        });

    // GET beacon/states/{state_id}/validator_balances?id
    let get_beacon_state_validator_balances = beacon_states_path
        .clone()
        .and(warp::path("validator_balances"))
        .and(warp::path::end())
        .and(warp::query::<api_types::ValidatorBalancesQuery>())
        .and_then(
            |state_id: StateId,
             chain: Arc<BeaconChain<T>>,
             query: api_types::ValidatorBalancesQuery| {
                blocking_json_task(move || {
                    state_id
                        .map_state(&chain, |state| {
                            Ok(state
                                .validators
                                .iter()
                                .zip(state.balances.iter())
                                .enumerate()
                                // filter by validator id(s) if provided
                                .filter(|(index, (validator, _))| {
                                    query.id.as_ref().map_or(true, |ids| {
                                        ids.0.iter().any(|id| match id {
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
                                .collect::<Vec<_>>())
                        })
                        .map(api_types::GenericResponse::from)
                })
            },
        );

    // GET beacon/states/{state_id}/validators?id,status
    let get_beacon_state_validators = beacon_states_path
        .clone()
        .and(warp::path("validators"))
        .and(warp::query::<api_types::ValidatorsQuery>())
        .and(warp::path::end())
        .and_then(
            |state_id: StateId, chain: Arc<BeaconChain<T>>, query: api_types::ValidatorsQuery| {
                blocking_json_task(move || {
                    state_id
                        .map_state(&chain, |state| {
                            let epoch = state.current_epoch();
                            let far_future_epoch = chain.spec.far_future_epoch;

                            Ok(state
                                .validators
                                .iter()
                                .zip(state.balances.iter())
                                .enumerate()
                                // filter by validator id(s) if provided
                                .filter(|(index, (validator, _))| {
                                    query.id.as_ref().map_or(true, |ids| {
                                        ids.0.iter().any(|id| match id {
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
                                            statuses.0.contains(&status)
                                                || statuses.0.contains(&status.superstatus())
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
                                .collect::<Vec<_>>())
                        })
                        .map(api_types::GenericResponse::from)
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
                    state_id
                        .map_state(&chain, |state| {
                            let index_opt = match &validator_id {
                                ValidatorId::PublicKey(pubkey) => {
                                    state.validators.iter().position(|v| v.pubkey == *pubkey)
                                }
                                ValidatorId::Index(index) => Some(*index as usize),
                            };

                            index_opt
                                .and_then(|index| {
                                    let validator = state.validators.get(index)?;
                                    let balance = *state.balances.get(index)?;
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
                                })
                        })
                        .map(api_types::GenericResponse::from)
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
                // the api spec says if the epoch is not present then the epoch of the state should be used
                let query_state_id = query.epoch.map_or(state_id, |epoch| {
                    StateId::slot(epoch.start_slot(T::EthSpec::slots_per_epoch()))
                });

                blocking_json_task(move || {
                    query_state_id.map_state(&chain, |state| {
                        let epoch = state.slot.epoch(T::EthSpec::slots_per_epoch());

                        let committee_cache = if state
                            .committee_cache_is_initialized(RelativeEpoch::Current)
                        {
                            state
                                .committee_cache(RelativeEpoch::Current)
                                .map(Cow::Borrowed)
                        } else {
                            CommitteeCache::initialized(state, epoch, &chain.spec).map(Cow::Owned)
                        }
                        .map_err(BeaconChainError::BeaconStateError)
                        .map_err(warp_utils::reject::beacon_chain_error)?;

                        // Use either the supplied slot or all slots in the epoch.
                        let slots = query.slot.map(|slot| vec![slot]).unwrap_or_else(|| {
                            epoch.slot_iter(T::EthSpec::slots_per_epoch()).collect()
                        });

                        // Use either the supplied committee index or all available indices.
                        let indices = query.index.map(|index| vec![index]).unwrap_or_else(|| {
                            (0..committee_cache.committees_per_slot()).collect()
                        });

                        let mut response = Vec::with_capacity(slots.len() * indices.len());

                        for slot in slots {
                            // It is not acceptable to query with a slot that is not within the
                            // specified epoch.
                            if slot.epoch(T::EthSpec::slots_per_epoch()) != epoch {
                                return Err(warp_utils::reject::custom_bad_request(format!(
                                    "{} is not in epoch {}",
                                    slot, epoch
                                )));
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

                        Ok(api_types::GenericResponse::from(response))
                    })
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
    let get_beacon_headers = eth1_v1
        .and(warp::path("beacon"))
        .and(warp::path("headers"))
        .and(warp::query::<api_types::HeadersQuery>())
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(
            |query: api_types::HeadersQuery, chain: Arc<BeaconChain<T>>| {
                blocking_json_task(move || {
                    let (root, block) = match (query.slot, query.parent_root) {
                        // No query parameters, return the canonical head block.
                        (None, None) => chain
                            .head_beacon_block()
                            .map_err(warp_utils::reject::beacon_chain_error)
                            .map(|block| (block.canonical_root(), block))?,
                        // Only the parent root parameter, do a forwards-iterator lookup.
                        (None, Some(parent_root)) => {
                            let parent = BlockId::from_root(parent_root).block(&chain)?;
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
                                .block(&chain)
                                .map(|block| (root, block))?
                        }
                        // Slot is supplied, search by slot and optionally filter by
                        // parent root.
                        (Some(slot), parent_root_opt) => {
                            let root = BlockId::from_slot(slot).root(&chain)?;
                            let block = BlockId::from_root(root).block(&chain)?;

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

                            (root, block)
                        }
                    };

                    let data = api_types::BlockHeaderData {
                        root,
                        canonical: true,
                        header: api_types::BlockHeaderAndSignature {
                            message: block.message.block_header(),
                            signature: block.signature.into(),
                        },
                    };

                    Ok(api_types::GenericResponse::from(vec![data]))
                })
            },
        );

    // GET beacon/headers/{block_id}
    let get_beacon_headers_block_id = eth1_v1
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
                let root = block_id.root(&chain)?;
                let block = BlockId::from_root(root).block(&chain)?;

                let canonical = chain
                    .block_root_at_slot(block.slot(), WhenSlotSkipped::None)
                    .map_err(warp_utils::reject::beacon_chain_error)?
                    .map_or(false, |canonical| root == canonical);

                let data = api_types::BlockHeaderData {
                    root,
                    canonical,
                    header: api_types::BlockHeaderAndSignature {
                        message: block.message.block_header(),
                        signature: block.signature.into(),
                    },
                };

                Ok(api_types::GenericResponse::from(data))
            })
        });

    /*
     * beacon/blocks
     */

    // POST beacon/blocks
    let post_beacon_blocks = eth1_v1
        .and(warp::path("beacon"))
        .and(warp::path("blocks"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(chain_filter.clone())
        .and(network_tx_filter.clone())
        .and(log_filter.clone())
        .and_then(
            |block: SignedBeaconBlock<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
             log: Logger| {
                blocking_json_task(move || {
                    let seen_timestamp = timestamp_now();

                    // Send the block, regardless of whether or not it is valid. The API
                    // specification is very clear that this is the desired behaviour.
                    publish_pubsub_message(
                        &network_tx,
                        PubsubMessage::BeaconBlock(Box::new(block.clone())),
                    )?;

                    // Determine the delay after the start of the slot, register it with metrics.
                    let delay =
                        get_block_delay_ms(seen_timestamp, &block.message, &chain.slot_clock);
                    metrics::observe_duration(
                        &metrics::HTTP_API_BLOCK_BROADCAST_DELAY_TIMES,
                        delay,
                    );


                    match chain.process_block(block.clone()) {
                        Ok(root) => {
                            info!(
                                log,
                                "Valid block from HTTP API";
                                "root" => format!("{}", root)
                            );

                            // Notify the validator monitor.
                            chain.validator_monitor.read().register_api_block(
                                seen_timestamp,
                                &block.message,
                                root,
                                &chain.slot_clock,
                            );

                            // Update the head since it's likely this block will become the new
                            // head.
                            chain
                                .fork_choice()
                                .map_err(warp_utils::reject::beacon_chain_error)?;

                            // Perform some logging to inform users if their blocks are being produced
                            // late.
                            //
                            // Check to see the thresholds are non-zero to avoid logging errors with small
                            // slot times (e.g., during testing)
                            let crit_threshold = chain.spec.seconds_per_slot / 3;
                            let warn_threshold = chain.spec.seconds_per_slot / 6;
                            if crit_threshold > 0 && delay.as_secs() > crit_threshold {
                                crit!(
                                    log,
                                    "Block was broadcast too late";
                                    "root" => ?root,
                                    "slot" => block.slot(),
                                    "delay_ms" => delay.as_millis(),
                                    "msg" => "system may be overloaded, block likely to be orphaned",
                                )
                            } else if warn_threshold > 0 && delay.as_secs() > warn_threshold {
                                warn!(
                                    log,
                                    "Block broadcast was delayed";
                                    "root" => ?root,
                                    "slot" => block.slot(),
                                    "delay_ms" => delay.as_millis(),
                                    "msg" => "system may be overloaded, block may be orphaned",
                                )
                            }

                            Ok(())
                        }
                        Err(e) => {
                            let msg = format!("{:?}", e);
                            error!(
                                log,
                                "Invalid block provided to HTTP API";
                                "reason" => &msg
                            );
                            Err(warp_utils::reject::broadcast_without_import(msg))
                        }
                    }
                })
            },
        );

    let beacon_blocks_path = eth1_v1
        .and(warp::path("beacon"))
        .and(warp::path("blocks"))
        .and(warp::path::param::<BlockId>().or_else(|_| async {
            Err(warp_utils::reject::custom_bad_request(
                "Invalid block ID".to_string(),
            ))
        }))
        .and(chain_filter.clone());

    // GET beacon/blocks/{block_id}
    let get_beacon_block = beacon_blocks_path
        .clone()
        .and(warp::path::end())
        .and(warp::header::optional::<api_types::Accept>("accept"))
        .and_then(
            |block_id: BlockId,
             chain: Arc<BeaconChain<T>>,
             accept_header: Option<api_types::Accept>| {
                blocking_task(move || {
                    let block = block_id.block(&chain)?;
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
                        _ => Ok(
                            warp::reply::json(&api_types::GenericResponseRef::from(&block))
                                .into_response(),
                        ),
                    }
                })
            },
        );

    // GET beacon/blocks/{block_id}/root
    let get_beacon_block_root = beacon_blocks_path
        .clone()
        .and(warp::path("root"))
        .and(warp::path::end())
        .and_then(|block_id: BlockId, chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                block_id
                    .root(&chain)
                    .map(api_types::RootData::from)
                    .map(api_types::GenericResponse::from)
            })
        });

    // GET beacon/blocks/{block_id}/attestations
    let get_beacon_block_attestations = beacon_blocks_path
        .clone()
        .and(warp::path("attestations"))
        .and(warp::path::end())
        .and_then(|block_id: BlockId, chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                block_id
                    .block(&chain)
                    .map(|block| block.message.body.attestations)
                    .map(api_types::GenericResponse::from)
            })
        });

    /*
     * beacon/pool
     */

    let beacon_pool_path = eth1_v1
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

                    for (index, attestation) in attestations.as_slice().iter().enumerate() {
                        let attestation = match chain
                            .verify_unaggregated_attestation_for_gossip(attestation.clone(), None)
                        {
                            Ok(attestation) => attestation,
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

                        if let Err(e) = chain.add_to_naive_aggregation_pool(attestation) {
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
                    let query_filter = |attestation: &Attestation<T::EthSpec>| {
                        query
                            .slot
                            .map_or(true, |slot| slot == attestation.data.slot)
                            && query
                                .committee_index
                                .map_or(true, |index| index == attestation.data.index)
                    };

                    let mut attestations = chain.op_pool.get_filtered_attestations(query_filter);
                    attestations.extend(
                        chain
                            .naive_aggregation_pool
                            .read()
                            .iter()
                            .cloned()
                            .filter(query_filter),
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

                        chain
                            .import_attester_slashing(slashing)
                            .map_err(warp_utils::reject::beacon_chain_error)?;
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

    /*
     * config/fork_schedule
     */

    let config_path = eth1_v1.and(warp::path("config"));

    // GET config/fork_schedule
    let get_config_fork_schedule = config_path
        .clone()
        .and(warp::path("fork_schedule"))
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(|chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                StateId::head()
                    .fork(&chain)
                    .map(|fork| api_types::GenericResponse::from(vec![fork]))
            })
        });

    // GET config/spec
    let get_config_spec = config_path
        .clone()
        .and(warp::path("spec"))
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(|chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                Ok(api_types::GenericResponse::from(YamlConfig::from_spec::<
                    T::EthSpec,
                >(
                    &chain.spec
                )))
            })
        });

    // GET config/deposit_contract
    let get_config_deposit_contract = config_path
        .clone()
        .and(warp::path("deposit_contract"))
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(|chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                Ok(api_types::GenericResponse::from(
                    api_types::DepositContractData {
                        address: chain.spec.deposit_contract_address,
                        chain_id: eth1::DEFAULT_NETWORK_ID.into(),
                    },
                ))
            })
        });

    /*
     * debug
     */

    // GET debug/beacon/states/{state_id}
    let get_debug_beacon_states = eth1_v1
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
            |state_id: StateId,
             accept_header: Option<api_types::Accept>,
             chain: Arc<BeaconChain<T>>| {
                blocking_task(move || match accept_header {
                    Some(api_types::Accept::Ssz) => {
                        let state = state_id.state(&chain)?;
                        Response::builder()
                            .status(200)
                            .header("Content-Type", "application/octet-stream")
                            .body(state.as_ssz_bytes().into())
                            .map_err(|e| {
                                warp_utils::reject::custom_server_error(format!(
                                    "failed to create response: {}",
                                    e
                                ))
                            })
                    }
                    _ => state_id.map_state(&chain, |state| {
                        Ok(
                            warp::reply::json(&api_types::GenericResponseRef::from(&state))
                                .into_response(),
                        )
                    }),
                })
            },
        );

    // GET debug/beacon/heads
    let get_debug_beacon_heads = eth1_v1
        .and(warp::path("debug"))
        .and(warp::path("beacon"))
        .and(warp::path("heads"))
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(|chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                let heads = chain
                    .heads()
                    .into_iter()
                    .map(|(root, slot)| api_types::ChainHeadData { slot, root })
                    .collect::<Vec<_>>();
                Ok(api_types::GenericResponse::from(heads))
            })
        });

    /*
     * node
     */

    // GET node/identity
    let get_node_identity = eth1_v1
        .and(warp::path("node"))
        .and(warp::path("identity"))
        .and(warp::path::end())
        .and(network_globals.clone())
        .and_then(|network_globals: Arc<NetworkGlobals<T::EthSpec>>| {
            blocking_json_task(move || {
                let enr = network_globals.local_enr();
                let p2p_addresses = enr.multiaddr_p2p_tcp();
                let discovery_addresses = enr.multiaddr_p2p_udp();
                Ok(api_types::GenericResponse::from(api_types::IdentityData {
                    peer_id: network_globals.local_peer_id().to_base58(),
                    enr,
                    p2p_addresses,
                    discovery_addresses,
                    metadata: api_types::MetaData {
                        seq_number: network_globals.local_metadata.read().seq_number,
                        attnets: format!(
                            "0x{}",
                            hex::encode(
                                network_globals
                                    .local_metadata
                                    .read()
                                    .attnets
                                    .clone()
                                    .into_bytes()
                            ),
                        ),
                    },
                }))
            })
        });

    // GET node/version
    let get_node_version = eth1_v1
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
    let get_node_syncing = eth1_v1
        .and(warp::path("node"))
        .and(warp::path("syncing"))
        .and(warp::path::end())
        .and(network_globals.clone())
        .and(chain_filter.clone())
        .and_then(
            |network_globals: Arc<NetworkGlobals<T::EthSpec>>, chain: Arc<BeaconChain<T>>| {
                blocking_json_task(move || {
                    let head_slot = chain
                        .head_info()
                        .map(|info| info.slot)
                        .map_err(warp_utils::reject::beacon_chain_error)?;
                    let current_slot = chain
                        .slot()
                        .map_err(warp_utils::reject::beacon_chain_error)?;

                    // Taking advantage of saturating subtraction on slot.
                    let sync_distance = current_slot - head_slot;

                    let syncing_data = api_types::SyncingData {
                        is_syncing: network_globals.sync_state.read().is_syncing(),
                        head_slot,
                        sync_distance,
                    };

                    Ok(api_types::GenericResponse::from(syncing_data))
                })
            },
        );

    // GET node/health
    let get_node_health = eth1_v1
        .and(warp::path("node"))
        .and(warp::path("health"))
        .and(warp::path::end())
        .and(network_globals.clone())
        .and_then(|network_globals: Arc<NetworkGlobals<T::EthSpec>>| {
            blocking_task(move || match *network_globals.sync_state.read() {
                SyncState::SyncingFinalized { .. }
                | SyncState::SyncingHead { .. }
                | SyncState::SyncTransition => Ok(warp::reply::with_status(
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
    let get_node_peers_by_id = eth1_v1
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
                        let address = if let Some(socket_addr) =
                            peer_info.seen_addresses.iter().next()
                        {
                            let mut addr = eth2_libp2p::Multiaddr::from(socket_addr.ip());
                            addr.push(eth2_libp2p::multiaddr::Protocol::Tcp(socket_addr.port()));
                            addr.to_string()
                        } else if let Some(addr) = peer_info.listening_addresses.first() {
                            addr.to_string()
                        } else {
                            String::new()
                        };

                        // the eth2 API spec implies only peers we have been connected to at some point should be included.
                        if let Some(dir) = peer_info.connection_direction.as_ref() {
                            return Ok(api_types::GenericResponse::from(api_types::PeerData {
                                peer_id: peer_id.to_string(),
                                enr: peer_info.enr.as_ref().map(|enr| enr.to_base64()),
                                last_seen_p2p_address: address,
                                direction: api_types::PeerDirection::from_connection_direction(
                                    &dir,
                                ),
                                state: api_types::PeerState::from_peer_connection_status(
                                    &peer_info.connection_status(),
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
    let get_node_peers = eth1_v1
        .and(warp::path("node"))
        .and(warp::path("peers"))
        .and(warp::path::end())
        .and(warp::query::<api_types::PeersQuery>())
        .and(network_globals.clone())
        .and_then(
            |query: api_types::PeersQuery, network_globals: Arc<NetworkGlobals<T::EthSpec>>| {
                blocking_json_task(move || {
                    let mut peers: Vec<api_types::PeerData> = Vec::new();
                    network_globals
                        .peers
                        .read()
                        .peers()
                        .for_each(|(peer_id, peer_info)| {
                            let address =
                                if let Some(socket_addr) = peer_info.seen_addresses.iter().next() {
                                    let mut addr = eth2_libp2p::Multiaddr::from(socket_addr.ip());
                                    addr.push(eth2_libp2p::multiaddr::Protocol::Tcp(
                                        socket_addr.port(),
                                    ));
                                    addr.to_string()
                                } else if let Some(addr) = peer_info.listening_addresses.first() {
                                    addr.to_string()
                                } else {
                                    String::new()
                                };

                            // the eth2 API spec implies only peers we have been connected to at some point should be included.
                            if let Some(dir) = peer_info.connection_direction.as_ref() {
                                let direction =
                                    api_types::PeerDirection::from_connection_direction(&dir);
                                let state = api_types::PeerState::from_peer_connection_status(
                                    &peer_info.connection_status(),
                                );

                                let state_matches = query.state.as_ref().map_or(true, |states| {
                                    states.0.iter().any(|state_param| *state_param == state)
                                });
                                let direction_matches =
                                    query.direction.as_ref().map_or(true, |directions| {
                                        directions.0.iter().any(|dir_param| *dir_param == direction)
                                    });

                                if state_matches && direction_matches {
                                    peers.push(api_types::PeerData {
                                        peer_id: peer_id.to_string(),
                                        enr: peer_info.enr.as_ref().map(|enr| enr.to_base64()),
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
    let get_node_peer_count = eth1_v1
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
                            &peer_info.connection_status(),
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
    let get_validator_duties_proposer = eth1_v1
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
    let get_validator_blocks = eth1_v1
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
            |slot: Slot, query: api_types::ValidatorBlocksQuery, chain: Arc<BeaconChain<T>>| {
                blocking_json_task(move || {
                    let randao_reveal = (&query.randao_reveal).try_into().map_err(|e| {
                        warp_utils::reject::custom_bad_request(format!(
                            "randao reveal is not valid BLS signature: {:?}",
                            e
                        ))
                    })?;

                    chain
                        .produce_block(randao_reveal, slot, query.graffiti.map(Into::into))
                        .map(|block_and_state| block_and_state.0)
                        .map(api_types::GenericResponse::from)
                        .map_err(warp_utils::reject::block_production_error)
                })
            },
        );

    // GET validator/attestation_data?slot,committee_index
    let get_validator_attestation_data = eth1_v1
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
    let get_validator_aggregate_attestation = eth1_v1
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
    let post_validator_duties_attester = eth1_v1
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

    // POST validator/aggregate_and_proofs
    let post_validator_aggregate_and_proofs = eth1_v1
        .and(warp::path("validator"))
        .and(warp::path("aggregate_and_proofs"))
        .and(warp::path::end())
        .and(not_while_syncing_filter)
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
                    for (index, aggregate) in aggregates.as_slice().iter().enumerate() {
                        match chain.verify_aggregated_attestation_for_gossip(aggregate.clone()) {
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
                            warn!(log,
                                    "Could not add verified aggregate attestation to the inclusion pool";
                                    "error" => format!("{:?}", e),
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

    // POST validator/beacon_committee_subscriptions
    let post_validator_beacon_committee_subscriptions = eth1_v1
        .and(warp::path("validator"))
        .and(warp::path("beacon_committee_subscriptions"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(network_tx_filter)
        .and(chain_filter.clone())
        .and_then(
            |subscriptions: Vec<api_types::BeaconCommitteeSubscription>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
             chain: Arc<BeaconChain<T>>| {
                blocking_json_task(move || {
                    for subscription in &subscriptions {
                        chain
                            .validator_monitor
                            .write()
                            .auto_register_local_validator(subscription.validator_index);

                        let subscription = api_types::ValidatorSubscription {
                            validator_index: subscription.validator_index,
                            attestation_committee_index: subscription.committee_index,
                            slot: subscription.slot,
                            committee_count_at_slot: subscription.committees_at_slot,
                            is_aggregator: subscription.is_aggregator,
                        };

                        publish_network_message(
                            &network_tx,
                            NetworkMessage::Subscribe {
                                subscriptions: vec![subscription],
                            },
                        )?;
                    }

                    Ok(())
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
                    chain.fork_choice.read().proto_array().core_proto_array(),
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
                let head_info = chain
                    .head_info()
                    .map_err(warp_utils::reject::beacon_chain_error)?;
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
                        eth1.sync_status(head_info.genesis_time, current_slot_opt, &chain.spec)
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
                let state = state_id.state(&chain)?;
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

    let get_events = eth1_v1
        .and(warp::path("events"))
        .and(warp::path::end())
        .and(warp::query::<api_types::EventQuery>())
        .and(chain_filter)
        .and_then(
            |topics: api_types::EventQuery, chain: Arc<BeaconChain<T>>| {
                blocking_task(move || {
                    // for each topic subscribed spawn a new subscription
                    let mut receivers = Vec::with_capacity(topics.topics.0.len());

                    if let Some(event_handler) = chain.event_handler.as_ref() {
                        for topic in topics.topics.0.clone() {
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
                .or(get_beacon_state_validators.boxed())
                .or(get_beacon_state_validators_id.boxed())
                .or(get_beacon_state_committees.boxed())
                .or(get_beacon_headers.boxed())
                .or(get_beacon_headers_block_id.boxed())
                .or(get_beacon_block.boxed())
                .or(get_beacon_block_attestations.boxed())
                .or(get_beacon_block_root.boxed())
                .or(get_beacon_pool_attestations.boxed())
                .or(get_beacon_pool_attester_slashings.boxed())
                .or(get_beacon_pool_proposer_slashings.boxed())
                .or(get_beacon_pool_voluntary_exits.boxed())
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
                .or(get_validator_attestation_data.boxed())
                .or(get_validator_aggregate_attestation.boxed())
                .or(get_lighthouse_health.boxed())
                .or(get_lighthouse_syncing.boxed())
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
                .or(get_events.boxed()),
        )
        .or(warp::post().and(
            post_beacon_blocks
                .boxed()
                .or(post_beacon_pool_attestations.boxed())
                .or(post_beacon_pool_attester_slashings.boxed())
                .or(post_beacon_pool_proposer_slashings.boxed())
                .or(post_beacon_pool_voluntary_exits.boxed())
                .or(post_validator_duties_attester.boxed())
                .or(post_validator_aggregate_and_proofs.boxed())
                .or(post_validator_beacon_committee_subscriptions.boxed()),
        ))
        .recover(warp_utils::reject::handle_rejection)
        .with(slog_logging(log.clone()))
        .with(prometheus_metrics())
        // Add a `Server` header.
        .map(|reply| warp::reply::with_header(reply, "Server", &version_with_platform()))
        .with(cors_builder.build());

    let (listening_socket, server) = {
        warp::serve(routes).try_bind_with_graceful_shutdown(
            SocketAddrV4::new(config.listen_addr, config.listen_port),
            async {
                shutdown.await;
            },
        )?
    };

    info!(
        log,
        "HTTP API started";
        "listen_address" => listening_socket.to_string(),
    );

    Ok((listening_socket, server))
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
