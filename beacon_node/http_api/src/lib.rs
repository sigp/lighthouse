//! This crate contains a HTTP server which serves the endpoints listed here:
//!
//! https://github.com/ethereum/eth2.0-APIs
//!
//! There are also some additional, non-standard endpoints behind the `/lighthouse/` path which are
//! used for development.

mod beacon_proposer_cache;
mod block_id;
mod metrics;
mod state_id;
mod validator_inclusion;

use beacon_chain::{
    observed_operations::ObservationOutcome, AttestationError as AttnError, BeaconChain,
    BeaconChainError, BeaconChainTypes,
};
use beacon_proposer_cache::BeaconProposerCache;
use block_id::BlockId;
use eth2::{
    types::{self as api_types, ValidatorId},
    StatusCode,
};
use eth2_libp2p::{types::SyncState, EnrExt, NetworkGlobals, PeerId, PubsubMessage};
use lighthouse_version::version_with_platform;
use network::NetworkMessage;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use slog::{crit, error, info, trace, warn, Logger};
use slot_clock::SlotClock;
use state_id::StateId;
use state_processing::per_slot_processing;
use std::borrow::Cow;
use std::convert::TryInto;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use types::{
    Attestation, AttestationDuty, AttesterSlashing, CloneConfig, CommitteeCache, Epoch, EthSpec,
    Hash256, ProposerSlashing, PublicKey, RelativeEpoch, SignedAggregateAndProof,
    SignedBeaconBlock, SignedVoluntaryExit, Slot, YamlConfig,
};
use warp::Filter;
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
                trace!(
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

    // Instantiate the beacon proposer cache.
    let beacon_proposer_cache = ctx
        .chain
        .as_ref()
        .map(|chain| BeaconProposerCache::new(&chain))
        .transpose()
        .map_err(|e| format!("Unable to initialize beacon proposer cache: {:?}", e))?
        .map(Mutex::new)
        .map(Arc::new);

    // Create a `warp` filter that provides access to the proposer cache.
    let beacon_proposer_cache = || {
        warp::any()
            .map(move || beacon_proposer_cache.clone())
            .and_then(|beacon_proposer_cache| async move {
                match beacon_proposer_cache {
                    Some(cache) => Ok(cache),
                    None => Err(warp_utils::reject::custom_not_found(
                        "Beacon proposer cache is not initialized.".to_string(),
                    )),
                }
            })
    };

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
                    SyncState::SyncingHead { .. } => Ok(()),
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
        .and(warp::path::param::<StateId>())
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

    // GET beacon/states/{state_id}/validators
    let get_beacon_state_validators = beacon_states_path
        .clone()
        .and(warp::path("validators"))
        .and(warp::path::end())
        .and_then(|state_id: StateId, chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                state_id
                    .map_state(&chain, |state| {
                        let epoch = state.current_epoch();
                        let finalized_epoch = state.finalized_checkpoint.epoch;
                        let far_future_epoch = chain.spec.far_future_epoch;

                        Ok(state
                            .validators
                            .iter()
                            .zip(state.balances.iter())
                            .enumerate()
                            .map(|(index, (validator, balance))| api_types::ValidatorData {
                                index: index as u64,
                                balance: *balance,
                                status: api_types::ValidatorStatus::from_validator(
                                    Some(validator),
                                    epoch,
                                    finalized_epoch,
                                    far_future_epoch,
                                ),
                                validator: validator.clone(),
                            })
                            .collect::<Vec<_>>())
                    })
                    .map(api_types::GenericResponse::from)
            })
        });

    // GET beacon/states/{state_id}/validators/{validator_id}
    let get_beacon_state_validators_id = beacon_states_path
        .clone()
        .and(warp::path("validators"))
        .and(warp::path::param::<ValidatorId>())
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
                                    let finalized_epoch = state.finalized_checkpoint.epoch;
                                    let far_future_epoch = chain.spec.far_future_epoch;

                                    Some(api_types::ValidatorData {
                                        index: index as u64,
                                        balance,
                                        status: api_types::ValidatorStatus::from_validator(
                                            Some(validator),
                                            epoch,
                                            finalized_epoch,
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

    // GET beacon/states/{state_id}/committees/{epoch}
    let get_beacon_state_committees = beacon_states_path
        .clone()
        .and(warp::path("committees"))
        .and(warp::path::param::<Epoch>())
        .and(warp::query::<api_types::CommitteesQuery>())
        .and(warp::path::end())
        .and_then(
            |state_id: StateId,
             chain: Arc<BeaconChain<T>>,
             epoch: Epoch,
             query: api_types::CommitteesQuery| {
                blocking_json_task(move || {
                    state_id.map_state(&chain, |state| {
                        let relative_epoch =
                            RelativeEpoch::from_epoch(state.current_epoch(), epoch).map_err(
                                |_| {
                                    warp_utils::reject::custom_bad_request(format!(
                                        "state is epoch {} and only previous, current and next epochs are supported",
                                        state.current_epoch()
                                    ))
                                },
                            )?;

                        let committee_cache = if state
                            .committee_cache_is_initialized(relative_epoch)
                        {
                            state.committee_cache(relative_epoch).map(Cow::Borrowed)
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
        .and(warp::path::param::<BlockId>())
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(|block_id: BlockId, chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                let root = block_id.root(&chain)?;
                let block = BlockId::from_root(root).block(&chain)?;

                let canonical = chain
                    .block_root_at_slot(block.slot())
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

    // POST beacon/blocks/{block_id}
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
                    // Send the block, regardless of whether or not it is valid. The API
                    // specification is very clear that this is the desired behaviour.
                    publish_pubsub_message(
                        &network_tx,
                        PubsubMessage::BeaconBlock(Box::new(block.clone())),
                    )?;

                    match chain.process_block(block.clone()) {
                        Ok(root) => {
                            info!(
                                log,
                                "Valid block from HTTP API";
                                "root" => format!("{}", root)
                            );

                            // Update the head since it's likely this block will become the new
                            // head.
                            chain
                                .fork_choice()
                                .map_err(warp_utils::reject::beacon_chain_error)?;

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
        .and(warp::path::param::<BlockId>())
        .and(chain_filter.clone());

    // GET beacon/blocks/{block_id}
    let get_beacon_block = beacon_blocks_path.clone().and(warp::path::end()).and_then(
        |block_id: BlockId, chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || block_id.block(&chain).map(api_types::GenericResponse::from))
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
        .and_then(
            |chain: Arc<BeaconChain<T>>,
             attestation: Attestation<T::EthSpec>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                blocking_json_task(move || {
                    let attestation = chain
                        .verify_unaggregated_attestation_for_gossip(attestation.clone(), None)
                        .map_err(|e| {
                            warp_utils::reject::object_invalid(format!(
                                "gossip verification failed: {:?}",
                                e
                            ))
                        })?;

                    publish_pubsub_message(
                        &network_tx,
                        PubsubMessage::Attestation(Box::new((
                            attestation.subnet_id(),
                            attestation.attestation().clone(),
                        ))),
                    )?;

                    chain
                        .apply_attestation_to_fork_choice(&attestation)
                        .map_err(|e| {
                            warp_utils::reject::broadcast_without_import(format!(
                                "not applied to fork choice: {:?}",
                                e
                            ))
                        })?;

                    chain
                        .add_to_naive_aggregation_pool(attestation)
                        .map_err(|e| {
                            warp_utils::reject::broadcast_without_import(format!(
                                "not applied to naive aggregation pool: {:?}",
                                e
                            ))
                        })?;

                    Ok(())
                })
            },
        );

    // GET beacon/pool/attestations
    let get_beacon_pool_attestations = beacon_pool_path
        .clone()
        .and(warp::path("attestations"))
        .and(warp::path::end())
        .and_then(|chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                let mut attestations = chain.op_pool.get_all_attestations();
                attestations.extend(chain.naive_aggregation_pool.read().iter().cloned());
                Ok(api_types::GenericResponse::from(attestations))
            })
        });

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
        .and(warp::path::param::<StateId>())
        .and(warp::path::end())
        .and(chain_filter.clone())
        .and_then(|state_id: StateId, chain: Arc<BeaconChain<T>>| {
            blocking_task(move || {
                state_id.map_state(&chain, |state| {
                    Ok(warp::reply::json(&api_types::GenericResponseRef::from(
                        &state,
                    )))
                })
            })
        });

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
                    .map(|(root, slot)| api_types::ChainHeadData { root, slot })
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
                SyncState::SyncingFinalized { .. } | SyncState::SyncingHead { .. } => {
                    Ok(warp::reply::with_status(
                        warp::reply(),
                        warp::http::StatusCode::PARTIAL_CONTENT,
                    ))
                }
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
                        bs58::decode(requested_peer_id.as_str())
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
                        //TODO: update this to seen_addresses once #1764 is resolved
                        let address = match peer_info.listening_addresses.get(0) {
                            Some(addr) => addr.to_string(),
                            None => "".to_string(), // this field is non-nullable in the eth2 API spec
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
                                    &peer_info.connection_status,
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
        .and(network_globals.clone())
        .and_then(|network_globals: Arc<NetworkGlobals<T::EthSpec>>| {
            blocking_json_task(move || {
                let mut peers: Vec<api_types::PeerData> = Vec::new();
                network_globals
                    .peers
                    .read()
                    .peers()
                    // the eth2 API spec implies only peers we have been connected to at some point should be included.
                    .filter(|(_, peer_info)| peer_info.connection_direction.is_some())
                    .for_each(|(peer_id, peer_info)| {
                        //TODO: update this to seen_addresses once #1764 is resolved
                        let address = match peer_info.listening_addresses.get(0) {
                            Some(addr) => addr.to_string(),
                            None => "".to_string(), // this field is non-nullable in the eth2 API spec
                        };
                        if let Some(dir) = peer_info.connection_direction.as_ref() {
                            peers.push(api_types::PeerData {
                                peer_id: peer_id.to_string(),
                                enr: peer_info.enr.as_ref().map(|enr| enr.to_base64()),
                                last_seen_p2p_address: address,
                                direction: api_types::PeerDirection::from_connection_direction(
                                    &dir,
                                ),
                                state: api_types::PeerState::from_peer_connection_status(
                                    &peer_info.connection_status,
                                ),
                            });
                        }
                    });
                Ok(api_types::GenericResponse::from(peers))
            })
        });

    /*
     * validator
     */

    // GET validator/duties/attester/{epoch}
    let get_validator_duties_attester = eth1_v1
        .and(warp::path("validator"))
        .and(warp::path("duties"))
        .and(warp::path("attester"))
        .and(warp::path::param::<Epoch>())
        .and(warp::path::end())
        .and(not_while_syncing_filter.clone())
        .and(warp::query::<api_types::ValidatorDutiesQuery>())
        .and(chain_filter.clone())
        .and_then(
            |epoch: Epoch, query: api_types::ValidatorDutiesQuery, chain: Arc<BeaconChain<T>>| {
                blocking_json_task(move || {
                    let current_epoch = chain
                        .epoch()
                        .map_err(warp_utils::reject::beacon_chain_error)?;

                    if epoch > current_epoch + 1 {
                        return Err(warp_utils::reject::custom_bad_request(format!(
                            "request epoch {} is more than one epoch past the current epoch {}",
                            epoch, current_epoch
                        )));
                    }

                    let validator_count = StateId::head()
                        .map_state(&chain, |state| Ok(state.validators.len() as u64))?;

                    let indices = query
                        .index
                        .as_ref()
                        .map(|index| index.0.clone())
                        .map(Result::Ok)
                        .unwrap_or_else(|| {
                            Ok::<_, warp::Rejection>((0..validator_count).collect())
                        })?;

                    let pubkeys = indices
                        .into_iter()
                        .filter(|i| *i < validator_count as u64)
                        .map(|i| {
                            let pubkey = chain
                                .validator_pubkey(i as usize)
                                .map_err(warp_utils::reject::beacon_chain_error)?
                                .ok_or_else(|| {
                                    warp_utils::reject::custom_bad_request(format!(
                                        "unknown validator index {}",
                                        i
                                    ))
                                })?;

                            Ok((i, pubkey))
                        })
                        .collect::<Result<Vec<_>, warp::Rejection>>()?;

                    // Converts the internal Lighthouse `AttestationDuty` struct into an
                    // API-conforming `AttesterData` struct.
                    let convert = |validator_index: u64,
                                   pubkey: PublicKey,
                                   duty: AttestationDuty|
                     -> api_types::AttesterData {
                        api_types::AttesterData {
                            pubkey: pubkey.into(),
                            validator_index,
                            committees_at_slot: duty.committees_at_slot,
                            committee_index: duty.index,
                            committee_length: duty.committee_len as u64,
                            validator_committee_index: duty.committee_position as u64,
                            slot: duty.slot,
                        }
                    };

                    // Here we have two paths:
                    //
                    // ## Fast
                    //
                    // If the request epoch is the current epoch, use the cached beacon chain
                    // method.
                    //
                    // ## Slow
                    //
                    // If the request epoch is prior to the current epoch, load a beacon state from
                    // disk
                    //
                    // The idea is to stop historical requests from washing out the cache on the
                    // beacon chain, whilst allowing a VC to request duties quickly.
                    let duties = if epoch == current_epoch {
                        // Fast path.
                        pubkeys
                            .into_iter()
                            // Exclude indices which do not represent a known public key and a
                            // validator duty.
                            .filter_map(|(i, pubkey)| {
                                Some(
                                    chain
                                        .validator_attestation_duty(i as usize, epoch)
                                        .transpose()?
                                        .map_err(warp_utils::reject::beacon_chain_error)
                                        .map(|duty| convert(i, pubkey, duty)),
                                )
                            })
                            .collect::<Result<Vec<_>, warp::Rejection>>()?
                    } else {
                        // If the head state is equal to or earlier than the request epoch, use it.
                        let mut state = chain
                            .with_head(|head| {
                                if head.beacon_state.current_epoch() <= epoch {
                                    Ok(Some(
                                        head.beacon_state
                                            .clone_with(CloneConfig::committee_caches_only()),
                                    ))
                                } else {
                                    Ok(None)
                                }
                            })
                            .map_err(warp_utils::reject::beacon_chain_error)?
                            .map(Result::Ok)
                            .unwrap_or_else(|| {
                                StateId::slot(epoch.start_slot(T::EthSpec::slots_per_epoch()))
                                    .state(&chain)
                            })?;

                        // Only skip forward to the epoch prior to the request, since we have a
                        // one-epoch look-ahead on shuffling.
                        while state
                            .next_epoch()
                            .map_err(warp_utils::reject::beacon_state_error)?
                            < epoch
                        {
                            // Don't calculate state roots since they aren't required for calculating
                            // shuffling (achieved by providing Hash256::zero()).
                            per_slot_processing(&mut state, Some(Hash256::zero()), &chain.spec)
                                .map_err(warp_utils::reject::slot_processing_error)?;
                        }

                        let relative_epoch =
                            RelativeEpoch::from_epoch(state.current_epoch(), epoch).map_err(
                                |e| {
                                    warp_utils::reject::custom_server_error(format!(
                                        "unable to obtain suitable state: {:?}",
                                        e
                                    ))
                                },
                            )?;

                        state
                            .build_committee_cache(relative_epoch, &chain.spec)
                            .map_err(warp_utils::reject::beacon_state_error)?;
                        pubkeys
                            .into_iter()
                            .filter_map(|(i, pubkey)| {
                                Some(
                                    state
                                        .get_attestation_duties(i as usize, relative_epoch)
                                        .transpose()?
                                        .map_err(warp_utils::reject::beacon_state_error)
                                        .map(|duty| convert(i, pubkey, duty)),
                                )
                            })
                            .collect::<Result<Vec<_>, warp::Rejection>>()?
                    };

                    Ok(api_types::GenericResponse::from(duties))
                })
            },
        );

    // GET validator/duties/proposer/{epoch}
    let get_validator_duties_proposer = eth1_v1
        .and(warp::path("validator"))
        .and(warp::path("duties"))
        .and(warp::path("proposer"))
        .and(warp::path::param::<Epoch>())
        .and(warp::path::end())
        .and(not_while_syncing_filter.clone())
        .and(chain_filter.clone())
        .and(beacon_proposer_cache())
        .and_then(
            |epoch: Epoch,
             chain: Arc<BeaconChain<T>>,
             beacon_proposer_cache: Arc<Mutex<BeaconProposerCache>>| {
                blocking_json_task(move || {
                    beacon_proposer_cache
                        .lock()
                        .get_proposers(&chain, epoch)
                        .map(api_types::GenericResponse::from)
                })
            },
        );

    // GET validator/blocks/{slot}
    let get_validator_blocks = eth1_v1
        .and(warp::path("validator"))
        .and(warp::path("blocks"))
        .and(warp::path::param::<Slot>())
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

    // POST validator/aggregate_and_proofs
    let post_validator_aggregate_and_proofs = eth1_v1
        .and(warp::path("validator"))
        .and(warp::path("aggregate_and_proofs"))
        .and(warp::path::end())
        .and(not_while_syncing_filter)
        .and(chain_filter.clone())
        .and(warp::body::json())
        .and(network_tx_filter.clone())
        .and_then(
            |chain: Arc<BeaconChain<T>>,
             aggregate: SignedAggregateAndProof<T::EthSpec>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                blocking_json_task(move || {
                    let aggregate =
                        match chain.verify_aggregated_attestation_for_gossip(aggregate.clone()) {
                            Ok(aggregate) => aggregate,
                            // If we already know the attestation, don't broadcast it or attempt to
                            // further verify it. Return success.
                            //
                            // It's reasonably likely that two different validators produce
                            // identical aggregates, especially if they're using the same beacon
                            // node.
                            Err(AttnError::AttestationAlreadyKnown(_)) => return Ok(()),
                            Err(e) => {
                                return Err(warp_utils::reject::object_invalid(format!(
                                    "gossip verification failed: {:?}",
                                    e
                                )))
                            }
                        };

                    publish_pubsub_message(
                        &network_tx,
                        PubsubMessage::AggregateAndProofAttestation(Box::new(
                            aggregate.aggregate().clone(),
                        )),
                    )?;

                    chain
                        .apply_attestation_to_fork_choice(&aggregate)
                        .map_err(|e| {
                            warp_utils::reject::broadcast_without_import(format!(
                                "not applied to fork choice: {:?}",
                                e
                            ))
                        })?;

                    chain.add_to_block_inclusion_pool(aggregate).map_err(|e| {
                        warp_utils::reject::broadcast_without_import(format!(
                            "not applied to block inclusion pool: {:?}",
                            e
                        ))
                    })?;

                    Ok(())
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
        .and_then(
            |subscriptions: Vec<api_types::BeaconCommitteeSubscription>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                blocking_json_task(move || {
                    for subscription in &subscriptions {
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
        .and(chain_filter)
        .and_then(|epoch: Epoch, chain: Arc<BeaconChain<T>>| {
            blocking_json_task(move || {
                validator_inclusion::global_validator_inclusion_data(epoch, &chain)
                    .map(api_types::GenericResponse::from)
            })
        });

    // Define the ultimate set of routes that will be provided to the server.
    let routes = warp::get()
        .and(
            get_beacon_genesis
                .or(get_beacon_state_root.boxed())
                .or(get_beacon_state_fork.boxed())
                .or(get_beacon_state_finality_checkpoints.boxed())
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
                .or(get_validator_duties_attester.boxed())
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
                .boxed(),
        )
        .or(warp::post()
            .and(
                post_beacon_blocks
                    .or(post_beacon_pool_attestations.boxed())
                    .or(post_beacon_pool_attester_slashings.boxed())
                    .or(post_beacon_pool_proposer_slashings.boxed())
                    .or(post_beacon_pool_voluntary_exits.boxed())
                    .or(post_validator_aggregate_and_proofs.boxed())
                    .or(post_validator_beacon_committee_subscriptions.boxed())
                    .boxed(),
            )
            .boxed())
        .boxed()
        // Maps errors into HTTP responses.
        .recover(warp_utils::reject::handle_rejection)
        .with(slog_logging(log.clone()))
        .with(prometheus_metrics())
        // Add a `Server` header.
        .map(|reply| warp::reply::with_header(reply, "Server", &version_with_platform()))
        .with(cors_builder.build());

    let (listening_socket, server) = warp::serve(routes).try_bind_with_graceful_shutdown(
        SocketAddrV4::new(config.listen_addr, config.listen_port),
        async {
            shutdown.await;
        },
    )?;

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
