//! This crate provides a HTTP server that is solely dedicated to serving the `/metrics` endpoint.
//!
//! For other endpoints, see the `http_api` crate.
use crate::{InitializedValidators, ValidatorStore};
use eth2::lighthouse_vc::types::{self as api_types, PublicKeyBytes};
use lighthouse_version::version_with_platform;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use slog::{crit, info, Logger};
use slot_clock::SystemTimeSlotClock;
use std::future::Future;
use std::marker::PhantomData;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;
use types::EthSpec;
use warp::Filter;
use warp_utils::task::blocking_json_task;

mod tests;

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

/// A wrapper around all the items required to spawn the HTTP server.
///
/// The server will gracefully handle the case where any fields are `None`.
pub struct Context<E: EthSpec> {
    pub initialized_validators: Option<Arc<RwLock<InitializedValidators>>>,
    pub data_dir: Option<PathBuf>,
    pub config: Config,
    pub log: Logger,
    pub _phantom: PhantomData<E>,
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
            listen_port: 5062,
            allow_origin: None,
        }
    }
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
pub fn serve<T: EthSpec>(
    ctx: Arc<Context<T>>,
    shutdown: impl Future<Output = ()> + Send + Sync + 'static,
) -> Result<(SocketAddr, impl Future<Output = ()>), Error> {
    let config = &ctx.config;
    let log = ctx.log.clone();
    let allow_origin = config.allow_origin.clone();

    // Sanity check.
    if !config.enabled {
        crit!(log, "Cannot start disabled metrics HTTP server");
        return Err(Error::Other(
            "A disabled metrics server should not be started".to_string(),
        ));
    }

    /*
    // Create a `warp` filter that provides access to the network globals.
    let inner_validator_store = ctx.validator_store.clone();
    let validator_store_filter = warp::any()
        .map(move || inner_validator_store.clone())
        .and_then(|validator_store| async move {
            match validator_store {
                Some(store) => Ok(store),
                None => Err(warp_utils::reject::custom_not_found(
                    "validator store is not initialized.".to_string(),
                )),
            }
        });
    */

    let inner_initialized_validators = ctx.initialized_validators.clone();
    let initialized_validators_filter = warp::any()
        .map(move || inner_initialized_validators.clone())
        .and_then(|initialized_validators| async move {
            match initialized_validators {
                Some(store) => Ok(store),
                None => Err(warp_utils::reject::custom_not_found(
                    "validator store is not initialized.".to_string(),
                )),
            }
        });

    let inner_data_dir = ctx.data_dir.clone();
    let data_dir_filter =
        warp::any()
            .map(move || inner_data_dir.clone())
            .and_then(|data_dir| async move {
                match data_dir {
                    Some(dir) => Ok(dir),
                    None => Err(warp_utils::reject::custom_not_found(
                        "data_dir directory is not initialized.".to_string(),
                    )),
                }
            });

    // GET node/version
    let get_node_version = warp::path("lighthouse")
        .and(warp::path("version"))
        .and(warp::path::end())
        .and_then(|| {
            blocking_json_task(move || {
                Ok(api_types::GenericResponse::from(api_types::VersionData {
                    version: version_with_platform(),
                }))
            })
        });

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

    // GET lighthouse/validators
    let get_lighthouse_validators = warp::path("lighthouse")
        .and(warp::path("validators"))
        .and(warp::path::end())
        .and(initialized_validators_filter.clone())
        .and_then(
            |initialized_validators: Arc<RwLock<InitializedValidators>>| {
                blocking_json_task(move || {
                    let validators = initialized_validators
                        .read()
                        .validator_definitions()
                        .iter()
                        .map(|def| api_types::ValidatorData {
                            enabled: def.enabled,
                            voting_pubkey: PublicKeyBytes::from(&def.voting_public_key),
                        })
                        .collect::<Vec<_>>();

                    Ok(api_types::GenericResponse::from(validators))
                })
            },
        );

    // POST lighthouse/validator/hd
    let post_validator_beacon_committee_subscriptions = warp::path("lighthouse")
        .and(warp::path("validator"))
        .and(warp::path("hd"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(data_dir_filter.clone())
        .and(initialized_validators_filter.clone())
        .and_then(
            |body: api_types::CreateHdValidatorPostData,
             data_dir: PathBuf,
             initialized_validators: Arc<RwLock<InitializedValidators>>| {
                blocking_json_task(move || {
                    // TODO
                    Ok(())
                })
            },
        );

    let routes = warp::get()
        .and(
            get_node_version
                .or(get_lighthouse_health)
                .or(get_lighthouse_validators),
        )
        // Maps errors into HTTP responses.
        .recover(warp_utils::reject::handle_rejection)
        // Add a `Server` header.
        .map(|reply| warp::reply::with_header(reply, "Server", &version_with_platform()))
        // Maybe add some CORS headers.
        .map(move |reply| warp_utils::reply::maybe_cors(reply, allow_origin.as_ref()));

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
