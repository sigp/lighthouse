//! This crate provides a HTTP server that is solely dedicated to serving the `/metrics` endpoint.
//!
//! For other endpoints, see the `http_api` crate.
mod api_secret;
mod create_validator;
mod tests;

use crate::InitializedValidators;
use account_utils::{
    mnemonic_from_phrase, validator_definitions::ValidatorDefinition, ZeroizeString,
};
use create_validator::create_validators;
use eth2::lighthouse_vc::types::{self as api_types, PublicKey, PublicKeyBytes};
use lighthouse_version::version_with_platform;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use slog::{crit, info, Logger};
use std::future::Future;
use std::marker::PhantomData;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;
use types::{ChainSpec, EthSpec};
use validator_dir::Builder as ValidatorDirBuilder;
use warp::{
    http::{
        header::{HeaderValue, CONTENT_TYPE},
        response::Response,
        StatusCode,
    },
    Filter,
};

pub use api_secret::ApiSecret;

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
    pub api_secret: ApiSecret,
    pub initialized_validators: Option<Arc<RwLock<InitializedValidators>>>,
    pub validator_dir: Option<PathBuf>,
    pub spec: ChainSpec,
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

    let authorization_header_filter = ctx.api_secret.authorization_header_filter();
    let api_token = ctx.api_secret.api_token();
    let signer = ctx.api_secret.signer();
    let signer = warp::any().map(move || signer.clone());

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

    let inner_validator_dir = ctx.validator_dir.clone();
    let validator_dir_filter = warp::any()
        .map(move || inner_validator_dir.clone())
        .and_then(|validator_dir| async move {
            match validator_dir {
                Some(dir) => Ok(dir),
                None => Err(warp_utils::reject::custom_not_found(
                    "validator_dir directory is not initialized.".to_string(),
                )),
            }
        });

    let inner_spec = Arc::new(ctx.spec.clone());
    let spec_filter = warp::any().map(move || inner_spec.clone());

    // GET node/version
    let get_node_version = warp::path("lighthouse")
        .and(warp::path("version"))
        .and(warp::path::end())
        .and(signer.clone())
        .and_then(|signer| {
            blocking_signed_json_task(signer, move || {
                Ok(api_types::GenericResponse::from(api_types::VersionData {
                    version: version_with_platform(),
                }))
            })
        });

    // GET lighthouse/health
    let get_lighthouse_health = warp::path("lighthouse")
        .and(warp::path("health"))
        .and(warp::path::end())
        .and(signer.clone())
        .and_then(|signer| {
            blocking_signed_json_task(signer, move || {
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
        .and(signer.clone())
        .and_then(
            |initialized_validators: Arc<RwLock<InitializedValidators>>, signer| {
                blocking_signed_json_task(signer, move || {
                    let validators = initialized_validators
                        .read()
                        .validator_definitions()
                        .iter()
                        .map(|def| api_types::ValidatorData {
                            enabled: def.enabled,
                            name: def.name.clone(),
                            voting_pubkey: PublicKeyBytes::from(&def.voting_public_key),
                        })
                        .collect::<Vec<_>>();

                    Ok(api_types::GenericResponse::from(validators))
                })
            },
        );

    // GET lighthouse/validators/{validator_pubkey}
    let get_lighthouse_validators_pubkey = warp::path("lighthouse")
        .and(warp::path("validators"))
        .and(warp::path::param::<PublicKey>())
        .and(warp::path::end())
        .and(initialized_validators_filter.clone())
        .and(signer.clone())
        .and_then(
            |validator_pubkey: PublicKey,
             initialized_validators: Arc<RwLock<InitializedValidators>>,
             signer| {
                blocking_signed_json_task(signer, move || {
                    let validator = initialized_validators
                        .read()
                        .validator_definitions()
                        .iter()
                        .find(|def| def.voting_public_key == validator_pubkey)
                        .map(|def| api_types::ValidatorData {
                            enabled: def.enabled,
                            name: def.name.clone(),
                            voting_pubkey: PublicKeyBytes::from(&def.voting_public_key),
                        })
                        .ok_or_else(|| {
                            warp_utils::reject::custom_not_found(format!(
                                "no validator for {:?}",
                                validator_pubkey
                            ))
                        })?;

                    Ok(api_types::GenericResponse::from(validator))
                })
            },
        );

    // POST lighthouse/validators/
    let post_validators = warp::path("lighthouse")
        .and(warp::path("validators"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(validator_dir_filter.clone())
        .and(initialized_validators_filter.clone())
        .and(spec_filter.clone())
        .and(signer.clone())
        .and_then(
            |body: Vec<api_types::ValidatorRequest>,
             validator_dir: PathBuf,
             initialized_validators: Arc<RwLock<InitializedValidators>>,
             spec: Arc<ChainSpec>,
             signer| {
                blocking_signed_json_task(signer, move || {
                    let (validators, mnemonic) = create_validators(
                        None,
                        None,
                        &body,
                        &validator_dir,
                        &initialized_validators,
                        &spec,
                    )?;
                    let response = api_types::PostValidatorsResponseData {
                        mnemonic: mnemonic.into_phrase(),
                        validators,
                    };
                    Ok(api_types::GenericResponse::from(response))
                })
            },
        );

    // POST lighthouse/validators/mnemonic
    let post_validators_mnemonic = warp::path("lighthouse")
        .and(warp::path("validators"))
        .and(warp::path("mnemonic"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(validator_dir_filter.clone())
        .and(initialized_validators_filter.clone())
        .and(spec_filter)
        .and(signer.clone())
        .and_then(
            |body: api_types::CreateValidatorsMnemonicRequest,
             validator_dir: PathBuf,
             initialized_validators: Arc<RwLock<InitializedValidators>>,
             spec: Arc<ChainSpec>,
             signer| {
                blocking_signed_json_task(signer, move || {
                    let mnemonic = mnemonic_from_phrase(&body.mnemonic).map_err(|e| {
                        warp_utils::reject::custom_bad_request(format!("invalid mnemonic: {:?}", e))
                    })?;
                    let (validators, _mnemonic) = create_validators(
                        Some(mnemonic),
                        Some(body.key_derivation_path_offset),
                        &body.validators,
                        &validator_dir,
                        &initialized_validators,
                        &spec,
                    )?;
                    Ok(api_types::GenericResponse::from(validators))
                })
            },
        );

    // POST lighthouse/validators/keystore
    let post_validators_keystore = warp::path("lighthouse")
        .and(warp::path("validators"))
        .and(warp::path("keystore"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(validator_dir_filter)
        .and(initialized_validators_filter.clone())
        .and(signer.clone())
        .and_then(
            |body: api_types::KeystoreValidatorsPostRequest,
             validator_dir: PathBuf,
             initialized_validators: Arc<RwLock<InitializedValidators>>,
             signer| {
                blocking_signed_json_task(signer, move || {
                    // Check to ensure the password is correct.
                    let keypair = body
                        .keystore
                        .decrypt_keypair(body.password.as_bytes())
                        .map_err(|e| {
                            warp_utils::reject::custom_bad_request(format!(
                                "invalid keystore: {:?}",
                                e
                            ))
                        })?;

                    let validator_dir = ValidatorDirBuilder::new(validator_dir.clone())
                        .voting_keystore(body.keystore.clone(), body.password.as_bytes())
                        .store_withdrawal_keystore(false)
                        .build()
                        .map_err(|e| {
                            warp_utils::reject::custom_server_error(format!(
                                "failed to build validator directory: {:?}",
                                e
                            ))
                        })?;

                    let voting_password = ZeroizeString::from(body.password.clone());

                    let mut validator_def = ValidatorDefinition::new_keystore_with_password(
                        validator_dir.voting_keystore_path(),
                        Some(voting_password),
                    )
                    .map_err(|e| {
                        warp_utils::reject::custom_server_error(format!(
                            "failed to create validator definitions: {:?}",
                            e
                        ))
                    })?;

                    let name = validator_def.name.clone();

                    validator_def.enabled = body.enable;

                    tokio::runtime::Handle::current()
                        .block_on(initialized_validators.write().add_definition(validator_def))
                        .map_err(|e| {
                            warp_utils::reject::custom_server_error(format!(
                                "failed to initialize validator: {:?}",
                                e
                            ))
                        })?;

                    Ok(api_types::GenericResponse::from(api_types::ValidatorData {
                        enabled: body.enable,
                        name,
                        voting_pubkey: keypair.pk.into(),
                    }))
                })
            },
        );

    // PATCH lighthouse/validators
    let patch_validators = warp::path("lighthouse")
        .and(warp::path("validators"))
        .and(warp::path::param::<PublicKey>())
        .and(warp::path::end())
        .and(warp::body::json())
        .and(initialized_validators_filter)
        .and(signer)
        .and_then(
            |validator_pubkey: PublicKey,
             body: api_types::ValidatorPatchRequest,
             initialized_validators: Arc<RwLock<InitializedValidators>>,
             signer| {
                blocking_signed_json_task(signer, move || {
                    let mut initialized_validators = initialized_validators.write();

                    match initialized_validators.is_enabled(&validator_pubkey) {
                        None => Err(warp_utils::reject::custom_not_found(format!(
                            "no validator for {:?}",
                            validator_pubkey
                        ))),
                        Some(enabled) if enabled == body.enabled => Ok(()),
                        Some(_) => {
                            tokio::runtime::Handle::current()
                                .block_on(
                                    initialized_validators
                                        .set_validator_status(&validator_pubkey, body.enabled),
                                )
                                .map_err(|e| {
                                    warp_utils::reject::custom_server_error(format!(
                                        "unable to set validator status: {:?}",
                                        e
                                    ))
                                })?;

                            Ok(())
                        }
                    }
                })
            },
        );

    let routes = warp::any()
        .and(authorization_header_filter)
        .and(
            warp::get().and(
                get_node_version
                    .or(get_lighthouse_health)
                    .or(get_lighthouse_validators)
                    .or(get_lighthouse_validators_pubkey),
            ),
        )
        .or(warp::post().and(
            post_validators
                .or(post_validators_keystore)
                .or(post_validators_mnemonic),
        ))
        .or(warp::patch().and(patch_validators))
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
        "api_token" => api_token,
    );

    Ok((listening_socket, server))
}

/// Executes `func` in blocking tokio task (i.e., where long-running tasks are permitted).
/// JSON-encodes the return value of `func`, using the `signer` function to produce a signature of
/// those bytes.
pub async fn blocking_signed_json_task<S, F, T>(
    signer: S,
    func: F,
) -> Result<impl warp::Reply, warp::Rejection>
where
    S: Fn(&[u8]) -> String,
    F: Fn() -> Result<T, warp::Rejection>,
    T: Serialize,
{
    warp_utils::task::blocking_task(func)
        .await
        .map(|func_output| {
            let mut response = match serde_json::to_vec(&func_output) {
                Ok(body) => {
                    let mut res = Response::new(body);
                    res.headers_mut()
                        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                    res
                }
                Err(_) => Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(vec![])
                    .expect("can produce simple response from static values"),
            };

            let body: &Vec<u8> = response.body();
            let signature = signer(body);
            let header_value =
                HeaderValue::from_str(&signature).expect("hash can be encoded as header");

            response.headers_mut().append("Signature", header_value);

            response
        })
}
