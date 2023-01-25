mod api_secret;
mod create_validator;
mod keystores;
mod remotekeys;
mod tests;

use crate::{determine_graffiti, GraffitiFile, ValidatorStore};
use account_utils::{
    mnemonic_from_phrase,
    validator_definitions::{SigningDefinition, ValidatorDefinition, Web3SignerDefinition},
};
pub use api_secret::ApiSecret;
use create_validator::{create_validators_mnemonic, create_validators_web3signer};
use eth2::lighthouse_vc::{
    std_types::{AuthResponse, GetFeeRecipientResponse, GetGasLimitResponse},
    types::{self as api_types, GenericResponse, Graffiti, PublicKey, PublicKeyBytes},
};
use lighthouse_version::version_with_platform;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use slog::{crit, info, warn, Logger};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use sysinfo::{System, SystemExt};
use system_health::observe_system_health_vc;
use task_executor::TaskExecutor;
use types::{ChainSpec, ConfigAndPreset, EthSpec};
use validator_dir::Builder as ValidatorDirBuilder;
use warp::{
    http::{
        header::{HeaderValue, CONTENT_TYPE},
        response::Response,
        StatusCode,
    },
    Filter,
};

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
pub struct Context<T: SlotClock, E: EthSpec> {
    pub task_executor: TaskExecutor,
    pub api_secret: ApiSecret,
    pub validator_store: Option<Arc<ValidatorStore<T, E>>>,
    pub validator_dir: Option<PathBuf>,
    pub graffiti_file: Option<GraffitiFile>,
    pub graffiti_flag: Option<Graffiti>,
    pub spec: ChainSpec,
    pub config: Config,
    pub log: Logger,
    pub _phantom: PhantomData<E>,
}

/// Configuration for the HTTP server.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub enabled: bool,
    pub listen_addr: IpAddr,
    pub listen_port: u16,
    pub allow_origin: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
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
pub fn serve<T: 'static + SlotClock + Clone, E: EthSpec>(
    ctx: Arc<Context<T, E>>,
    shutdown: impl Future<Output = ()> + Send + Sync + 'static,
) -> Result<(SocketAddr, impl Future<Output = ()>), Error> {
    let config = &ctx.config;
    let log = ctx.log.clone();

    // Configure CORS.
    let cors_builder = {
        let builder = warp::cors()
            .allow_methods(vec!["GET", "POST", "PATCH", "DELETE"])
            .allow_headers(vec!["Content-Type", "Authorization"]);

        warp_utils::cors::set_builder_origins(
            builder,
            config.allow_origin.as_deref(),
            (config.listen_addr, config.listen_port),
        )?
    };

    // Sanity check.
    if !config.enabled {
        crit!(log, "Cannot start disabled metrics HTTP server");
        return Err(Error::Other(
            "A disabled metrics server should not be started".to_string(),
        ));
    }

    let authorization_header_filter = ctx.api_secret.authorization_header_filter();
    let mut api_token_path = ctx.api_secret.api_token_path();

    // Attempt to convert the path to an absolute path, but don't error if it fails.
    match api_token_path.canonicalize() {
        Ok(abs_path) => api_token_path = abs_path,
        Err(e) => {
            warn!(
                log,
                "Error canonicalizing token path";
                "error" => ?e,
            );
        }
    };

    let signer = ctx.api_secret.signer();
    let signer = warp::any().map(move || signer.clone());

    let inner_validator_store = ctx.validator_store.clone();
    let validator_store_filter = warp::any()
        .map(move || inner_validator_store.clone())
        .and_then(|validator_store: Option<_>| async move {
            validator_store.ok_or_else(|| {
                warp_utils::reject::custom_not_found(
                    "validator store is not initialized.".to_string(),
                )
            })
        });

    let inner_task_executor = ctx.task_executor.clone();
    let task_executor_filter = warp::any().map(move || inner_task_executor.clone());

    let inner_validator_dir = ctx.validator_dir.clone();
    let validator_dir_filter = warp::any()
        .map(move || inner_validator_dir.clone())
        .and_then(|validator_dir: Option<_>| async move {
            validator_dir.ok_or_else(|| {
                warp_utils::reject::custom_not_found(
                    "validator_dir directory is not initialized.".to_string(),
                )
            })
        });

    let inner_graffiti_file = ctx.graffiti_file.clone();
    let graffiti_file_filter = warp::any().map(move || inner_graffiti_file.clone());

    let inner_graffiti_flag = ctx.graffiti_flag;
    let graffiti_flag_filter = warp::any().map(move || inner_graffiti_flag);

    let inner_ctx = ctx.clone();
    let log_filter = warp::any().map(move || inner_ctx.log.clone());

    let inner_spec = Arc::new(ctx.spec.clone());
    let spec_filter = warp::any().map(move || inner_spec.clone());

    let api_token_path_inner = api_token_path.clone();
    let api_token_path_filter = warp::any().map(move || api_token_path_inner.clone());

    // Create a `warp` filter that provides access to local system information.
    let system_info = Arc::new(RwLock::new(sysinfo::System::new()));
    {
        // grab write access for initialisation
        let mut system_info = system_info.write();
        system_info.refresh_disks_list();
        system_info.refresh_networks_list();
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

    // GET lighthouse/version
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

    // GET lighthouse/spec
    let get_lighthouse_spec = warp::path("lighthouse")
        .and(warp::path("spec"))
        .and(warp::path::end())
        .and(spec_filter.clone())
        .and(signer.clone())
        .and_then(|spec: Arc<_>, signer| {
            blocking_signed_json_task(signer, move || {
                let config = ConfigAndPreset::from_chain_spec::<E>(&spec, None);
                Ok(api_types::GenericResponse::from(config))
            })
        });

    // GET lighthouse/validators
    let get_lighthouse_validators = warp::path("lighthouse")
        .and(warp::path("validators"))
        .and(warp::path::end())
        .and(validator_store_filter.clone())
        .and(signer.clone())
        .and_then(|validator_store: Arc<ValidatorStore<T, E>>, signer| {
            blocking_signed_json_task(signer, move || {
                let validators = validator_store
                    .initialized_validators()
                    .read()
                    .validator_definitions()
                    .iter()
                    .map(|def| api_types::ValidatorData {
                        enabled: def.enabled,
                        description: def.description.clone(),
                        voting_pubkey: PublicKeyBytes::from(&def.voting_public_key),
                    })
                    .collect::<Vec<_>>();

                Ok(api_types::GenericResponse::from(validators))
            })
        });

    // GET lighthouse/validators/{validator_pubkey}
    let get_lighthouse_validators_pubkey = warp::path("lighthouse")
        .and(warp::path("validators"))
        .and(warp::path::param::<PublicKey>())
        .and(warp::path::end())
        .and(validator_store_filter.clone())
        .and(signer.clone())
        .and_then(
            |validator_pubkey: PublicKey, validator_store: Arc<ValidatorStore<T, E>>, signer| {
                blocking_signed_json_task(signer, move || {
                    let validator = validator_store
                        .initialized_validators()
                        .read()
                        .validator_definitions()
                        .iter()
                        .find(|def| def.voting_public_key == validator_pubkey)
                        .map(|def| api_types::ValidatorData {
                            enabled: def.enabled,
                            description: def.description.clone(),
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

    // GET lighthouse/ui/health
    let get_lighthouse_ui_health = warp::path("lighthouse")
        .and(warp::path("ui"))
        .and(warp::path("health"))
        .and(warp::path::end())
        .and(system_info_filter)
        .and(app_start_filter)
        .and(validator_dir_filter.clone())
        .and(signer.clone())
        .and_then(|sysinfo, app_start: std::time::Instant, val_dir, signer| {
            blocking_signed_json_task(signer, move || {
                let app_uptime = app_start.elapsed().as_secs();
                Ok(api_types::GenericResponse::from(observe_system_health_vc(
                    sysinfo, val_dir, app_uptime,
                )))
            })
        });

    let get_lighthouse_ui_graffiti = warp::path("lighthouse")
        .and(warp::path("ui"))
        .and(warp::path("graffiti"))
        .and(warp::path::end())
        .and(validator_store_filter.clone())
        .and(graffiti_file_filter)
        .and(graffiti_flag_filter)
        .and(signer.clone())
        .and(log_filter.clone())
        .and_then(
            |validator_store: Arc<ValidatorStore<T, E>>,
             graffiti_file: Option<GraffitiFile>,
             graffiti_flag: Option<Graffiti>,
             signer,
             log| {
                blocking_signed_json_task(signer, move || {
                    let mut result = HashMap::new();
                    for (key, graffiti_definition) in validator_store
                        .initialized_validators()
                        .read()
                        .get_all_validators_graffiti()
                    {
                        let graffiti = determine_graffiti(
                            key,
                            &log,
                            graffiti_file.clone(),
                            graffiti_definition,
                            graffiti_flag,
                        );
                        result.insert(key.to_string(), graffiti.map(|g| g.as_utf8_lossy()));
                    }
                    Ok(api_types::GenericResponse::from(result))
                })
            },
        );

    // POST lighthouse/validators/
    let post_validators = warp::path("lighthouse")
        .and(warp::path("validators"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(validator_dir_filter.clone())
        .and(validator_store_filter.clone())
        .and(spec_filter.clone())
        .and(signer.clone())
        .and(task_executor_filter.clone())
        .and_then(
            |body: Vec<api_types::ValidatorRequest>,
             validator_dir: PathBuf,
             validator_store: Arc<ValidatorStore<T, E>>,
             spec: Arc<ChainSpec>,
             signer,
             task_executor: TaskExecutor| {
                blocking_signed_json_task(signer, move || {
                    if let Some(handle) = task_executor.handle() {
                        let (validators, mnemonic) =
                            handle.block_on(create_validators_mnemonic(
                                None,
                                None,
                                &body,
                                &validator_dir,
                                &validator_store,
                                &spec,
                            ))?;
                        let response = api_types::PostValidatorsResponseData {
                            mnemonic: mnemonic.into_phrase().into(),
                            validators,
                        };
                        Ok(api_types::GenericResponse::from(response))
                    } else {
                        Err(warp_utils::reject::custom_server_error(
                            "Lighthouse shutting down".into(),
                        ))
                    }
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
        .and(validator_store_filter.clone())
        .and(spec_filter)
        .and(signer.clone())
        .and(task_executor_filter.clone())
        .and_then(
            |body: api_types::CreateValidatorsMnemonicRequest,
             validator_dir: PathBuf,
             validator_store: Arc<ValidatorStore<T, E>>,
             spec: Arc<ChainSpec>,
             signer,
             task_executor: TaskExecutor| {
                blocking_signed_json_task(signer, move || {
                    if let Some(handle) = task_executor.handle() {
                        let mnemonic =
                            mnemonic_from_phrase(body.mnemonic.as_str()).map_err(|e| {
                                warp_utils::reject::custom_bad_request(format!(
                                    "invalid mnemonic: {:?}",
                                    e
                                ))
                            })?;
                        let (validators, _mnemonic) =
                            handle.block_on(create_validators_mnemonic(
                                Some(mnemonic),
                                Some(body.key_derivation_path_offset),
                                &body.validators,
                                &validator_dir,
                                &validator_store,
                                &spec,
                            ))?;
                        Ok(api_types::GenericResponse::from(validators))
                    } else {
                        Err(warp_utils::reject::custom_server_error(
                            "Lighthouse shutting down".into(),
                        ))
                    }
                })
            },
        );

    // POST lighthouse/validators/keystore
    let post_validators_keystore = warp::path("lighthouse")
        .and(warp::path("validators"))
        .and(warp::path("keystore"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(validator_dir_filter.clone())
        .and(validator_store_filter.clone())
        .and(signer.clone())
        .and(task_executor_filter.clone())
        .and_then(
            |body: api_types::KeystoreValidatorsPostRequest,
             validator_dir: PathBuf,
             validator_store: Arc<ValidatorStore<T, E>>,
             signer,
             task_executor: TaskExecutor| {
                blocking_signed_json_task(signer, move || {
                    // Check to ensure the password is correct.
                    let keypair = body
                        .keystore
                        .decrypt_keypair(body.password.as_ref())
                        .map_err(|e| {
                            warp_utils::reject::custom_bad_request(format!(
                                "invalid keystore: {:?}",
                                e
                            ))
                        })?;

                    let validator_dir = ValidatorDirBuilder::new(validator_dir.clone())
                        .voting_keystore(body.keystore.clone(), body.password.as_ref())
                        .store_withdrawal_keystore(false)
                        .build()
                        .map_err(|e| {
                            warp_utils::reject::custom_server_error(format!(
                                "failed to build validator directory: {:?}",
                                e
                            ))
                        })?;

                    // Drop validator dir so that `add_validator_keystore` can re-lock the keystore.
                    let voting_keystore_path = validator_dir.voting_keystore_path();
                    drop(validator_dir);
                    let voting_password = body.password.clone();
                    let graffiti = body.graffiti.clone();
                    let suggested_fee_recipient = body.suggested_fee_recipient;
                    let gas_limit = body.gas_limit;
                    let builder_proposals = body.builder_proposals;

                    let validator_def = {
                        if let Some(handle) = task_executor.handle() {
                            handle
                                .block_on(validator_store.add_validator_keystore(
                                    voting_keystore_path,
                                    voting_password,
                                    body.enable,
                                    graffiti,
                                    suggested_fee_recipient,
                                    gas_limit,
                                    builder_proposals,
                                ))
                                .map_err(|e| {
                                    warp_utils::reject::custom_server_error(format!(
                                        "failed to initialize validator: {:?}",
                                        e
                                    ))
                                })?
                        } else {
                            return Err(warp_utils::reject::custom_server_error(
                                "Lighthouse shutting down".into(),
                            ));
                        }
                    };

                    Ok(api_types::GenericResponse::from(api_types::ValidatorData {
                        enabled: body.enable,
                        description: validator_def.description,
                        voting_pubkey: keypair.pk.into(),
                    }))
                })
            },
        );

    // POST lighthouse/validators/web3signer
    let post_validators_web3signer = warp::path("lighthouse")
        .and(warp::path("validators"))
        .and(warp::path("web3signer"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(validator_store_filter.clone())
        .and(signer.clone())
        .and(task_executor_filter.clone())
        .and_then(
            |body: Vec<api_types::Web3SignerValidatorRequest>,
             validator_store: Arc<ValidatorStore<T, E>>,
             signer,
             task_executor: TaskExecutor| {
                blocking_signed_json_task(signer, move || {
                    if let Some(handle) = task_executor.handle() {
                        let web3signers: Vec<ValidatorDefinition> = body
                            .into_iter()
                            .map(|web3signer| ValidatorDefinition {
                                enabled: web3signer.enable,
                                voting_public_key: web3signer.voting_public_key,
                                graffiti: web3signer.graffiti,
                                suggested_fee_recipient: web3signer.suggested_fee_recipient,
                                gas_limit: web3signer.gas_limit,
                                builder_proposals: web3signer.builder_proposals,
                                description: web3signer.description,
                                signing_definition: SigningDefinition::Web3Signer(
                                    Web3SignerDefinition {
                                        url: web3signer.url,
                                        root_certificate_path: web3signer.root_certificate_path,
                                        request_timeout_ms: web3signer.request_timeout_ms,
                                        client_identity_path: web3signer.client_identity_path,
                                        client_identity_password: web3signer
                                            .client_identity_password,
                                    },
                                ),
                            })
                            .collect();
                        handle.block_on(create_validators_web3signer(
                            web3signers,
                            &validator_store,
                        ))?;
                        Ok(())
                    } else {
                        Err(warp_utils::reject::custom_server_error(
                            "Lighthouse shutting down".into(),
                        ))
                    }
                })
            },
        );

    // PATCH lighthouse/validators/{validator_pubkey}
    let patch_validators = warp::path("lighthouse")
        .and(warp::path("validators"))
        .and(warp::path::param::<PublicKey>())
        .and(warp::path::end())
        .and(warp::body::json())
        .and(validator_store_filter.clone())
        .and(signer.clone())
        .and(task_executor_filter.clone())
        .and_then(
            |validator_pubkey: PublicKey,
             body: api_types::ValidatorPatchRequest,
             validator_store: Arc<ValidatorStore<T, E>>,
             signer,
             task_executor: TaskExecutor| {
                blocking_signed_json_task(signer, move || {
                    let initialized_validators_rw_lock = validator_store.initialized_validators();
                    let mut initialized_validators = initialized_validators_rw_lock.write();

                    match (
                        initialized_validators.is_enabled(&validator_pubkey),
                        initialized_validators.validator(&validator_pubkey.compress()),
                    ) {
                        (None, _) => Err(warp_utils::reject::custom_not_found(format!(
                            "no validator for {:?}",
                            validator_pubkey
                        ))),
                        (Some(is_enabled), Some(initialized_validator))
                            if Some(is_enabled) == body.enabled
                                && initialized_validator.get_gas_limit() == body.gas_limit
                                && initialized_validator.get_builder_proposals()
                                    == body.builder_proposals =>
                        {
                            Ok(())
                        }
                        (Some(_), _) => {
                            if let Some(handle) = task_executor.handle() {
                                handle
                                    .block_on(
                                        initialized_validators.set_validator_definition_fields(
                                            &validator_pubkey,
                                            body.enabled,
                                            body.gas_limit,
                                            body.builder_proposals,
                                        ),
                                    )
                                    .map_err(|e| {
                                        warp_utils::reject::custom_server_error(format!(
                                            "unable to set validator status: {:?}",
                                            e
                                        ))
                                    })?;
                                Ok(())
                            } else {
                                Err(warp_utils::reject::custom_server_error(
                                    "Lighthouse shutting down".into(),
                                ))
                            }
                        }
                    }
                })
            },
        );

    // GET /lighthouse/auth
    let get_auth = warp::path("lighthouse").and(warp::path("auth").and(warp::path::end()));
    let get_auth = get_auth
        .and(signer.clone())
        .and(api_token_path_filter)
        .and_then(|signer, token_path: PathBuf| {
            blocking_signed_json_task(signer, move || {
                Ok(AuthResponse {
                    token_path: token_path.display().to_string(),
                })
            })
        });

    // Standard key-manager endpoints.
    let eth_v1 = warp::path("eth").and(warp::path("v1"));
    let std_keystores = eth_v1.and(warp::path("keystores")).and(warp::path::end());
    let std_remotekeys = eth_v1.and(warp::path("remotekeys")).and(warp::path::end());

    // GET /eth/v1/validator/{pubkey}/feerecipient
    let get_fee_recipient = eth_v1
        .and(warp::path("validator"))
        .and(warp::path::param::<PublicKey>())
        .and(warp::path("feerecipient"))
        .and(warp::path::end())
        .and(validator_store_filter.clone())
        .and(signer.clone())
        .and_then(
            |validator_pubkey: PublicKey, validator_store: Arc<ValidatorStore<T, E>>, signer| {
                blocking_signed_json_task(signer, move || {
                    if validator_store
                        .initialized_validators()
                        .read()
                        .is_enabled(&validator_pubkey)
                        .is_none()
                    {
                        return Err(warp_utils::reject::custom_not_found(format!(
                            "no validator found with pubkey {:?}",
                            validator_pubkey
                        )));
                    }
                    validator_store
                        .get_fee_recipient(&PublicKeyBytes::from(&validator_pubkey))
                        .map(|fee_recipient| {
                            GenericResponse::from(GetFeeRecipientResponse {
                                pubkey: PublicKeyBytes::from(validator_pubkey.clone()),
                                ethaddress: fee_recipient,
                            })
                        })
                        .ok_or_else(|| {
                            warp_utils::reject::custom_server_error(
                                "no fee recipient set".to_string(),
                            )
                        })
                })
            },
        );

    // POST /eth/v1/validator/{pubkey}/feerecipient
    let post_fee_recipient = eth_v1
        .and(warp::path("validator"))
        .and(warp::path::param::<PublicKey>())
        .and(warp::path("feerecipient"))
        .and(warp::body::json())
        .and(warp::path::end())
        .and(validator_store_filter.clone())
        .and(signer.clone())
        .and_then(
            |validator_pubkey: PublicKey,
             request: api_types::UpdateFeeRecipientRequest,
             validator_store: Arc<ValidatorStore<T, E>>,
             signer| {
                blocking_signed_json_task(signer, move || {
                    if validator_store
                        .initialized_validators()
                        .read()
                        .is_enabled(&validator_pubkey)
                        .is_none()
                    {
                        return Err(warp_utils::reject::custom_not_found(format!(
                            "no validator found with pubkey {:?}",
                            validator_pubkey
                        )));
                    }
                    validator_store
                        .initialized_validators()
                        .write()
                        .set_validator_fee_recipient(&validator_pubkey, request.ethaddress)
                        .map_err(|e| {
                            warp_utils::reject::custom_server_error(format!(
                                "Error persisting fee recipient: {:?}",
                                e
                            ))
                        })
                })
            },
        )
        .map(|reply| warp::reply::with_status(reply, warp::http::StatusCode::ACCEPTED));

    // DELETE /eth/v1/validator/{pubkey}/feerecipient
    let delete_fee_recipient = eth_v1
        .and(warp::path("validator"))
        .and(warp::path::param::<PublicKey>())
        .and(warp::path("feerecipient"))
        .and(warp::path::end())
        .and(validator_store_filter.clone())
        .and(signer.clone())
        .and_then(
            |validator_pubkey: PublicKey, validator_store: Arc<ValidatorStore<T, E>>, signer| {
                blocking_signed_json_task(signer, move || {
                    if validator_store
                        .initialized_validators()
                        .read()
                        .is_enabled(&validator_pubkey)
                        .is_none()
                    {
                        return Err(warp_utils::reject::custom_not_found(format!(
                            "no validator found with pubkey {:?}",
                            validator_pubkey
                        )));
                    }
                    validator_store
                        .initialized_validators()
                        .write()
                        .delete_validator_fee_recipient(&validator_pubkey)
                        .map_err(|e| {
                            warp_utils::reject::custom_server_error(format!(
                                "Error persisting fee recipient removal: {:?}",
                                e
                            ))
                        })
                })
            },
        )
        .map(|reply| warp::reply::with_status(reply, warp::http::StatusCode::NO_CONTENT));

    // GET /eth/v1/validator/{pubkey}/gas_limit
    let get_gas_limit = eth_v1
        .and(warp::path("validator"))
        .and(warp::path::param::<PublicKey>())
        .and(warp::path("gas_limit"))
        .and(warp::path::end())
        .and(validator_store_filter.clone())
        .and(signer.clone())
        .and_then(
            |validator_pubkey: PublicKey, validator_store: Arc<ValidatorStore<T, E>>, signer| {
                blocking_signed_json_task(signer, move || {
                    if validator_store
                        .initialized_validators()
                        .read()
                        .is_enabled(&validator_pubkey)
                        .is_none()
                    {
                        return Err(warp_utils::reject::custom_not_found(format!(
                            "no validator found with pubkey {:?}",
                            validator_pubkey
                        )));
                    }
                    Ok(GenericResponse::from(GetGasLimitResponse {
                        pubkey: PublicKeyBytes::from(validator_pubkey.clone()),
                        gas_limit: validator_store
                            .get_gas_limit(&PublicKeyBytes::from(&validator_pubkey)),
                    }))
                })
            },
        );

    // POST /eth/v1/validator/{pubkey}/gas_limit
    let post_gas_limit = eth_v1
        .and(warp::path("validator"))
        .and(warp::path::param::<PublicKey>())
        .and(warp::path("gas_limit"))
        .and(warp::body::json())
        .and(warp::path::end())
        .and(validator_store_filter.clone())
        .and(signer.clone())
        .and_then(
            |validator_pubkey: PublicKey,
             request: api_types::UpdateGasLimitRequest,
             validator_store: Arc<ValidatorStore<T, E>>,
             signer| {
                blocking_signed_json_task(signer, move || {
                    if validator_store
                        .initialized_validators()
                        .read()
                        .is_enabled(&validator_pubkey)
                        .is_none()
                    {
                        return Err(warp_utils::reject::custom_not_found(format!(
                            "no validator found with pubkey {:?}",
                            validator_pubkey
                        )));
                    }
                    validator_store
                        .initialized_validators()
                        .write()
                        .set_validator_gas_limit(&validator_pubkey, request.gas_limit)
                        .map_err(|e| {
                            warp_utils::reject::custom_server_error(format!(
                                "Error persisting gas limit: {:?}",
                                e
                            ))
                        })
                })
            },
        )
        .map(|reply| warp::reply::with_status(reply, warp::http::StatusCode::ACCEPTED));

    // DELETE /eth/v1/validator/{pubkey}/gas_limit
    let delete_gas_limit = eth_v1
        .and(warp::path("validator"))
        .and(warp::path::param::<PublicKey>())
        .and(warp::path("gas_limit"))
        .and(warp::path::end())
        .and(validator_store_filter.clone())
        .and(signer.clone())
        .and_then(
            |validator_pubkey: PublicKey, validator_store: Arc<ValidatorStore<T, E>>, signer| {
                blocking_signed_json_task(signer, move || {
                    if validator_store
                        .initialized_validators()
                        .read()
                        .is_enabled(&validator_pubkey)
                        .is_none()
                    {
                        return Err(warp_utils::reject::custom_not_found(format!(
                            "no validator found with pubkey {:?}",
                            validator_pubkey
                        )));
                    }
                    validator_store
                        .initialized_validators()
                        .write()
                        .delete_validator_gas_limit(&validator_pubkey)
                        .map_err(|e| {
                            warp_utils::reject::custom_server_error(format!(
                                "Error persisting gas limit removal: {:?}",
                                e
                            ))
                        })
                })
            },
        )
        .map(|reply| warp::reply::with_status(reply, warp::http::StatusCode::NO_CONTENT));

    // GET /eth/v1/keystores
    let get_std_keystores = std_keystores
        .and(signer.clone())
        .and(validator_store_filter.clone())
        .and_then(|signer, validator_store: Arc<ValidatorStore<T, E>>| {
            blocking_signed_json_task(signer, move || Ok(keystores::list(validator_store)))
        });

    // POST /eth/v1/keystores
    let post_std_keystores = std_keystores
        .and(warp::body::json())
        .and(signer.clone())
        .and(validator_dir_filter)
        .and(validator_store_filter.clone())
        .and(task_executor_filter.clone())
        .and(log_filter.clone())
        .and_then(
            |request, signer, validator_dir, validator_store, task_executor, log| {
                blocking_signed_json_task(signer, move || {
                    keystores::import(request, validator_dir, validator_store, task_executor, log)
                })
            },
        );

    // DELETE /eth/v1/keystores
    let delete_std_keystores = std_keystores
        .and(warp::body::json())
        .and(signer.clone())
        .and(validator_store_filter.clone())
        .and(task_executor_filter.clone())
        .and(log_filter.clone())
        .and_then(|request, signer, validator_store, task_executor, log| {
            blocking_signed_json_task(signer, move || {
                keystores::delete(request, validator_store, task_executor, log)
            })
        });

    // GET /eth/v1/remotekeys
    let get_std_remotekeys = std_remotekeys
        .and(signer.clone())
        .and(validator_store_filter.clone())
        .and_then(|signer, validator_store: Arc<ValidatorStore<T, E>>| {
            blocking_signed_json_task(signer, move || Ok(remotekeys::list(validator_store)))
        });

    // POST /eth/v1/remotekeys
    let post_std_remotekeys = std_remotekeys
        .and(warp::body::json())
        .and(signer.clone())
        .and(validator_store_filter.clone())
        .and(task_executor_filter.clone())
        .and(log_filter.clone())
        .and_then(|request, signer, validator_store, task_executor, log| {
            blocking_signed_json_task(signer, move || {
                remotekeys::import(request, validator_store, task_executor, log)
            })
        });

    // DELETE /eth/v1/remotekeys
    let delete_std_remotekeys = std_remotekeys
        .and(warp::body::json())
        .and(signer)
        .and(validator_store_filter)
        .and(task_executor_filter)
        .and(log_filter.clone())
        .and_then(|request, signer, validator_store, task_executor, log| {
            blocking_signed_json_task(signer, move || {
                remotekeys::delete(request, validator_store, task_executor, log)
            })
        });

    let routes = warp::any()
        .and(authorization_header_filter)
        // Note: it is critical that the `authorization_header_filter` is applied to all routes.
        // Keeping all the routes inside the following `and` is a reliable way to achieve this.
        //
        // When adding a route, don't forget to add it to the `routes_with_invalid_auth` tests!
        .and(
            warp::get()
                .and(
                    get_node_version
                        .or(get_lighthouse_health)
                        .or(get_lighthouse_spec)
                        .or(get_lighthouse_validators)
                        .or(get_lighthouse_validators_pubkey)
                        .or(get_lighthouse_ui_health)
                        .or(get_lighthouse_ui_graffiti)
                        .or(get_fee_recipient)
                        .or(get_gas_limit)
                        .or(get_std_keystores)
                        .or(get_std_remotekeys),
                )
                .or(warp::post().and(
                    post_validators
                        .or(post_validators_keystore)
                        .or(post_validators_mnemonic)
                        .or(post_validators_web3signer)
                        .or(post_fee_recipient)
                        .or(post_gas_limit)
                        .or(post_std_keystores)
                        .or(post_std_remotekeys),
                ))
                .or(warp::patch().and(patch_validators))
                .or(warp::delete().and(
                    delete_fee_recipient
                        .or(delete_gas_limit)
                        .or(delete_std_keystores)
                        .or(delete_std_remotekeys),
                )),
        )
        // The auth route is the only route that is allowed to be accessed without the API token.
        .or(warp::get().and(get_auth))
        // Maps errors into HTTP responses.
        .recover(warp_utils::reject::handle_rejection)
        // Add a `Server` header.
        .map(|reply| warp::reply::with_header(reply, "Server", &version_with_platform()))
        .with(cors_builder.build());

    let (listening_socket, server) = warp::serve(routes).try_bind_with_graceful_shutdown(
        SocketAddr::new(config.listen_addr, config.listen_port),
        async {
            shutdown.await;
        },
    )?;

    info!(
        log,
        "HTTP API started";
        "listen_address" => listening_socket.to_string(),
        "api_token_file" => ?api_token_path,
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
    F: FnOnce() -> Result<T, warp::Rejection> + Send + 'static,
    T: Serialize + Send + 'static,
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
