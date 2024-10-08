mod api_secret;
mod create_signed_voluntary_exit;
mod create_validator;
mod graffiti;
mod keystores;
mod remotekeys;
mod tests;

pub mod test_utils;

use crate::beacon_node_fallback::CandidateInfo;
use crate::http_api::graffiti::{delete_graffiti, get_graffiti, set_graffiti};

use crate::http_api::create_signed_voluntary_exit::create_signed_voluntary_exit;
use crate::{determine_graffiti, BlockService, GraffitiFile, ValidatorStore};
use account_utils::{
    mnemonic_from_phrase,
    validator_definitions::{SigningDefinition, ValidatorDefinition, Web3SignerDefinition},
};
pub use api_secret::ApiSecret;
use create_validator::{
    create_validators_mnemonic, create_validators_web3signer, get_voting_password_storage,
};
use eth2::lighthouse_vc::{
    std_types::{AuthResponse, GetFeeRecipientResponse, GetGasLimitResponse},
    types::{
        self as api_types, GenericResponse, GetGraffitiResponse, Graffiti, PublicKey,
        PublicKeyBytes, SetGraffitiRequest,
    },
};
use lighthouse_version::version_with_platform;
use logging::crit;
use logging::SSELoggingComponents;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
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
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use tracing::{info, warn};
use types::{ChainSpec, ConfigAndPreset, EthSpec};
use validator_dir::Builder as ValidatorDirBuilder;
use warp::{sse::Event, Filter};
use warp_utils::task::blocking_json_task;

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
    pub block_service: Option<BlockService<T, E>>,
    pub validator_store: Option<Arc<ValidatorStore<T, E>>>,
    pub validator_dir: Option<PathBuf>,
    pub secrets_dir: Option<PathBuf>,
    pub graffiti_file: Option<GraffitiFile>,
    pub graffiti_flag: Option<Graffiti>,
    pub spec: Arc<ChainSpec>,
    pub config: Config,
    // pub log: Logger,
    // pub sse_logging_components: Option<SSELoggingComponents>,
    pub slot_clock: T,
    pub _phantom: PhantomData<E>,
}

/// Configuration for the HTTP server.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub enabled: bool,
    pub listen_addr: IpAddr,
    pub listen_port: u16,
    pub allow_origin: Option<String>,
    pub allow_keystore_export: bool,
    pub store_passwords_in_secrets_dir: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            listen_port: 5062,
            allow_origin: None,
            allow_keystore_export: false,
            store_passwords_in_secrets_dir: false,
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
    let allow_keystore_export = config.allow_keystore_export;
    let store_passwords_in_secrets_dir = config.store_passwords_in_secrets_dir;

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
        crit!("Cannot start disabled metrics HTTP server");
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
                error = ?e,
                "Error canonicalizing token path"
            );
        }
    };

    let inner_block_service = ctx.block_service.clone();
    let block_service_filter = warp::any()
        .map(move || inner_block_service.clone())
        .and_then(|block_service: Option<_>| async move {
            block_service.ok_or_else(|| {
                warp_utils::reject::custom_not_found(
                    "block service is not initialized.".to_string(),
                )
            })
        });

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

    let inner_secrets_dir = ctx.secrets_dir.clone();
    let secrets_dir_filter = warp::any().map(move || inner_secrets_dir.clone()).and_then(
        |secrets_dir: Option<_>| async move {
            secrets_dir.ok_or_else(|| {
                warp_utils::reject::custom_not_found(
                    "secrets_dir directory is not initialized.".to_string(),
                )
            })
        },
    );

    let inner_graffiti_file = ctx.graffiti_file.clone();
    let graffiti_file_filter = warp::any().map(move || inner_graffiti_file.clone());

    let inner_graffiti_flag = ctx.graffiti_flag;
    let graffiti_flag_filter = warp::any().map(move || inner_graffiti_flag);

    let inner_ctx = ctx.clone();
    //let log_filter = warp::any().map(move || inner_ctx.log.clone());

    let inner_slot_clock = ctx.slot_clock.clone();
    let slot_clock_filter = warp::any().map(move || inner_slot_clock.clone());

    let inner_spec = ctx.spec.clone();
    let spec_filter = warp::any().map(move || inner_spec.clone());

    let api_token_path_inner = api_token_path.clone();
    let api_token_path_filter = warp::any().map(move || api_token_path_inner.clone());

    // Filter for SEE Logging events
    // let inner_components = ctx.sse_logging_components.clone();
    // let sse_component_filter = warp::any().map(move || inner_components.clone());

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
        .then(|| {
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
        .then(|| {
            blocking_json_task(move || {
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
        .then(|spec: Arc<_>| {
            blocking_json_task(move || {
                let config = ConfigAndPreset::from_chain_spec::<E>(&spec, None);
                Ok(api_types::GenericResponse::from(config))
            })
        });

    // GET lighthouse/validators
    let get_lighthouse_validators = warp::path("lighthouse")
        .and(warp::path("validators"))
        .and(warp::path::end())
        .and(validator_store_filter.clone())
        .then(|validator_store: Arc<ValidatorStore<T, E>>| {
            blocking_json_task(move || {
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
        .then(
            |validator_pubkey: PublicKey, validator_store: Arc<ValidatorStore<T, E>>| {
                blocking_json_task(move || {
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
        .then(|sysinfo, app_start: std::time::Instant, val_dir| {
            blocking_json_task(move || {
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
        .and(graffiti_file_filter.clone())
        .and(graffiti_flag_filter)
        // .and(log_filter.clone())
        .then(
            |validator_store: Arc<ValidatorStore<T, E>>,
             graffiti_file: Option<GraffitiFile>,
             graffiti_flag: Option<Graffiti>| {
                blocking_json_task(move || {
                    let mut result = HashMap::new();
                    for (key, graffiti_definition) in validator_store
                        .initialized_validators()
                        .read()
                        .get_all_validators_graffiti()
                    {
                        let graffiti = determine_graffiti(
                            key,
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

    // GET lighthouse/ui/fallback_health
    let get_lighthouse_ui_fallback_health = warp::path("lighthouse")
        .and(warp::path("ui"))
        .and(warp::path("fallback_health"))
        .and(warp::path::end())
        .and(block_service_filter.clone())
        .then(|block_filter: BlockService<T, E>| async move {
            let mut result: HashMap<String, Vec<CandidateInfo>> = HashMap::new();

            let mut beacon_nodes = Vec::new();
            for node in &*block_filter.beacon_nodes.candidates.read().await {
                beacon_nodes.push(CandidateInfo {
                    index: node.index,
                    endpoint: node.beacon_node.to_string(),
                    health: *node.health.read().await,
                });
            }
            result.insert("beacon_nodes".to_string(), beacon_nodes);

            if let Some(proposer_nodes_list) = &block_filter.proposer_nodes {
                let mut proposer_nodes = Vec::new();
                for node in &*proposer_nodes_list.candidates.read().await {
                    proposer_nodes.push(CandidateInfo {
                        index: node.index,
                        endpoint: node.beacon_node.to_string(),
                        health: *node.health.read().await,
                    });
                }
                result.insert("proposer_nodes".to_string(), proposer_nodes);
            }

            blocking_json_task(move || Ok(api_types::GenericResponse::from(result))).await
        });

    // POST lighthouse/validators/
    let post_validators = warp::path("lighthouse")
        .and(warp::path("validators"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(validator_dir_filter.clone())
        .and(secrets_dir_filter.clone())
        .and(validator_store_filter.clone())
        .and(spec_filter.clone())
        .and(task_executor_filter.clone())
        .then(
            move |body: Vec<api_types::ValidatorRequest>,
                  validator_dir: PathBuf,
                  secrets_dir: PathBuf,
                  validator_store: Arc<ValidatorStore<T, E>>,
                  spec: Arc<ChainSpec>,
                  task_executor: TaskExecutor| {
                blocking_json_task(move || {
                    let secrets_dir = store_passwords_in_secrets_dir.then_some(secrets_dir);
                    if let Some(handle) = task_executor.handle() {
                        let (validators, mnemonic) =
                            handle.block_on(create_validators_mnemonic(
                                None,
                                None,
                                &body,
                                &validator_dir,
                                secrets_dir,
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
        .and(secrets_dir_filter.clone())
        .and(validator_store_filter.clone())
        .and(spec_filter)
        .and(task_executor_filter.clone())
        .then(
            move |body: api_types::CreateValidatorsMnemonicRequest,
                  validator_dir: PathBuf,
                  secrets_dir: PathBuf,
                  validator_store: Arc<ValidatorStore<T, E>>,
                  spec: Arc<ChainSpec>,
                  task_executor: TaskExecutor| {
                blocking_json_task(move || {
                    let secrets_dir = store_passwords_in_secrets_dir.then_some(secrets_dir);
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
                                secrets_dir,
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
        .and(secrets_dir_filter.clone())
        .and(validator_store_filter.clone())
        .and(task_executor_filter.clone())
        .then(
            move |body: api_types::KeystoreValidatorsPostRequest,
                  validator_dir: PathBuf,
                  secrets_dir: PathBuf,
                  validator_store: Arc<ValidatorStore<T, E>>,
                  task_executor: TaskExecutor| {
                blocking_json_task(move || {
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

                    let secrets_dir = store_passwords_in_secrets_dir.then_some(secrets_dir);
                    let password_storage =
                        get_voting_password_storage(&secrets_dir, &body.keystore, &body.password)?;

                    let validator_dir = ValidatorDirBuilder::new(validator_dir.clone())
                        .password_dir_opt(secrets_dir)
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
                    let graffiti = body.graffiti.clone();
                    let suggested_fee_recipient = body.suggested_fee_recipient;
                    let gas_limit = body.gas_limit;
                    let builder_proposals = body.builder_proposals;
                    let builder_boost_factor = body.builder_boost_factor;
                    let prefer_builder_proposals = body.prefer_builder_proposals;

                    let validator_def = {
                        if let Some(handle) = task_executor.handle() {
                            handle
                                .block_on(validator_store.add_validator_keystore(
                                    voting_keystore_path,
                                    password_storage,
                                    body.enable,
                                    graffiti,
                                    suggested_fee_recipient,
                                    gas_limit,
                                    builder_proposals,
                                    builder_boost_factor,
                                    prefer_builder_proposals,
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
        .and(task_executor_filter.clone())
        .then(
            |body: Vec<api_types::Web3SignerValidatorRequest>,
             validator_store: Arc<ValidatorStore<T, E>>,
             task_executor: TaskExecutor| {
                blocking_json_task(move || {
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
                                builder_boost_factor: web3signer.builder_boost_factor,
                                prefer_builder_proposals: web3signer.prefer_builder_proposals,
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
        .and(graffiti_file_filter.clone())
        .and(task_executor_filter.clone())
        .then(
            |validator_pubkey: PublicKey,
             body: api_types::ValidatorPatchRequest,
             validator_store: Arc<ValidatorStore<T, E>>,
             graffiti_file: Option<GraffitiFile>,
             task_executor: TaskExecutor| {
                blocking_json_task(move || {
                    if body.graffiti.is_some() && graffiti_file.is_some() {
                        return Err(warp_utils::reject::custom_bad_request(
                            "Unable to update graffiti as the \"--graffiti-file\" flag is set"
                                .to_string(),
                        ));
                    }

                    let maybe_graffiti = body.graffiti.clone().map(Into::into);
                    let initialized_validators_rw_lock = validator_store.initialized_validators();
                    let initialized_validators = initialized_validators_rw_lock.upgradable_read();

                    // Do not make any changes if all fields are identical or unchanged.
                    fn equal_or_none<T: PartialEq>(
                        current_value: Option<T>,
                        new_value: Option<T>,
                    ) -> bool {
                        new_value.is_none() || current_value == new_value
                    }

                    match (
                        initialized_validators.is_enabled(&validator_pubkey),
                        initialized_validators.validator(&validator_pubkey.compress()),
                    ) {
                        (None, _) => Err(warp_utils::reject::custom_not_found(format!(
                            "no validator for {:?}",
                            validator_pubkey
                        ))),
                        // If all specified parameters match their existing settings, then this
                        // change is a no-op.
                        (Some(is_enabled), Some(initialized_validator))
                            if equal_or_none(Some(is_enabled), body.enabled)
                                && equal_or_none(
                                    initialized_validator.get_gas_limit(),
                                    body.gas_limit,
                                )
                                && equal_or_none(
                                    initialized_validator.get_builder_boost_factor(),
                                    body.builder_boost_factor,
                                )
                                && equal_or_none(
                                    initialized_validator.get_builder_proposals(),
                                    body.builder_proposals,
                                )
                                && equal_or_none(
                                    initialized_validator.get_prefer_builder_proposals(),
                                    body.prefer_builder_proposals,
                                )
                                && equal_or_none(
                                    initialized_validator.get_graffiti(),
                                    maybe_graffiti,
                                ) =>
                        {
                            Ok(())
                        }
                        // Disabling an already disabled validator *with no other changes* is a
                        // no-op.
                        (Some(false), None)
                            if body.enabled.map_or(true, |enabled| !enabled)
                                && body.gas_limit.is_none()
                                && body.builder_boost_factor.is_none()
                                && body.builder_proposals.is_none()
                                && body.prefer_builder_proposals.is_none()
                                && maybe_graffiti.is_none() =>
                        {
                            Ok(())
                        }
                        (Some(_), _) => {
                            // Upgrade read lock only in the case where a write is actually
                            // required.
                            let mut initialized_validators_write =
                                parking_lot::RwLockUpgradableReadGuard::upgrade(
                                    initialized_validators,
                                );
                            if let Some(handle) = task_executor.handle() {
                                handle
                                    .block_on(
                                        initialized_validators_write
                                            .set_validator_definition_fields(
                                                &validator_pubkey,
                                                body.enabled,
                                                body.gas_limit,
                                                body.builder_proposals,
                                                body.builder_boost_factor,
                                                body.prefer_builder_proposals,
                                                body.graffiti,
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
        .and(api_token_path_filter)
        .then(move |token_path: PathBuf| {
            blocking_json_task(move || {
                Ok(AuthResponse {
                    token_path: token_path.display().to_string(),
                })
            })
        });

    // DELETE /lighthouse/keystores
    let delete_lighthouse_keystores = warp::path("lighthouse")
        .and(warp::path("keystores"))
        .and(warp::path::end())
        .and(warp::body::json())
        .and(validator_store_filter.clone())
        .and(task_executor_filter.clone())
        // .and(log_filter.clone())
        .then(move |request, validator_store, task_executor| {
            blocking_json_task(move || {
                if allow_keystore_export {
                    keystores::export(request, validator_store, task_executor)
                } else {
                    Err(warp_utils::reject::custom_bad_request(
                        "keystore export is disabled".to_string(),
                    ))
                }
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
        .then(
            |validator_pubkey: PublicKey, validator_store: Arc<ValidatorStore<T, E>>| {
                blocking_json_task(move || {
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
        .then(
            |validator_pubkey: PublicKey,
             request: api_types::UpdateFeeRecipientRequest,
             validator_store: Arc<ValidatorStore<T, E>>| {
                blocking_json_task(move || {
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
        .then(
            |validator_pubkey: PublicKey, validator_store: Arc<ValidatorStore<T, E>>| {
                blocking_json_task(move || {
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
        .then(
            |validator_pubkey: PublicKey, validator_store: Arc<ValidatorStore<T, E>>| {
                blocking_json_task(move || {
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
        .then(
            |validator_pubkey: PublicKey,
             request: api_types::UpdateGasLimitRequest,
             validator_store: Arc<ValidatorStore<T, E>>| {
                blocking_json_task(move || {
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
        .then(
            |validator_pubkey: PublicKey, validator_store: Arc<ValidatorStore<T, E>>| {
                blocking_json_task(move || {
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

    // POST /eth/v1/validator/{pubkey}/voluntary_exit
    let post_validators_voluntary_exits = eth_v1
        .and(warp::path("validator"))
        .and(warp::path::param::<PublicKey>())
        .and(warp::path("voluntary_exit"))
        .and(warp::query::<api_types::VoluntaryExitQuery>())
        .and(warp::path::end())
        .and(validator_store_filter.clone())
        .and(slot_clock_filter)
        // .and(log_filter.clone())
        .and(task_executor_filter.clone())
        .then(
            |pubkey: PublicKey,
             query: api_types::VoluntaryExitQuery,
             validator_store: Arc<ValidatorStore<T, E>>,
             slot_clock: T,
             task_executor: TaskExecutor| {
                blocking_json_task(move || {
                    if let Some(handle) = task_executor.handle() {
                        let signed_voluntary_exit =
                            handle.block_on(create_signed_voluntary_exit(
                                pubkey,
                                query.epoch,
                                validator_store,
                                slot_clock,
                            ))?;
                        Ok(signed_voluntary_exit)
                    } else {
                        Err(warp_utils::reject::custom_server_error(
                            "Lighthouse shutting down".into(),
                        ))
                    }
                })
            },
        );

    // GET /eth/v1/validator/{pubkey}/graffiti
    let get_graffiti = eth_v1
        .and(warp::path("validator"))
        .and(warp::path::param::<PublicKey>())
        .and(warp::path("graffiti"))
        .and(warp::path::end())
        .and(validator_store_filter.clone())
        .and(graffiti_flag_filter)
        .then(
            |pubkey: PublicKey,
             validator_store: Arc<ValidatorStore<T, E>>,
             graffiti_flag: Option<Graffiti>| {
                blocking_json_task(move || {
                    let graffiti = get_graffiti(pubkey.clone(), validator_store, graffiti_flag)?;
                    Ok(GenericResponse::from(GetGraffitiResponse {
                        pubkey: pubkey.into(),
                        graffiti,
                    }))
                })
            },
        );

    // POST /eth/v1/validator/{pubkey}/graffiti
    let post_graffiti = eth_v1
        .and(warp::path("validator"))
        .and(warp::path::param::<PublicKey>())
        .and(warp::path("graffiti"))
        .and(warp::body::json())
        .and(warp::path::end())
        .and(validator_store_filter.clone())
        .and(graffiti_file_filter.clone())
        .then(
            |pubkey: PublicKey,
             query: SetGraffitiRequest,
             validator_store: Arc<ValidatorStore<T, E>>,
             graffiti_file: Option<GraffitiFile>| {
                blocking_json_task(move || {
                    if graffiti_file.is_some() {
                        return Err(warp_utils::reject::invalid_auth(
                            "Unable to update graffiti as the \"--graffiti-file\" flag is set"
                                .to_string(),
                        ));
                    }
                    set_graffiti(pubkey.clone(), query.graffiti, validator_store)
                })
            },
        )
        .map(|reply| warp::reply::with_status(reply, warp::http::StatusCode::ACCEPTED));

    // DELETE /eth/v1/validator/{pubkey}/graffiti
    let delete_graffiti = eth_v1
        .and(warp::path("validator"))
        .and(warp::path::param::<PublicKey>())
        .and(warp::path("graffiti"))
        .and(warp::path::end())
        .and(validator_store_filter.clone())
        .and(graffiti_file_filter.clone())
        .then(
            |pubkey: PublicKey,
             validator_store: Arc<ValidatorStore<T, E>>,
             graffiti_file: Option<GraffitiFile>| {
                blocking_json_task(move || {
                    if graffiti_file.is_some() {
                        return Err(warp_utils::reject::invalid_auth(
                            "Unable to delete graffiti as the \"--graffiti-file\" flag is set"
                                .to_string(),
                        ));
                    }
                    delete_graffiti(pubkey.clone(), validator_store)
                })
            },
        )
        .map(|reply| warp::reply::with_status(reply, warp::http::StatusCode::NO_CONTENT));

    // GET /eth/v1/keystores
    let get_std_keystores = std_keystores.and(validator_store_filter.clone()).then(
        |validator_store: Arc<ValidatorStore<T, E>>| {
            blocking_json_task(move || Ok(keystores::list(validator_store)))
        },
    );

    // POST /eth/v1/keystores
    let post_std_keystores = std_keystores
        .and(warp::body::json())
        .and(validator_dir_filter)
        .and(secrets_dir_filter)
        .and(validator_store_filter.clone())
        .and(task_executor_filter.clone())
        // .and(log_filter.clone())
        .then(
            move |request, validator_dir, secrets_dir, validator_store, task_executor| {
                let secrets_dir = store_passwords_in_secrets_dir.then_some(secrets_dir);
                blocking_json_task(move || {
                    keystores::import(
                        request,
                        validator_dir,
                        secrets_dir,
                        validator_store,
                        task_executor,
                    )
                })
            },
        );

    // DELETE /eth/v1/keystores
    let delete_std_keystores = std_keystores
        .and(warp::body::json())
        .and(validator_store_filter.clone())
        .and(task_executor_filter.clone())
        // .and(log_filter.clone())
        .then(|request, validator_store, task_executor| {
            blocking_json_task(move || keystores::delete(request, validator_store, task_executor))
        });

    // GET /eth/v1/remotekeys
    let get_std_remotekeys = std_remotekeys.and(validator_store_filter.clone()).then(
        |validator_store: Arc<ValidatorStore<T, E>>| {
            blocking_json_task(move || Ok(remotekeys::list(validator_store)))
        },
    );

    // POST /eth/v1/remotekeys
    let post_std_remotekeys = std_remotekeys
        .and(warp::body::json())
        .and(validator_store_filter.clone())
        .and(task_executor_filter.clone())
        // .and(log_filter.clone())
        .then(|request, validator_store, task_executor| {
            blocking_json_task(move || remotekeys::import(request, validator_store, task_executor))
        });

    // DELETE /eth/v1/remotekeys
    let delete_std_remotekeys = std_remotekeys
        .and(warp::body::json())
        .and(validator_store_filter)
        .and(task_executor_filter)
        // .and(log_filter.clone())
        .then(|request, validator_store, task_executor| {
            blocking_json_task(move || remotekeys::delete(request, validator_store, task_executor))
        });

    // Subscribe to get VC logs via Server side events
    // /lighthouse/logs
    // let get_log_events = warp::path("lighthouse")
    //     .and(warp::path("logs"))
    //     .and(warp::path::end())
    //     // .and(sse_component_filter)
    //     .and_then(|| {
    //         warp_utils::task::blocking_task(move || {
    //             if let Some(logging_components) = sse_component {
    //                 // Build a JSON stream
    //                 let s =
    //                     BroadcastStream::new(logging_components.sender.subscribe()).map(|msg| {
    //                         match msg {
    //                             Ok(data) => {
    //                                 // Serialize to json
    //                                 match data.to_json_string() {
    //                                     // Send the json as a Server Sent Event
    //                                     Ok(json) => Event::default().json_data(json).map_err(|e| {
    //                                         warp_utils::reject::server_sent_event_error(format!(
    //                                             "{:?}",
    //                                             e
    //                                         ))
    //                                     }),
    //                                     Err(e) => Err(warp_utils::reject::server_sent_event_error(
    //                                         format!("Unable to serialize to JSON {}", e),
    //                                     )),
    //                                 }
    //                             }
    //                             Err(e) => Err(warp_utils::reject::server_sent_event_error(
    //                                 format!("Unable to receive event {}", e),
    //                             )),
    //                         }
    //                     });

    //                 Ok::<_, warp::Rejection>(warp::sse::reply(warp::sse::keep_alive().stream(s)))
    //             } else {
    //                 Err(warp_utils::reject::custom_server_error(
    //                     "SSE Logging is not enabled".to_string(),
    //                 ))
    //             }
    //         })
    //     });

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
                        .or(get_lighthouse_ui_fallback_health)
                        .or(get_fee_recipient)
                        .or(get_gas_limit)
                        .or(get_graffiti)
                        .or(get_std_keystores)
                        .or(get_std_remotekeys)
                        .recover(warp_utils::reject::handle_rejection),
                )
                .or(warp::post().and(
                    post_validators
                        .or(post_validators_keystore)
                        .or(post_validators_mnemonic)
                        .or(post_validators_web3signer)
                        .or(post_validators_voluntary_exits)
                        .or(post_fee_recipient)
                        .or(post_gas_limit)
                        .or(post_std_keystores)
                        .or(post_std_remotekeys)
                        .or(post_graffiti)
                        .recover(warp_utils::reject::handle_rejection),
                ))
                .or(warp::patch()
                    .and(patch_validators.recover(warp_utils::reject::handle_rejection)))
                .or(warp::delete().and(
                    delete_lighthouse_keystores
                        .or(delete_fee_recipient)
                        .or(delete_gas_limit)
                        .or(delete_std_keystores)
                        .or(delete_std_remotekeys)
                        .or(delete_graffiti)
                        .recover(warp_utils::reject::handle_rejection),
                )),
        )
        // The auth route and logs  are the only routes that are allowed to be accessed without the API token.
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
        listen_address = listening_socket.to_string(),
        ?api_token_path,
        "HTTP API started"
    );

    Ok((listening_socket, server))
}
