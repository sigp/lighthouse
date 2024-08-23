use crate::beacon_node_fallback::ApiTopic;
use crate::cli::ValidatorClient;
use crate::graffiti_file::GraffitiFile;
use crate::{http_api, http_metrics};
use clap::ArgMatches;
use clap_utils::{flags::DISABLE_MALLOC_TUNING_FLAG, parse_optional, parse_required};
use directory::{
    get_network_dir, DEFAULT_HARDCODED_NETWORK, DEFAULT_ROOT_DIR, DEFAULT_SECRET_DIR,
    DEFAULT_VALIDATOR_DIR,
};
use eth2::types::Graffiti;
use sensitive_url::SensitiveUrl;
use serde::{Deserialize, Serialize};
use slog::{info, warn, Logger};
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;
use types::{Address, GRAFFITI_BYTES_LEN};

pub const DEFAULT_BEACON_NODE: &str = "http://localhost:5052/";
pub const DEFAULT_WEB3SIGNER_KEEP_ALIVE: Option<Duration> = Some(Duration::from_secs(20));

/// Stores the core configuration for this validator instance.
#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    /// The data directory, which stores all validator databases
    pub validator_dir: PathBuf,
    /// The directory containing the passwords to unlock validator keystores.
    pub secrets_dir: PathBuf,
    /// The http endpoints of the beacon node APIs.
    ///
    /// Should be similar to `["http://localhost:8080"]`
    pub beacon_nodes: Vec<SensitiveUrl>,
    /// An optional beacon node used for block proposals only.
    pub proposer_nodes: Vec<SensitiveUrl>,
    /// If true, the validator client will still poll for duties and produce blocks even if the
    /// beacon node is not synced at startup.
    pub allow_unsynced_beacon_node: bool,
    /// If true, don't scan the validators dir for new keystores.
    pub disable_auto_discover: bool,
    /// If true, re-register existing validators in definitions.yml for slashing protection.
    pub init_slashing_protection: bool,
    /// If true, use longer timeouts for requests made to the beacon node.
    pub use_long_timeouts: bool,
    /// Graffiti to be inserted everytime we create a block.
    pub graffiti: Option<Graffiti>,
    /// Graffiti file to load per validator graffitis.
    pub graffiti_file: Option<GraffitiFile>,
    /// Fallback fallback address.
    pub fee_recipient: Option<Address>,
    /// Configuration for the HTTP REST API.
    pub http_api: http_api::Config,
    /// Configuration for the HTTP REST API.
    pub http_metrics: http_metrics::Config,
    /// Configuration for sending metrics to a remote explorer endpoint.
    pub monitoring_api: Option<monitoring_api::Config>,
    /// If true, enable functionality that monitors the network for attestations or proposals from
    /// any of the validators managed by this client before starting up.
    pub enable_doppelganger_protection: bool,
    /// If true, then we publish validator specific metrics (e.g next attestation duty slot)
    /// for all our managed validators.
    /// Note: We publish validator specific metrics for low validator counts without this flag
    /// (<= 64 validators)
    pub enable_high_validator_count_metrics: bool,
    /// Enable use of the blinded block endpoints during proposals.
    pub builder_proposals: bool,
    /// Overrides the timestamp field in builder api ValidatorRegistrationV1
    pub builder_registration_timestamp_override: Option<u64>,
    /// Fallback gas limit.
    pub gas_limit: Option<u64>,
    /// A list of custom certificates that the validator client will additionally use when
    /// connecting to a beacon node over SSL/TLS.
    pub beacon_nodes_tls_certs: Option<Vec<PathBuf>>,
    /// Enables broadcasting of various requests (by topic) to all beacon nodes.
    pub broadcast_topics: Vec<ApiTopic>,
    /// Enables a service which attempts to measure latency between the VC and BNs.
    pub enable_latency_measurement_service: bool,
    /// Defines the number of validators per `validator/register_validator` request sent to the BN.
    pub validator_registration_batch_size: usize,
    /// Enable slashing protection even while using web3signer keys.
    pub enable_web3signer_slashing_protection: bool,
    /// Specifies the boost factor, a percentage multiplier to apply to the builder's payload value.
    pub builder_boost_factor: Option<u64>,
    /// If true, Lighthouse will prefer builder proposals, if available.
    pub prefer_builder_proposals: bool,
    /// Whether we are running with distributed network support.
    pub distributed: bool,
    pub web3_signer_keep_alive_timeout: Option<Duration>,
    pub web3_signer_max_idle_connections: Option<usize>,
}

impl Default for Config {
    /// Build a new configuration from defaults.
    fn default() -> Self {
        // WARNING: these directory defaults should be always overwritten with parameters from cli
        // for specific networks.
        let base_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_ROOT_DIR)
            .join(DEFAULT_HARDCODED_NETWORK);
        let validator_dir = base_dir.join(DEFAULT_VALIDATOR_DIR);
        let secrets_dir = base_dir.join(DEFAULT_SECRET_DIR);

        let beacon_nodes = vec![SensitiveUrl::parse(DEFAULT_BEACON_NODE)
            .expect("beacon_nodes must always be a valid url.")];
        Self {
            validator_dir,
            secrets_dir,
            beacon_nodes,
            proposer_nodes: Vec::new(),
            allow_unsynced_beacon_node: false,
            disable_auto_discover: false,
            init_slashing_protection: false,
            use_long_timeouts: false,
            graffiti: None,
            graffiti_file: None,
            fee_recipient: None,
            http_api: <_>::default(),
            http_metrics: <_>::default(),
            monitoring_api: None,
            enable_doppelganger_protection: false,
            enable_high_validator_count_metrics: false,
            beacon_nodes_tls_certs: None,
            builder_proposals: false,
            builder_registration_timestamp_override: None,
            gas_limit: None,
            broadcast_topics: vec![ApiTopic::Subscriptions],
            enable_latency_measurement_service: true,
            validator_registration_batch_size: 500,
            enable_web3signer_slashing_protection: true,
            builder_boost_factor: None,
            prefer_builder_proposals: false,
            distributed: false,
            web3_signer_keep_alive_timeout: DEFAULT_WEB3SIGNER_KEEP_ALIVE,
            web3_signer_max_idle_connections: None,
        }
    }
}

impl Config {
    /// Returns a `Default` implementation of `Self` with some parameters modified by the supplied
    /// `cli_args`.
    pub fn from_cli(
        cli_args: &ArgMatches,
        validator_client_config: &ValidatorClient,
        log: &Logger,
    ) -> Result<Config, String> {
        let mut config = Config::default();

        let default_root_dir = dirs::home_dir()
            .map(|home| home.join(DEFAULT_ROOT_DIR))
            .unwrap_or_else(|| PathBuf::from("."));

        let (mut validator_dir, mut secrets_dir) = (None, None);
        if cli_args.get_one::<String>("datadir").is_some() {
            let base_dir: PathBuf = parse_required(cli_args, "datadir")?;
            validator_dir = Some(base_dir.join(DEFAULT_VALIDATOR_DIR));
            secrets_dir = Some(base_dir.join(DEFAULT_SECRET_DIR));
        }

        if let Some(validator_dir_path) = validator_client_config.validator_dir.as_ref() {
            validator_dir = Some(validator_dir_path.clone());
        }
        if let Some(secrets_dir_path) = validator_client_config.secrets_dir.as_ref() {
            secrets_dir = Some(secrets_dir_path.clone());
        }

        config.validator_dir = validator_dir.unwrap_or_else(|| {
            default_root_dir
                .join(get_network_dir(cli_args))
                .join(DEFAULT_VALIDATOR_DIR)
        });

        config.secrets_dir = secrets_dir.unwrap_or_else(|| {
            default_root_dir
                .join(get_network_dir(cli_args))
                .join(DEFAULT_SECRET_DIR)
        });

        if !config.validator_dir.exists() {
            fs::create_dir_all(&config.validator_dir)
                .map_err(|e| format!("Failed to create {:?}: {:?}", config.validator_dir, e))?;
        }

        if let Some(beacon_nodes) = validator_client_config.beacon_nodes.as_ref() {
            config.beacon_nodes = beacon_nodes
                .iter()
                .map(|s| SensitiveUrl::parse(s).unwrap())
                .collect::<Vec<_>>();
        }

        if let Some(proposer_nodes) = validator_client_config.proposer_nodes.as_ref() {
            config.proposer_nodes = proposer_nodes
                .iter()
                .map(|s| SensitiveUrl::parse(s).unwrap())
                .collect::<Vec<_>>();
        }

        config.disable_auto_discover = validator_client_config.disable_auto_discover;
        config.init_slashing_protection = validator_client_config.init_slashing_protection;
        config.use_long_timeouts = validator_client_config.use_long_timeouts;

        if let Some(graffiti_file_path) = validator_client_config.graffiti_file.as_ref() {
            let mut graffiti_file = GraffitiFile::new(graffiti_file_path.into());
            graffiti_file
                .read_graffiti_file()
                .map_err(|e| format!("Error reading graffiti file: {:?}", e))?;
            config.graffiti_file = Some(graffiti_file);
            info!(log, "Successfully loaded graffiti file"; "path" => graffiti_file_path.to_str());
        }

        if let Some(input_graffiti) = validator_client_config.graffiti.as_ref() {
            let graffiti_bytes = input_graffiti.as_bytes();
            if graffiti_bytes.len() > GRAFFITI_BYTES_LEN {
                return Err(format!(
                    "Your graffiti is too long! {} bytes maximum!",
                    GRAFFITI_BYTES_LEN
                ));
            } else {
                let mut graffiti = [0; 32];

                // Copy the provided bytes over.
                //
                // Panic-free because `graffiti_bytes.len()` <= `GRAFFITI_BYTES_LEN`.
                graffiti[..graffiti_bytes.len()].copy_from_slice(graffiti_bytes);

                config.graffiti = Some(graffiti.into());
            }
        }

        if let Some(input_fee_recipient) = validator_client_config.suggested_fee_recipient {
            config.fee_recipient = Some(input_fee_recipient);
        }

        if let Some(tls_certs) = validator_client_config.beacon_nodes_tls_certs.as_ref() {
            config.beacon_nodes_tls_certs = Some(tls_certs.iter().map(PathBuf::from).collect());
        }

        if let Some(tls_certs) = parse_optional::<String>(cli_args, "beacon-nodes-tls-certs")? {
            config.beacon_nodes_tls_certs = Some(tls_certs.split(',').map(PathBuf::from).collect());
        }

        config.distributed = validator_client_config.distributed;

        if validator_client_config.disable_run_on_all {
            warn!(
                log,
                "The --disable-run-on-all flag is deprecated";
                "msg" => "please use --broadcast instead"
            );
            config.broadcast_topics = vec![];
        }

        if let Some(broadcast_topics) = validator_client_config.broadcast.as_ref() {
            config.broadcast_topics = broadcast_topics
                .iter()
                .filter(|t| *t != "none")
                .map(|t| {
                    t.trim()
                        .parse::<ApiTopic>()
                        .map_err(|_| format!("Unknown API topic to broadcast: {t}"))
                })
                .collect::<Result<_, _>>()?;
        }

        /*
         * Web3 signer
         */
        if validator_client_config.web3_signer_keep_alive_timeout == 0 {
            config.web3_signer_keep_alive_timeout = None
        } else {
            config.web3_signer_keep_alive_timeout = Some(Duration::from_millis(
                validator_client_config.web3_signer_keep_alive_timeout,
            ));
        }

        if let Some(n) = validator_client_config.web3_signer_max_idle_connections {
            config.web3_signer_max_idle_connections = Some(n);
        }

        /*
         * Http API server
         */

        config.http_api.enabled = validator_client_config.http;

        if let Some(address) = validator_client_config.http_address {
            if validator_client_config.unencrypted_http_transport {
                config.http_api.listen_addr = IpAddr::V4(address);
            } else {
                return Err(
                    "While using `--http-address`, you must also use `--unencrypted-http-transport`."
                        .to_string(),
                );
            }
        }

        config.http_api.listen_port = validator_client_config.http_port;

        if let Some(allow_origin) = validator_client_config.http_allow_origin.as_ref() {
            // Pre-validate the config value to give feedback to the user on node startup, instead of
            // as late as when the first API response is produced.
            hyper::header::HeaderValue::from_str(allow_origin)
                .map_err(|_| "Invalid allow-origin value")?;

            config.http_api.allow_origin = Some(allow_origin.to_string());
        }

        config.http_api.allow_keystore_export = validator_client_config.http_allow_keystore_export;
        config.http_api.store_passwords_in_secrets_dir =
            validator_client_config.http_store_passwords_in_secrets_dir;
        /*
         * Prometheus metrics HTTP server
         */

        config.http_metrics.enabled = validator_client_config.metrics;
        config.enable_high_validator_count_metrics =
            validator_client_config.enable_high_validator_count_metrics;
        config.http_metrics.listen_addr = IpAddr::V4(validator_client_config.metrics_address);
        config.http_metrics.listen_port = validator_client_config.metrics_port;

        if let Some(allow_origin) = validator_client_config.metrics_allow_origin.as_ref() {
            // Pre-validate the config value to give feedback to the user on node startup, instead of
            // as late as when the first API response is produced.
            hyper::header::HeaderValue::from_str(allow_origin)
                .map_err(|_| "Invalid allow-origin value")?;

            config.http_metrics.allow_origin = Some(allow_origin.to_string());
        }

        if cli_args.get_flag(DISABLE_MALLOC_TUNING_FLAG) {
            config.http_metrics.allocator_metrics_enabled = false;
        }

        /*
         * Explorer metrics
         */
        if let Some(monitoring_endpoint) = validator_client_config.monitoring_endpoint.as_ref() {
            let update_period_secs = Some(validator_client_config.monitoring_endpoint_period);
            config.monitoring_api = Some(monitoring_api::Config {
                db_path: None,
                freezer_db_path: None,
                update_period_secs,
                monitoring_endpoint: monitoring_endpoint.to_string(),
            });
        }

        config.enable_doppelganger_protection =
            validator_client_config.enable_doppelganger_protection;
        config.builder_proposals = validator_client_config.builder_proposals;

        if validator_client_config.produce_block_v3 {
            warn!(
                log,
                "produce-block-v3 flag";
                "note" => "deprecated flag has no effect and should be removed"
            );
        }

        config.gas_limit = Some(validator_client_config.gas_limit);

        config.builder_registration_timestamp_override =
            validator_client_config.builder_registration_timestamp_override;

        config.builder_boost_factor = validator_client_config.builder_boost_factor;
        config.enable_latency_measurement_service =
            !validator_client_config.disable_latency_measurement_service;
        config.validator_registration_batch_size =
            validator_client_config.validator_registration_batch_size;

        if config.validator_registration_batch_size == 0 {
            return Err("validator-registration-batch-size cannot be 0".to_string());
        }

        config.enable_web3signer_slashing_protection =
            if validator_client_config.disable_slashing_protection_web3signer {
                warn!(
                    log,
                    "Slashing protection for remote keys disabled";
                    "info" => "ensure slashing protection on web3signer is enabled or you WILL \
                            get slashed"
                );
                false
            } else {
                true
            };

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Ensures the default config does not panic.
    fn default_config() {
        Config::default();
    }
}
