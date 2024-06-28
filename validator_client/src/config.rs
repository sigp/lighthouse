use crate::beacon_node_fallback::ApiTopic;
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
    /// Enables block production via the block v3 endpoint. This configuration option can be removed post deneb.
    pub produce_block_v3: bool,
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
            produce_block_v3: false,
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
    pub fn from_cli(cli_args: &ArgMatches, log: &Logger) -> Result<Config, String> {
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
        if cli_args.get_one::<String>("validators-dir").is_some() {
            validator_dir = Some(parse_required(cli_args, "validators-dir")?);
        }
        if cli_args.get_one::<String>("secrets-dir").is_some() {
            secrets_dir = Some(parse_required(cli_args, "secrets-dir")?);
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

        if let Some(beacon_nodes) = parse_optional::<String>(cli_args, "beacon-nodes")? {
            config.beacon_nodes = beacon_nodes
                .split(',')
                .map(SensitiveUrl::parse)
                .collect::<Result<_, _>>()
                .map_err(|e| format!("Unable to parse beacon node URL: {:?}", e))?;
        }
        if let Some(proposer_nodes) = parse_optional::<String>(cli_args, "proposer_nodes")? {
            config.proposer_nodes = proposer_nodes
                .split(',')
                .map(SensitiveUrl::parse)
                .collect::<Result<_, _>>()
                .map_err(|e| format!("Unable to parse proposer node URL: {:?}", e))?;
        }

        config.disable_auto_discover = cli_args.get_flag("disable-auto-discover");
        config.init_slashing_protection = cli_args.get_flag("init-slashing-protection");
        config.use_long_timeouts = cli_args.get_flag("use-long-timeouts");

        if let Some(graffiti_file_path) = cli_args.get_one::<String>("graffiti-file") {
            let mut graffiti_file = GraffitiFile::new(graffiti_file_path.into());
            graffiti_file
                .read_graffiti_file()
                .map_err(|e| format!("Error reading graffiti file: {:?}", e))?;
            config.graffiti_file = Some(graffiti_file);
            info!(log, "Successfully loaded graffiti file"; "path" => graffiti_file_path);
        }

        if let Some(input_graffiti) = cli_args.get_one::<String>("graffiti") {
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

        if let Some(input_fee_recipient) =
            parse_optional::<Address>(cli_args, "suggested-fee-recipient")?
        {
            config.fee_recipient = Some(input_fee_recipient);
        }

        if let Some(tls_certs) = parse_optional::<String>(cli_args, "beacon-nodes-tls-certs")? {
            config.beacon_nodes_tls_certs = Some(tls_certs.split(',').map(PathBuf::from).collect());
        }

        if cli_args.get_flag("distributed") {
            config.distributed = true;
        }

        if cli_args.get_flag("disable-run-on-all") {
            warn!(
                log,
                "The --disable-run-on-all flag is deprecated";
                "msg" => "please use --broadcast instead"
            );
            config.broadcast_topics = vec![];
        }
        if let Some(broadcast_topics) = cli_args.get_one::<String>("broadcast") {
            config.broadcast_topics = broadcast_topics
                .split(',')
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
        if let Some(s) = parse_optional::<String>(cli_args, "web3-signer-keep-alive-timeout")? {
            config.web3_signer_keep_alive_timeout = if s == "null" {
                None
            } else {
                Some(Duration::from_millis(
                    s.parse().map_err(|_| "invalid timeout value".to_string())?,
                ))
            }
        }
        if let Some(n) = parse_optional::<usize>(cli_args, "web3-signer-max-idle-connections")? {
            config.web3_signer_max_idle_connections = Some(n);
        }

        /*
         * Http API server
         */

        if cli_args.get_flag("http") {
            config.http_api.enabled = true;
        }

        if let Some(address) = cli_args.get_one::<String>("http-address") {
            if cli_args.get_flag("unencrypted-http-transport") {
                config.http_api.listen_addr = address
                    .parse::<IpAddr>()
                    .map_err(|_| "http-address is not a valid IP address.")?;
            } else {
                return Err(
                    "While using `--http-address`, you must also use `--unencrypted-http-transport`."
                        .to_string(),
                );
            }
        }

        if let Some(port) = cli_args.get_one::<String>("http-port") {
            config.http_api.listen_port = port
                .parse::<u16>()
                .map_err(|_| "http-port is not a valid u16.")?;
        }

        if let Some(allow_origin) = cli_args.get_one::<String>("http-allow-origin") {
            // Pre-validate the config value to give feedback to the user on node startup, instead of
            // as late as when the first API response is produced.
            hyper::header::HeaderValue::from_str(allow_origin)
                .map_err(|_| "Invalid allow-origin value")?;

            config.http_api.allow_origin = Some(allow_origin.to_string());
        }

        if cli_args.get_flag("http-allow-keystore-export") {
            config.http_api.allow_keystore_export = true;
        }

        if cli_args.get_flag("http-store-passwords-in-secrets-dir") {
            config.http_api.store_passwords_in_secrets_dir = true;
        }

        /*
         * Prometheus metrics HTTP server
         */

        if cli_args.get_flag("metrics") {
            config.http_metrics.enabled = true;
        }

        if cli_args.get_flag("enable-high-validator-count-metrics") {
            config.enable_high_validator_count_metrics = true;
        }

        if let Some(address) = cli_args.get_one::<String>("metrics-address") {
            config.http_metrics.listen_addr = address
                .parse::<IpAddr>()
                .map_err(|_| "metrics-address is not a valid IP address.")?;
        }

        if let Some(port) = cli_args.get_one::<String>("metrics-port") {
            config.http_metrics.listen_port = port
                .parse::<u16>()
                .map_err(|_| "metrics-port is not a valid u16.")?;
        }

        if let Some(allow_origin) = cli_args.get_one::<String>("metrics-allow-origin") {
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
        if let Some(monitoring_endpoint) = cli_args.get_one::<String>("monitoring-endpoint") {
            let update_period_secs =
                clap_utils::parse_optional(cli_args, "monitoring-endpoint-period")?;
            config.monitoring_api = Some(monitoring_api::Config {
                db_path: None,
                freezer_db_path: None,
                update_period_secs,
                monitoring_endpoint: monitoring_endpoint.to_string(),
            });
        }

        if cli_args.get_flag("enable-doppelganger-protection") {
            config.enable_doppelganger_protection = true;
        }

        if cli_args.get_flag("builder-proposals") {
            config.builder_proposals = true;
        }

        if cli_args.get_flag("produce-block-v3") {
            config.produce_block_v3 = true;
        }

        if cli_args.get_flag("prefer-builder-proposals") {
            config.prefer_builder_proposals = true;
        }

        config.gas_limit = cli_args
            .get_one::<String>("gas-limit")
            .map(|gas_limit| {
                gas_limit
                    .parse::<u64>()
                    .map_err(|_| "gas-limit is not a valid u64.")
            })
            .transpose()?;

        if let Some(registration_timestamp_override) =
            cli_args.get_one::<String>("builder-registration-timestamp-override")
        {
            config.builder_registration_timestamp_override = Some(
                registration_timestamp_override
                    .parse::<u64>()
                    .map_err(|_| "builder-registration-timestamp-override is not a valid u64.")?,
            );
        }

        config.builder_boost_factor = parse_optional(cli_args, "builder-boost-factor")?;

        config.enable_latency_measurement_service =
            !cli_args.get_flag("disable-latency-measurement-service");

        if cli_args
            .get_one::<String>("latency-measurement-service")
            .is_some()
        {
            warn!(
                log,
                "latency-measurement-service flag";
                "note" => "deprecated flag has no effect and should be removed"
            );
        }

        config.validator_registration_batch_size =
            parse_required(cli_args, "validator-registration-batch-size")?;
        if config.validator_registration_batch_size == 0 {
            return Err("validator-registration-batch-size cannot be 0".to_string());
        }

        config.enable_web3signer_slashing_protection =
            if cli_args.get_flag("disable-slashing-protection-web3signer") {
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
