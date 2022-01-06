use crate::graffiti_file::GraffitiFile;
use crate::{http_api, http_metrics};
use clap::ArgMatches;
use clap_utils::flags::*;
use clap_utils::{parse_optional, parse_required};
use directory::{
    get_network_dir, DEFAULT_HARDCODED_NETWORK, DEFAULT_ROOT_DIR, DEFAULT_SECRET_DIR,
    DEFAULT_VALIDATOR_DIR,
};
use eth2::types::Graffiti;
use sensitive_url::SensitiveUrl;
use serde_derive::{Deserialize, Serialize};
use slog::{info, warn, Logger};
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use types::GRAFFITI_BYTES_LEN;

pub const DEFAULT_BEACON_NODE: &str = "http://localhost:5052/";

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
    /// Configuration for the HTTP REST API.
    pub http_api: http_api::Config,
    /// Configuration for the HTTP REST API.
    pub http_metrics: http_metrics::Config,
    /// Configuration for sending metrics to a remote explorer endpoint.
    pub monitoring_api: Option<monitoring_api::Config>,
    /// If true, enable functionality that monitors the network for attestations or proposals from
    /// any of the validators managed by this client before starting up.
    pub enable_doppelganger_protection: bool,
    /// A list of custom certificates that the validator client will additionally use when
    /// connecting to a beacon node over SSL/TLS.
    pub beacon_nodes_tls_certs: Option<Vec<PathBuf>>,
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
            allow_unsynced_beacon_node: false,
            disable_auto_discover: false,
            init_slashing_protection: false,
            use_long_timeouts: false,
            graffiti: None,
            graffiti_file: None,
            http_api: <_>::default(),
            http_metrics: <_>::default(),
            monitoring_api: None,
            enable_doppelganger_protection: false,
            beacon_nodes_tls_certs: None,
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
        if cli_args.value_of(DATADIR_FLAG).is_some() {
            let base_dir: PathBuf = parse_required(cli_args, DATADIR_FLAG)?;
            validator_dir = Some(base_dir.join(DEFAULT_VALIDATOR_DIR));
            secrets_dir = Some(base_dir.join(DEFAULT_SECRET_DIR));
        }
        if cli_args.value_of(VALIDATORS_DIR_FLAG).is_some() {
            validator_dir = Some(parse_required(cli_args, VALIDATORS_DIR_FLAG)?);
        }
        if cli_args.value_of(SECRETS_DIR_FLAG).is_some() {
            secrets_dir = Some(parse_required(cli_args, SECRETS_DIR_FLAG)?);
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

        if let Some(beacon_nodes) = parse_optional::<String>(cli_args, BEACON_NODES_FLAG)? {
            config.beacon_nodes = beacon_nodes
                .split(',')
                .map(SensitiveUrl::parse)
                .collect::<Result<_, _>>()
                .map_err(|e| format!("Unable to parse beacon node URL: {:?}", e))?;
        }
        // To be deprecated.
        else if let Some(beacon_node) = parse_optional::<String>(cli_args, BEACON_NODE_FLAG)? {
            warn!(
                log,
                "The --beacon-node flag is deprecated";
                "msg" => "please use --beacon-nodes instead"
            );
            config.beacon_nodes = vec![SensitiveUrl::parse(&beacon_node)
                .map_err(|e| format!("Unable to parse beacon node URL: {:?}", e))?];
        }
        // To be deprecated.
        else if let Some(server) = parse_optional::<String>(cli_args, SERVER_FLAG)? {
            warn!(
                log,
                "The --server flag is deprecated";
                "msg" => "please use --beacon-nodes instead"
            );
            config.beacon_nodes = vec![SensitiveUrl::parse(&server)
                .map_err(|e| format!("Unable to parse beacon node URL: {:?}", e))?];
        }

        if cli_args.is_present(DELETE_LOCKFILES_FLAG) {
            warn!(
                log,
                "The --delete-lockfiles flag is deprecated";
                "msg" => "it is no longer necessary, and no longer has any effect",
            );
        }

        config.allow_unsynced_beacon_node = cli_args.is_present(ALLOW_UNSYNCED_FLAG);
        config.disable_auto_discover = cli_args.is_present(DISABLE_AUTO_DISCOVER_FLAG);
        config.init_slashing_protection = cli_args.is_present(INIT_SLASHING_PROTECTION_FLAG);
        config.use_long_timeouts = cli_args.is_present(USE_LONG_TIMEOUTS_FLAG);

        if let Some(graffiti_file_path) = cli_args.value_of(GRAFFITI_FILE_FLAG) {
            let mut graffiti_file = GraffitiFile::new(graffiti_file_path.into());
            graffiti_file
                .read_graffiti_file()
                .map_err(|e| format!("Error reading graffiti file: {:?}", e))?;
            config.graffiti_file = Some(graffiti_file);
            info!(log, "Successfully loaded graffiti file"; "path" => graffiti_file_path);
        }

        if let Some(input_graffiti) = cli_args.value_of(GRAFFITI_FLAG) {
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

        if let Some(tls_certs) = parse_optional::<String>(cli_args, BEACON_NODES_TLS_CERTS_FLAG)? {
            config.beacon_nodes_tls_certs = Some(tls_certs.split(',').map(PathBuf::from).collect());
        }

        /*
         * Http API server
         */

        if cli_args.is_present(HTTP_FLAG) {
            config.http_api.enabled = true;
        }

        if let Some(address) = cli_args.value_of(HTTP_ADDRESS_FLAG) {
            if cli_args.is_present(UNENCRYPTED_HTTP_TRANSPORT_FLAG) {
                config.http_api.listen_addr = address
                    .parse::<Ipv4Addr>()
                    .map_err(|_| "http-address is not a valid IPv4 address.")?;
            } else {
                return Err(format!(
                    "While using `--{}`, you must also use `--{}`.",
                    HTTP_ADDRESS_FLAG, UNENCRYPTED_HTTP_TRANSPORT_FLAG
                ));
            }
        }

        if let Some(port) = cli_args.value_of(HTTP_PORT_FLAG) {
            config.http_api.listen_port = port
                .parse::<u16>()
                .map_err(|_| "http-port is not a valid u16.")?;
        }

        if let Some(allow_origin) = cli_args.value_of(HTTP_ALLOW_ORIGIN_FLAG) {
            // Pre-validate the config value to give feedback to the user on node startup, instead of
            // as late as when the first API response is produced.
            hyper::header::HeaderValue::from_str(allow_origin)
                .map_err(|_| "Invalid allow-origin value")?;

            config.http_api.allow_origin = Some(allow_origin.to_string());
        }

        /*
         * Prometheus metrics HTTP server
         */

        if cli_args.is_present(METRICS_FLAG) {
            config.http_metrics.enabled = true;
        }

        if let Some(address) = cli_args.value_of(METRICS_ADDRESS_FLAG) {
            config.http_metrics.listen_addr = address
                .parse::<Ipv4Addr>()
                .map_err(|_| "metrics-address is not a valid IPv4 address.")?;
        }

        if let Some(port) = cli_args.value_of(METRICS_PORT_FLAG) {
            config.http_metrics.listen_port = port
                .parse::<u16>()
                .map_err(|_| "metrics-port is not a valid u16.")?;
        }

        if let Some(allow_origin) = cli_args.value_of(METRICS_ALLOW_ORIGIN_FLAG) {
            // Pre-validate the config value to give feedback to the user on node startup, instead of
            // as late as when the first API response is produced.
            hyper::header::HeaderValue::from_str(allow_origin)
                .map_err(|_| "Invalid allow-origin value")?;

            config.http_metrics.allow_origin = Some(allow_origin.to_string());
        }
        /*
         * Explorer metrics
         */
        if let Some(monitoring_endpoint) = cli_args.value_of(MONITORING_ENDPOINT_FLAG) {
            config.monitoring_api = Some(monitoring_api::Config {
                db_path: None,
                freezer_db_path: None,
                monitoring_endpoint: monitoring_endpoint.to_string(),
            });
        }

        if cli_args.is_present(ENABLE_DOPPELGANGER_PROTECTION_FLAG) {
            config.enable_doppelganger_protection = true;
        }

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
