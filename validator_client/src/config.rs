use crate::graffiti_file::GraffitiFile;
use crate::{http_api, http_metrics, ValidatorClient};
use clap::ArgMatches;
use clap_utils::{GlobalConfig, parse_optional, parse_required};
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
    pub fn from_cli(validator_config: &ValidatorClient, global_config: &GlobalConfig, log: &Logger) -> Result<Config, String> {
        let mut config = Config::default();

        let default_root_dir = dirs::home_dir()
            .map(|home| home.join(DEFAULT_ROOT_DIR))
            .unwrap_or_else(|| PathBuf::from("."));

        let (mut validator_dir, mut secrets_dir) = (None, None);
        if let Some(base_dir) = global_config.datadir.as_ref() {
            validator_dir = Some(base_dir.join(DEFAULT_VALIDATOR_DIR));
            secrets_dir = Some(base_dir.join(DEFAULT_SECRET_DIR));
        }

        validator_dir = validator_config.validators_dir.clone();
        secrets_dir = validator_config.secrets_dir.clone();

        config.validator_dir = validator_dir.unwrap_or_else(|| {
            default_root_dir
                .join(get_network_dir(global_config))
                .join(DEFAULT_VALIDATOR_DIR)
        });

        config.secrets_dir = secrets_dir.unwrap_or_else(|| {
            default_root_dir
                .join(get_network_dir(global_config))
                .join(DEFAULT_SECRET_DIR)
        });

        if !config.validator_dir.exists() {
            fs::create_dir_all(&config.validator_dir)
                .map_err(|e| format!("Failed to create {:?}: {:?}", config.validator_dir, e))?;
        }

        if let Some(beacon_nodes) = validator_config.beacon_nodes.as_ref() {
            config.beacon_nodes = beacon_nodes
                .split(',')
                .map(SensitiveUrl::parse)
                .collect::<Result<_, _>>()
                .map_err(|e| format!("Unable to parse beacon node URL: {:?}", e))?;
        }
        // To be deprecated.
        else if let Some(beacon_node) = validator_config.beacon_node.as_ref() {
            warn!(
                log,
                "The --beacon-node flag is deprecated";
                "msg" => "please use --beacon-nodes instead"
            );
            config.beacon_nodes = vec![SensitiveUrl::parse(&beacon_node)
                .map_err(|e| format!("Unable to parse beacon node URL: {:?}", e))?];
        }
        // To be deprecated.
        else if let Some(server) = validator_config.beacon_node.as_ref() {
            warn!(
                log,
                "The --server flag is deprecated";
                "msg" => "please use --beacon-nodes instead"
            );
            config.beacon_nodes = vec![SensitiveUrl::parse(&server)
                .map_err(|e| format!("Unable to parse beacon node URL: {:?}", e))?];
        }

        if validator_config.delete_lockfiles {
            warn!(
                log,
                "The --delete-lockfiles flag is deprecated";
                "msg" => "it is no longer necessary, and no longer has any effect",
            );
        }

        config.allow_unsynced_beacon_node = validator_config.allow_unsynced;
        config.disable_auto_discover = validator_config.disable_auto_discover;
        config.init_slashing_protection = validator_config.init_slashing_protection;
        config.use_long_timeouts = validator_config.use_long_timeouts;

        if let Some(graffiti_file_path) = validator_config.graffiti_file.as_ref() {
            let mut graffiti_file = GraffitiFile::new(graffiti_file_path.into());
            graffiti_file
                .read_graffiti_file()
                .map_err(|e| format!("Error reading graffiti file: {:?}", e))?;
            config.graffiti_file = Some(graffiti_file);
            info!(log, "Successfully loaded graffiti file"; "path" => ?graffiti_file_path);
        }

        if let Some(input_graffiti) = validator_config.graffiti.as_ref() {
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

        if let Some(tls_certs) = validator_config.beacon_nodes_tls_certs.as_ref() {
            config.beacon_nodes_tls_certs = Some(tls_certs.split(',').map(PathBuf::from).collect());
        }

        /*
         * Http API server
         */
            config.http_api.enabled = validator_config.http;

        if let Some(address) = validator_config.http_address.clone() {
            config.http_api.listen_addr = address;
        }

            config.http_api.listen_port = validator_config.http_port;

        if let Some(allow_origin) = validator_config.http_allow_origin.as_ref() {
            // Pre-validate the config value to give feedback to the user on node startup, instead of
            // as late as when the first API response is produced.
            hyper::header::HeaderValue::from_str(allow_origin)
                .map_err(|_| "Invalid allow-origin value")?;

            config.http_api.allow_origin = Some(allow_origin.to_string());
        }

        /*
         * Prometheus metrics HTTP server
         */
            config.http_metrics.enabled = validator_config.metrics;
        config.http_metrics.listen_addr = validator_config.metrics_address.clone();
        config.http_metrics.listen_port = validator_config.metrics_port;

        if let Some(allow_origin) = validator_config.metrics_allow_origin.as_ref() {
            // Pre-validate the config value to give feedback to the user on node startup, instead of
            // as late as when the first API response is produced.
            hyper::header::HeaderValue::from_str(allow_origin)
                .map_err(|_| "Invalid allow-origin value")?;

            config.http_metrics.allow_origin = Some(allow_origin.to_string());
        }
        /*
         * Explorer metrics
         */
        if let Some(monitoring_endpoint) = validator_config.monitoring_endpoint.clone() {
            config.monitoring_api = Some(monitoring_api::Config {
                db_path: None,
                freezer_db_path: None,
                monitoring_endpoint,
            });
        }

            config.enable_doppelganger_protection = validator_config.enable_doppelganger_protection;

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
