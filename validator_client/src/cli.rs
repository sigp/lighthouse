use std::net::Ipv4Addr;
use clap::{ArgEnum, Args, Subcommand};
pub use clap::{IntoApp, Parser};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(name = "validator_client",
visible_aliases = &["v", "vc", "validator"],
about = "When connected to a beacon node, performs the duties of a staked \
                validator (e.g., proposing blocks and attestations).",)]
pub struct ValidatorClient {
    #[clap(
        long,
        value_name = "NETWORK_ADDRESS",
        help = "Deprecated. Use --beacon-nodes.",
        conflicts_with = "beacon_nodes"
    )]
    pub beacon_node: Option<String>,
    #[clap(
        long,
        value_name = "NETWORK_ADDRESSES",
        help = "Comma-separated addresses to one or more beacon node HTTP APIs. \
                       Default is http://localhost:5052."
    )]
    pub beacon_nodes: Option<String>,
    #[clap(
    long,
    value_name = "NETWORK_ADDRESS",
    help = "Deprecated. Use --beacon-nodes.",
    conflicts_with_all = &["beacon_node", "beacon_nodes"],
    )]
    pub server: Option<String>,
    #[clap(
        long,
        value_name = "VALIDATORS_DIR",
        help = "The directory which contains the validator keystores, deposit data for \
                    each validator along with the common slashing protection database \
                    and the validator_definitions.yml",
        conflicts_with = "datadir"
    )]
    pub validators_dir: Option<PathBuf>,
    #[clap(
        long,
        value_name = "SECRETS_DIRECTORY",
        help = "The directory which contains the password to unlock the validator \
                    voting keypairs. Each password should be contained in a file where the \
                    name is the 0x-prefixed hex representation of the validators voting public \
                    key. Defaults to ~/.lighthouse/{network}/secrets.",
        conflicts_with = "datadir"
    )]
    pub secrets_dir: Option<PathBuf>,
    #[clap(
        long,
        help = "DEPRECATED. This flag does nothing and will be removed in a future release."
    )]
    pub delete_lockfiles: bool,
    #[clap(
        long,
        help = "If present, do not require the slashing protection database to exist before \
                     running. You SHOULD NOT use this flag unless you're certain that a new \
                     slashing protection database is required. Usually, your database \
                     will have been initialized when you imported your validator keys. If you \
                     misplace your database and then run with this flag you risk being slashed."
    )]
    pub init_slashing_protection: bool,
    #[clap(
        long,
        help = "If present, do not attempt to discover new validators in the validators-dir. Validators \
                will need to be manually added to the validator_definitions.yml file."
    )]
    pub disable_auto_discover: bool,
    #[clap(
        long,
        help = "If present, the validator client will still poll for duties if the beacon
                      node is not synced."
    )]
    pub allow_unsynced: bool,
    #[clap(
        long,
        help = "If present, the validator client will use longer timeouts for requests \
                        made to the beacon node. This flag is generally not recommended, \
                        longer timeouts can cause missed duties when fallbacks are used."
    )]
    pub use_long_timeouts: bool,
    #[clap(
        long,
        value_name = "CERTIFICATE-FILES",
        help = "Comma-separated paths to custom TLS certificates to use when connecting \
                        to a beacon node. These certificates must be in PEM format and are used \
                        in addition to the OS trust store. Commas must only be used as a \
                        delimiter, and must not be part of the certificate path."
    )]
    pub beacon_nodes_tls_certs: Option<String>,
    #[clap(
        long,
        help = "Specify your custom graffiti to be included in blocks.",
        value_name = "GRAFFITI"
    )]
    pub graffiti: Option<String>,
    #[clap(
        long,
        help = "Specify a graffiti file to load validator graffitis from.",
        value_name = "GRAFFITI-FILE",
        conflicts_with = "graffiti"
    )]
    pub graffiti_file: Option<PathBuf>,
    #[clap(
        long,
        help = "Enable the RESTful HTTP API server. Disabled by default."
    )]
    pub http: bool,
    #[clap(
        long,
        value_name = "ADDRESS",
        help = "Set the address for the HTTP address. The HTTP server is not encrypted \
                        and therefore it is unsafe to publish on a public network. When this \
                        flag is used, it additionally requires the explicit use of the \
                        `--unencrypted-http-transport` flag to ensure the user is aware of the \
                        risks involved. For access via the Internet, users should apply \
                        transport-layer security like a HTTPS reverse-proxy or SSH tunnelling.",
        requires = "unencrypted_http_transport"
    )]
    pub http_address: Option<Ipv4Addr>,
    #[clap(
        long,
        help = "This is a safety flag to ensure that the user is aware that the http \
                        transport is unencrypted and using a custom HTTP address is unsafe.",
        requires = "http_address"
    )]
    pub unencrypted_http_transport: bool,
    #[clap(
        long,
        value_name = "PORT",
        help = "Set the listen TCP port for the RESTful HTTP API server.",
        default_value = "5062"
    )]
    pub http_port: u16,
    #[clap(
        long,
        value_name = "ORIGIN",
        help = "Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5062)."
    )]
    pub http_allow_origin: Option<String>,
    #[clap(
        long,
        help = "Enable the Prometheus metrics HTTP server. Disabled by default."
    )]
    pub metrics: bool,
    #[clap(
        long,
        value_name = "ADDRESS",
        help = "Set the listen address for the Prometheus metrics HTTP server.",
        default_value = "127.0.0.1"
    )]
    pub metrics_address: Ipv4Addr,
    #[clap(
        long,
        value_name = "PORT",
        help = "Set the listen TCP port for the Prometheus metrics HTTP server.",
        default_value = "5064"
    )]
    pub metrics_port: u16,
    #[clap(
        long,
        value_name = "ORIGIN",
        help = "Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5064)."
    )]
    pub metrics_allow_origin: Option<String>,
    #[clap(
        long,
        value_name = "ADDRESS",
        help = "Enables the monitoring service for sending system metrics to a remote endpoint. \
                This can be used to monitor your setup on certain services (e.g. beaconcha.in). \
                This flag sets the endpoint where the beacon node metrics will be sent. \
                Note: This will send information to a remote sever which may identify and associate your \
                validators, IP address and other personal information. Always use a HTTPS connection \
                and never provide an untrusted URL."
    )]
    pub monitoring_endpoint: Option<String>,
    #[clap(
        long,
        value_name = "ENABLE_DOPPELGANGER_PROTECTION",
        help = "If this flag is set, Lighthouse will delay startup for three epochs and \
                    monitor for messages on the network by any of the validators managed by this \
                    client. This will result in three (possibly four) epochs worth of missed \
                    attestations. If an attestation is detected during this period, it means it is \
                    very likely that you are running a second validator client with the same keys. \
                    This validator client will immediately shutdown if this is detected in order \
                    to avoid potentially committing a slashable offense. Use this flag in order to \
                    ENABLE this functionality, without this flag Lighthouse will begin attesting \
                    immediately."
    )]
    pub enable_doppelganger_protection: bool,
}
