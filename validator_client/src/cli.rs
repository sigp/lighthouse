pub use clap::{Arg, ArgAction, Args, Command, FromArgMatches, Parser};
use clap_utils::get_color_style;
use clap_utils::FLAG_HEADER;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use types::Address;

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(
    name = "validator_client",
    visible_aliases = &["v", "vc", "validator"],
    about = "When connected to a beacon node, performs the duties of a staked \
                validator (e.g., proposing blocks and attestations).",
    styles = get_color_style(),
    next_line_help = true,
    term_width = 80,
    disable_help_flag = true,
    disable_help_subcommand = true,
    display_order = 0,
)]
pub struct ValidatorClient {
    #[clap(
        long,
        short = 'h',
        global = true,
        help = "Prints help information",
        action = clap::ArgAction::HelpLong,
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    help: Option<bool>,

    #[clap(
        long,
        value_name = "NETWORK_ADDRESSES",
        value_delimiter = ',',
        help = "Comma-separated addresses to one or more beacon node HTTP APIs. \
                Default is http://localhost:5052.",
        display_order = 0
    )]
    pub beacon_nodes: Option<Vec<String>>,

    #[clap(
        long,
        value_name = "NETWORK_ADDRESSES",
        value_delimiter = ',',
        help = "Comma-separated addresses to one or more beacon node HTTP APIs. \
                These specify nodes that are used to send beacon block proposals. \
                A failure will revert back to the standard beacon nodes specified in --beacon-nodes.",
        display_order = 0
    )]
    pub proposer_nodes: Option<Vec<String>>,

    // TODO remove this flag in a future release
    #[clap(
        long,
        value_name = "DISABLE_RUN_ON_ALL",
        help = "DEPRECATED. Use --broadcast. \
                By default, Lighthouse publishes attestation, sync committee subscriptions \
                and proposer preparation messages to all beacon nodes provided in the \
                `--beacon-nodes flag`. This option changes that behaviour such that these \
                api calls only go out to the first available and synced beacon node.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub disable_run_on_all: bool,

    #[clap(
        long,
        value_name = "API_TOPICS",
        value_delimiter = ',',
        help = "Comma-separated list of beacon API topics to broadcast to all beacon nodes. \
                Possible values are: none, attestations, blocks, subscriptions, \
                sync-committee. Default (when flag is omitted) is to broadcast \
                subscriptions only.",
        display_order = 0
    )]
    pub broadcast: Option<Vec<String>>,

    #[clap(
        long,
        value_name = "VALIDATORS_DIR",
        conflicts_with = "datadir",
        help = "The directory which contains the validator keystores, deposit data for \
                each validator along with the common slashing protection database \
                and the validator_definitions.yml",
        display_order = 0
    )]
    pub validators_dir: Option<PathBuf>,

    #[clap(
        long,
        value_name = "SECRETS_DIRECTORY",
        conflicts_with = "datadir",
        help = "The directory which contains the password to unlock the validator \
                voting keypairs. Each password should be contained in a file where the \
                name is the 0x-prefixed hex representation of the validators voting public \
                key. Defaults to ~/.lighthouse/{network}/secrets.",
        display_order = 0
    )]
    pub secrets_dir: Option<PathBuf>,

    #[clap(
        long,
        help = "If present, do not require the slashing protection database to exist before \
                running. You SHOULD NOT use this flag unless you're certain that a new \
                slashing protection database is required. Usually, your database \
                will have been initialized when you imported your validator keys. If you \
                misplace your database and then run with this flag you risk being slashed.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub init_slashing_protection: bool,

    #[clap(
        long,
        help = "If present, do not attempt to discover new validators in the validators-dir. Validators \
                will need to be manually added to the validator_definitions.yml file.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub disable_auto_discover: bool,

    #[clap(
        long,
        help = "If present, the validator client will use longer timeouts for requests \
                made to the beacon node. This flag is generally not recommended, \
                longer timeouts can cause missed duties when fallbacks are used.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub use_long_timeouts: bool,

    #[clap(
        long,
        value_name = "CERTIFICATE-FILES",
        value_delimiter = ',',
        help = "Comma-separated paths to custom TLS certificates to use when connecting \
                to a beacon node (and/or proposer node). These certificates must be in PEM format and are used \
                in addition to the OS trust store. Commas must only be used as a \
                delimiter, and must not be part of the certificate path.",
        display_order = 0
    )]
    pub beacon_nodes_tls_certs: Option<Vec<String>>,

    // This overwrites the graffiti configured in the beacon node.
    #[clap(
        long,
        value_name = "GRAFFITI",
        help = "Specify your custom graffiti to be included in blocks.",
        display_order = 0
    )]
    pub graffiti: Option<String>,

    #[clap(
        long,
        value_name = "GRAFFITI-FILE",
        conflicts_with = "graffiti",
        help = "Specify a graffiti file to load validator graffitis from.",
        display_order = 0
    )]
    pub graffiti_file: Option<PathBuf>,

    #[clap(
        long,
        value_name = "FEE-RECIPIENT",
        help = "Once the merge has happened, this address will receive transaction fees \
                from blocks proposed by this validator client. If a fee recipient is \
                configured in the validator definitions it takes priority over this value.",
        display_order = 0
    )]
    pub suggested_fee_recipient: Option<Address>,

    #[clap(
        long,
        help = "This flag is deprecated and is no longer in use.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub produce_block_v3: bool,

    #[clap(
        long,
        help = "Enables functionality required for running the validator in a distributed validator cluster.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub distributed: bool,

    /* REST API related arguments */
    #[clap(
        long,
        help = "Enable the RESTful HTTP API server. Disabled by default.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub http: bool,

    /*
     * Note: The HTTP server is **not** encrypted (i.e., not HTTPS) and therefore it is
     * unsafe to publish on a public network.
     *
     * If the `--http-address` flag is used, the `--unencrypted-http-transport` flag
     * must also be used in order to make it clear to the user that this is unsafe.
     */
    #[clap(
        long,
        value_name = "ADDRESS",
        requires = "unencrypted_http_transport",
        help = "Set the address for the HTTP address. The HTTP server is not encrypted \
                and therefore it is unsafe to publish on a public network. When this \
                flag is used, it additionally requires the explicit use of the \
                `--unencrypted-http-transport` flag to ensure the user is aware of the \
                risks involved. For access via the Internet, users should apply \
                transport-layer security like a HTTPS reverse-proxy or SSH tunnelling.",
        display_order = 0
    )]
    pub http_address: Option<IpAddr>,

    #[clap(
        long,
        requires = "http_address",
        help = "This is a safety flag to ensure that the user is aware that the http \
                transport is unencrypted and using a custom HTTP address is unsafe.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub unencrypted_http_transport: bool,

    #[clap(
        long,
        value_name = "PORT",
        default_value_t = 5062,
        help = "Set the listen TCP port for the RESTful HTTP API server.",
        display_order = 0
    )]
    pub http_port: u16,

    #[clap(
        long,
        value_name = "ORIGIN",
        help = "Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5062).",
        display_order = 0
    )]
    pub http_allow_origin: Option<String>,

    #[clap(
        long,
        requires = "http",
        help = "If present, allow access to the DELETE /lighthouse/keystores HTTP \
                API method, which allows exporting keystores and passwords to HTTP API \
                consumers who have access to the API token. This method is useful for \
                exporting validators, however it should be used with caution since it \
                exposes private key data to authorized users.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub http_allow_keystore_export: bool,

    #[clap(
        long,
        requires = "http",
        help = "If present, any validators created via the HTTP will have keystore \
                passwords stored in the secrets-dir rather than the validator \
                definitions file.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub http_store_passwords_in_secrets_dir: bool,

    /* Prometheus metrics HTTP server related arguments */
    #[clap(
        long,
        help = "Enable the Prometheus metrics HTTP server. Disabled by default.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub metrics: bool,

    #[clap(
        long,
        value_name = "ADDRESS",
        default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST),
        help = "Set the listen address for the Prometheus metrics HTTP server.",
        display_order = 0

    )]
    pub metrics_address: IpAddr,

    #[clap(
        long,
        value_name = "PORT",
        default_value_t = 5064,
        help = "Set the listen TCP port for the Prometheus metrics HTTP server.",
        display_order = 0
    )]
    pub metrics_port: u16,

    #[clap(
        long,
        value_name = "ORIGIN",
        help = "Set the value of the Access-Control-Allow-Origin response HTTP header. \
                Use * to allow any origin (not recommended in production). \
                If no value is supplied, the CORS allowed origin is set to the listen \
                address of this server (e.g., http://localhost:5064).",
        display_order = 0
    )]
    pub metrics_allow_origin: Option<String>,

    #[clap(
        long,
        help = "Enable per validator metrics for > 64 validators. \
                Note: This flag is automatically enabled for <= 64 validators. \
                Enabling this metric for higher validator counts will lead to higher volume \
                of prometheus metrics being collected.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub enable_high_validator_count_metrics: bool,

    /* Explorer metrics */
    #[clap(
        long,
        value_name = "ADDRESS",
        help = "Enables the monitoring service for sending system metrics to a remote endpoint. \
                This can be used to monitor your setup on certain services (e.g. beaconcha.in). \
                This flag sets the endpoint where the beacon node metrics will be sent. \
                Note: This will send information to a remote sever which may identify and associate your \
                validators, IP address and other personal information. Always use a HTTPS connection \
                and never provide an untrusted URL.",
        display_order = 0
    )]
    pub monitoring_endpoint: Option<String>,

    #[clap(
        long,
        value_name = "SECONDS",
        requires = "monitoring_endpoint",
        default_value_t = 60,
        help = "Defines how many seconds to wait between each message sent to \
                the monitoring-endpoint.",
        display_order = 0
    )]
    pub monitoring_endpoint_period: u64,

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
                immediately.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub enable_doppelganger_protection: bool,

    #[clap(
        long,
        alias = "private-tx-proposals",
        help = "If this flag is set, Lighthouse will query the Beacon Node for only block \
                headers during proposals and will sign over headers. Useful for outsourcing \
                execution payload construction during proposals.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub builder_proposals: bool,

    #[clap(
        long,
        value_name = "UNIX-TIMESTAMP",
        help = "This flag takes a unix timestamp value that will be used to override the \
                timestamp used in the builder api registration.",
        display_order = 0
    )]
    pub builder_registration_timestamp_override: Option<u64>,

    #[clap(
        long,
        value_name = "INTEGER",
        default_value_t = 30_000_000,
        help = "The gas limit to be used in all builder proposals for all validators managed \
                by this validator client. Note this will not necessarily be used if the gas limit \
                set here moves too far from the previous block's gas limit.",
        display_order = 0
    )]
    pub gas_limit: u64,

    #[clap(
        long,
        value_name = "BOOLEAN",
        help = "Disables the service that periodically attempts to measure latency to BNs.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub disable_latency_measurement_service: bool,

    #[clap(
        long,
        value_name = "BOOLEAN",
        help = "Disables the service that periodically attempts to measure latency to BNs.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub latency_measurement_service: bool,

    #[clap(
        long,
        value_name = "INTEGER",
        default_value_t = 500,
        help = "Defines the number of validators per \
                validator/register_validator request sent to the BN. This value \
                can be reduced to avoid timeouts from builders.",
        display_order = 0
    )]
    pub validator_registration_batch_size: usize,

    #[clap(
        long,
        value_name = "UINT64",
        help = "Defines the boost factor, \
                a percentage multiplier to apply to the builder's payload value \
                when choosing between a builder payload header and payload from \
                the local execution node.",
        display_order = 0
    )]
    pub builder_boost_factor: Option<u64>,

    #[clap(
        long,
        help = "If this flag is set, Lighthouse will always prefer blocks \
                constructed by builders, regardless of payload value.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub prefer_builder_proposals: bool,

    #[clap(
        long,
        help = "Disable Lighthouse's slashing protection for all web3signer keys. This can \
                reduce the I/O burden on the VC but is only safe if slashing protection \
                is enabled on the remote signer and is implemented correctly. DO NOT ENABLE \
                THIS FLAG UNLESS YOU ARE CERTAIN THAT SLASHING PROTECTION IS ENABLED ON \
                THE REMOTE SIGNER. YOU WILL GET SLASHED IF YOU USE THIS FLAG WITHOUT \
                ENABLING WEB3SIGNER'S SLASHING PROTECTION.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub disable_slashing_protection_web3signer: bool,

    /*  Experimental/development options */
    #[clap(
        long,
        value_name = "MILLIS",
        default_value_t = 20000,
        help = "Keep-alive timeout for each web3signer connection. Set to '0' to never \
                timeout.",
        display_order = 0
    )]
    pub web3_signer_keep_alive_timeout: u64,

    #[clap(
        long,
        value_name = "COUNT",
        help = "Maximum number of idle connections to maintain per web3signer host. Default \
                is unlimited.",
        display_order = 0
    )]
    pub web3_signer_max_idle_connections: Option<usize>,
}
