use clap::Arg;
use clap_utils::{flags::*, DefaultConfigApp as App};
use std::collections::HashMap;

pub fn cli_app<'a>(file_args: Option<&'a HashMap<&'a str, &'a str>>) -> App<'a> {
    App::new("validator_client", file_args)
        .visible_aliases(&["v", "vc", "validator"])
        .about(
            "When connected to a beacon node, performs the duties of a staked \
                validator (e.g., proposing blocks and attestations).",
        )
        // This argument is deprecated, use `--beacon-nodes` instead.
        .arg(
            Arg::new(BEACON_NODE_FLAG)
                .long(BEACON_NODE_FLAG)
                .value_name("NETWORK_ADDRESS")
                .help("Deprecated. Use --beacon-nodes.")
                .takes_value(true)
                .conflicts_with("beacon-nodes"),
        )
        .arg(
            Arg::new(BEACON_NODES_FLAG)
                .long(BEACON_NODES_FLAG)
                .value_name("NETWORK_ADDRESSES")
                .help("Comma-separated addresses to one or more beacon node HTTP APIs. \
                       Default is http://localhost:5052."
                )
                .takes_value(true),
        )
        // This argument is deprecated, use `--beacon-nodes` instead.
        .arg(
            Arg::new(SERVER_FLAG)
                .long(SERVER_FLAG)
                .value_name("NETWORK_ADDRESS")
                .help("Deprecated. Use --beacon-nodes.")
                .takes_value(true)
                .conflicts_with_all(&["beacon-node", "beacon-nodes"]),
        )
        .arg(
            Arg::new(VALIDATORS_DIR_FLAG)
                .long(VALIDATORS_DIR_FLAG)
                .value_name("VALIDATORS_DIR")
                .help(
                    "The directory which contains the validator keystores, deposit data for \
                    each validator along with the common slashing protection database \
                    and the validator_definitions.yml"
                )
                .takes_value(true)
                .conflicts_with("datadir")
        )
        .arg(
            Arg::new(SECRETS_DIR_FLAG)
                .long(SECRETS_DIR_FLAG)
                .value_name("SECRETS_DIRECTORY")
                .help(
                    "The directory which contains the password to unlock the validator \
                    voting keypairs. Each password should be contained in a file where the \
                    name is the 0x-prefixed hex representation of the validators voting public \
                    key. Defaults to ~/.lighthouse/{network}/secrets.",
                )
                .takes_value(true)
                .conflicts_with("datadir")
        )
        .arg(
            Arg::new(DELETE_LOCKFILES_FLAG)
            .long(DELETE_LOCKFILES_FLAG)
            .help(
                "DEPRECATED. This flag does nothing and will be removed in a future release."
            )
        )
        .arg(
            Arg::new(INIT_SLASHING_PROTECTION_FLAG)
                .long(INIT_SLASHING_PROTECTION_FLAG)
                .help(
                    "If present, do not require the slashing protection database to exist before \
                     running. You SHOULD NOT use this flag unless you're certain that a new \
                     slashing protection database is required. Usually, your database \
                     will have been initialized when you imported your validator keys. If you \
                     misplace your database and then run with this flag you risk being slashed."
                )
        )
        .arg(
            Arg::new(DISABLE_AUTO_DISCOVER_FLAG)
            .long(DISABLE_AUTO_DISCOVER_FLAG)
            .help(
                "If present, do not attempt to discover new validators in the validators-dir. Validators \
                will need to be manually added to the validator_definitions.yml file."
            )
        )
        .arg(
            Arg::new(ALLOW_UNSYNCED_FLAG)
                .long(ALLOW_UNSYNCED_FLAG)
                .help(
                    "If present, the validator client will still poll for duties if the beacon
                      node is not synced.",
                ),
        )
        .arg(
            Arg::new(USE_LONG_TIMEOUTS_FLAG)
                .long(USE_LONG_TIMEOUTS_FLAG)
                .help("If present, the validator client will use longer timeouts for requests \
                        made to the beacon node. This flag is generally not recommended, \
                        longer timeouts can cause missed duties when fallbacks are used.")
        )
        .arg(
            Arg::new(BEACON_NODES_TLS_CERTS_FLAG)
                .long(BEACON_NODES_TLS_CERTS_FLAG)
                .value_name("CERTIFICATE-FILES")
                .takes_value(true)
                .help("Comma-separated paths to custom TLS certificates to use when connecting \
                        to a beacon node. These certificates must be in PEM format and are used \
                        in addition to the OS trust store. Commas must only be used as a \
                        delimiter, and must not be part of the certificate path.")
        )
        // This overwrites the graffiti configured in the beacon node.
        .arg(
            Arg::new(GRAFFITI_FLAG)
                .long(GRAFFITI_FLAG)
                .help("Specify your custom graffiti to be included in blocks.")
                .value_name("GRAFFITI")
                .takes_value(true)
        )
        .arg(
            Arg::new(GRAFFITI_FILE_FLAG)
                .long(GRAFFITI_FILE_FLAG)
                .help("Specify a graffiti file to load validator graffitis from.")
                .value_name("GRAFFITI-FILE")
                .takes_value(true)
                .conflicts_with("graffiti")
        )
        /* REST API related arguments */
        .arg(
            Arg::new(HTTP_FLAG)
                .long(HTTP_FLAG)
                .help("Enable the RESTful HTTP API server. Disabled by default.")
                .takes_value(false),
        )
        /*
         * Note: The HTTP server is **not** encrypted (i.e., not HTTPS) and therefore it is
         * unsafe to publish on a public network.
         *
         * If the `--http-address` flag is used, the `--unencrypted-http-transport` flag
         * must also be used in order to make it clear to the user that this is unsafe.
         */
         .arg(
             Arg::new(HTTP_ADDRESS_FLAG)
                 .long(HTTP_ADDRESS_FLAG)
                 .value_name("ADDRESS")
                 .help("Set the address for the HTTP address. The HTTP server is not encrypted \
                        and therefore it is unsafe to publish on a public network. When this \
                        flag is used, it additionally requires the explicit use of the \
                        `--unencrypted-http-transport` flag to ensure the user is aware of the \
                        risks involved. For access via the Internet, users should apply \
                        transport-layer security like a HTTPS reverse-proxy or SSH tunnelling.")
                .requires("unencrypted-http-transport"),
         )
         .arg(
             Arg::new(UNENCRYPTED_HTTP_TRANSPORT_FLAG)
                 .long(UNENCRYPTED_HTTP_TRANSPORT_FLAG)
                 .help("This is a safety flag to ensure that the user is aware that the http \
                        transport is unencrypted and using a custom HTTP address is unsafe.")
                 .requires("http-address"),
         )
        .arg(
            Arg::new(HTTP_PORT_FLAG)
                .long(HTTP_PORT_FLAG)
                .value_name("PORT")
                .help("Set the listen TCP port for the RESTful HTTP API server.")
                .default_value("5062")
                .takes_value(true),
        )
        .arg(
            Arg::new(HTTP_ALLOW_ORIGIN_FLAG)
                .long(HTTP_ALLOW_ORIGIN_FLAG)
                .value_name("ORIGIN")
                .help("Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5062).")
                .takes_value(true),
        )
        /* Prometheus metrics HTTP server related arguments */
        .arg(
            Arg::new(METRICS_FLAG)
                .long(METRICS_FLAG)
                .help("Enable the Prometheus metrics HTTP server. Disabled by default.")
                .takes_value(false),
        )
        .arg(
            Arg::new(METRICS_ADDRESS_FLAG)
                .long(METRICS_ADDRESS_FLAG)
                .value_name("ADDRESS")
                .help("Set the listen address for the Prometheus metrics HTTP server.")
                .default_value("127.0.0.1")
                .takes_value(true),
        )
        .arg(
            Arg::new(METRICS_PORT_FLAG)
                .long(METRICS_PORT_FLAG)
                .value_name("PORT")
                .help("Set the listen TCP port for the Prometheus metrics HTTP server.")
                .default_value("5064")
                .takes_value(true),
        )
        .arg(
            Arg::new(METRICS_ALLOW_ORIGIN_FLAG)
                .long(METRICS_ALLOW_ORIGIN_FLAG)
                .value_name("ORIGIN")
                .help("Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5064).")
                .takes_value(true),
        )
        /*
         * Explorer metrics
         */
         .arg(
            Arg::new(MONITORING_ENDPOINT_FLAG)
                .long(MONITORING_ENDPOINT_FLAG)
                .value_name("ADDRESS")
                .help("Enables the monitoring service for sending system metrics to a remote endpoint. \
                This can be used to monitor your setup on certain services (e.g. beaconcha.in). \
                This flag sets the endpoint where the beacon node metrics will be sent. \
                Note: This will send information to a remote sever which may identify and associate your \
                validators, IP address and other personal information. Always use a HTTPS connection \
                and never provide an untrusted URL.")
                .takes_value(true),
        )
        .arg(
            Arg::new(ENABLE_DOPPELGANGER_PROTECTION_FLAG)
                .long(ENABLE_DOPPELGANGER_PROTECTION_FLAG)
                .value_name("ENABLE_DOPPELGANGER_PROTECTION")
                .help("If this flag is set, Lighthouse will delay startup for three epochs and \
                    monitor for messages on the network by any of the validators managed by this \
                    client. This will result in three (possibly four) epochs worth of missed \
                    attestations. If an attestation is detected during this period, it means it is \
                    very likely that you are running a second validator client with the same keys. \
                    This validator client will immediately shutdown if this is detected in order \
                    to avoid potentially committing a slashable offense. Use this flag in order to \
                    ENABLE this functionality, without this flag Lighthouse will begin attesting \
                    immediately.")
                .takes_value(false),
        )
}
