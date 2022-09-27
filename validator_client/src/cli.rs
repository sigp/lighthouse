use clap::{App, Arg};

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("validator_client")
        .visible_aliases(&["v", "vc", "validator"])
        .setting(clap::AppSettings::ColoredHelp)
        .about(
            "When connected to a beacon node, performs the duties of a staked \
                validator (e.g., proposing blocks and attestations).",
        )
        // This argument is deprecated, use `--beacon-nodes` instead.
        .arg(
            Arg::with_name("beacon-node")
                .long("beacon-node")
                .value_name("NETWORK_ADDRESS")
                .help("Deprecated. Use --beacon-nodes.")
                .takes_value(true)
                .conflicts_with("beacon-nodes"),
        )
        .arg(
            Arg::with_name("beacon-nodes")
                .long("beacon-nodes")
                .value_name("NETWORK_ADDRESSES")
                .help("Comma-separated addresses to one or more beacon node HTTP APIs. \
                       Default is http://localhost:5052."
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("disable-run-on-all")
                .long("disable-run-on-all")
                .value_name("DISABLE_RUN_ON_ALL")
                .help("By default, Lighthouse publishes attestation, sync committee subscriptions \
                       and proposer preparation messages to all beacon nodes provided in the \
                       `--beacon-nodes flag`. This option changes that behaviour such that these \
                       api calls only go out to the first available and synced beacon node")
                .takes_value(false)
        )
        // This argument is deprecated, use `--beacon-nodes` instead.
        .arg(
            Arg::with_name("server")
                .long("server")
                .value_name("NETWORK_ADDRESS")
                .help("Deprecated. Use --beacon-nodes.")
                .takes_value(true)
                .conflicts_with_all(&["beacon-node", "beacon-nodes"]),
        )
        .arg(
            Arg::with_name("validators-dir")
                .long("validators-dir")
                .alias("validator-dir")
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
            Arg::with_name("secrets-dir")
                .long("secrets-dir")
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
            Arg::with_name("delete-lockfiles")
            .long("delete-lockfiles")
            .help(
                "DEPRECATED. This flag does nothing and will be removed in a future release."
            )
        )
        .arg(
            Arg::with_name("init-slashing-protection")
                .long("init-slashing-protection")
                .help(
                    "If present, do not require the slashing protection database to exist before \
                     running. You SHOULD NOT use this flag unless you're certain that a new \
                     slashing protection database is required. Usually, your database \
                     will have been initialized when you imported your validator keys. If you \
                     misplace your database and then run with this flag you risk being slashed."
                )
        )
        .arg(
            Arg::with_name("disable-auto-discover")
            .long("disable-auto-discover")
            .help(
                "If present, do not attempt to discover new validators in the validators-dir. Validators \
                will need to be manually added to the validator_definitions.yml file."
            )
        )
        .arg(
            Arg::with_name("allow-unsynced")
                .long("allow-unsynced")
                .help(
                    "If present, the validator client will still poll for duties if the beacon
                      node is not synced.",
                ),
        )
        .arg(
            Arg::with_name("use-long-timeouts")
                .long("use-long-timeouts")
                .help("If present, the validator client will use longer timeouts for requests \
                        made to the beacon node. This flag is generally not recommended, \
                        longer timeouts can cause missed duties when fallbacks are used.")
        )
        .arg(
            Arg::with_name("beacon-nodes-tls-certs")
                .long("beacon-nodes-tls-certs")
                .value_name("CERTIFICATE-FILES")
                .takes_value(true)
                .help("Comma-separated paths to custom TLS certificates to use when connecting \
                        to a beacon node. These certificates must be in PEM format and are used \
                        in addition to the OS trust store. Commas must only be used as a \
                        delimiter, and must not be part of the certificate path.")
        )
        // This overwrites the graffiti configured in the beacon node.
        .arg(
            Arg::with_name("graffiti")
                .long("graffiti")
                .help("Specify your custom graffiti to be included in blocks.")
                .value_name("GRAFFITI")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("graffiti-file")
                .long("graffiti-file")
                .help("Specify a graffiti file to load validator graffitis from.")
                .value_name("GRAFFITI-FILE")
                .takes_value(true)
                .conflicts_with("graffiti")
        )
        .arg(
            Arg::with_name("suggested-fee-recipient")
                .long("suggested-fee-recipient")
                .help("Once the merge has happened, this address will receive transaction fees \
                       from blocks proposed by this validator client. If a fee recipient is \
                       configured in the validator definitions it takes priority over this value.")
                .value_name("FEE-RECIPIENT")
                .takes_value(true)
        )
        /* REST API related arguments */
        .arg(
            Arg::with_name("http")
                .long("http")
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
             Arg::with_name("http-address")
                 .long("http-address")
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
             Arg::with_name("unencrypted-http-transport")
                 .long("unencrypted-http-transport")
                 .help("This is a safety flag to ensure that the user is aware that the http \
                        transport is unencrypted and using a custom HTTP address is unsafe.")
                 .requires("http-address"),
         )
        .arg(
            Arg::with_name("http-port")
                .long("http-port")
                .value_name("PORT")
                .help("Set the listen TCP port for the RESTful HTTP API server.")
                .default_value("5062")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("http-allow-origin")
                .long("http-allow-origin")
                .value_name("ORIGIN")
                .help("Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5062).")
                .takes_value(true),
        )
        /* Prometheus metrics HTTP server related arguments */
        .arg(
            Arg::with_name("metrics")
                .long("metrics")
                .help("Enable the Prometheus metrics HTTP server. Disabled by default.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("metrics-address")
                .long("metrics-address")
                .value_name("ADDRESS")
                .help("Set the listen address for the Prometheus metrics HTTP server.")
                .default_value("127.0.0.1")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("metrics-port")
                .long("metrics-port")
                .value_name("PORT")
                .help("Set the listen TCP port for the Prometheus metrics HTTP server.")
                .default_value("5064")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("metrics-allow-origin")
                .long("metrics-allow-origin")
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
            Arg::with_name("monitoring-endpoint")
                .long("monitoring-endpoint")
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
            Arg::with_name("monitoring-endpoint-period")
                .long("monitoring-endpoint-period")
                .value_name("SECONDS")
                .help("Defines how many seconds to wait between each message sent to \
                       the monitoring-endpoint. Default: 60s")
                .requires("monitoring-endpoint")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enable-doppelganger-protection")
                .long("enable-doppelganger-protection")
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
        .arg(
            Arg::with_name("builder-proposals")
                .long("builder-proposals")
                .alias("private-tx-proposals")
                .help("If this flag is set, Lighthouse will query the Beacon Node for only block \
                    headers during proposals and will sign over headers. Useful for outsourcing \
                    execution payload construction during proposals.")
                .takes_value(false),
        ).arg(
            Arg::with_name("strict-fee-recipient")
                .long("strict-fee-recipient")
                .help("[DEPRECATED] If this flag is set, Lighthouse will refuse to sign any block whose \
                        `fee_recipient` does not match the `suggested_fee_recipient` sent by this validator. \
                         This applies to both the normal block proposal flow, as well as block proposals \
                         through the builder API. Proposals through the builder API are more likely to have a \
                         discrepancy in `fee_recipient` so you should be aware of how your connected relay \
                         sends proposer payments before using this flag. If this flag is used, a fee recipient \
                         mismatch in the builder API flow will result in a fallback to the local execution engine \
                         for payload construction, where a strict fee recipient check will still be applied.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("builder-registration-timestamp-override")
                .long("builder-registration-timestamp-override")
                .alias("builder-registration-timestamp-override")
                .help("This flag takes a unix timestamp value that will be used to override the \
                    timestamp used in the builder api registration")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("gas-limit")
                .long("gas-limit")
                .value_name("INTEGER")
                .takes_value(true)
                .help("The gas limit to be used in all builder proposals for all validators managed \
                    by this validator client. Note this will not necessarily be used if the gas limit \
                    set here moves too far from the previous block's gas limit. [default: 30,000,000]")
                .requires("builder-proposals"),
    )
}
