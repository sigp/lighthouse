use clap::{App, Arg};

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("validator_client")
        .visible_aliases(&["v", "vc", "validator"])
        .setting(clap::AppSettings::ColoredHelp)
        .about(
            "When connected to a beacon node, performs the duties of a staked \
                validator (e.g., proposing blocks and attestations).",
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
            Arg::with_name("proposer-nodes")
                .long("proposer-nodes")
                .value_name("NETWORK_ADDRESSES")
                .help("Comma-separated addresses to one or more beacon node HTTP APIs. \
                These specify nodes that are used to send beacon block proposals. A failure will revert back to the standard beacon nodes specified in --beacon-nodes."
                )
                .takes_value(true),
        )
        // TODO remove this flag in a future release
        .arg(
            Arg::with_name("disable-run-on-all")
                .long("disable-run-on-all")
                .value_name("DISABLE_RUN_ON_ALL")
                .help("DEPRECATED. Use --broadcast. \
                       By default, Lighthouse publishes attestation, sync committee subscriptions \
                       and proposer preparation messages to all beacon nodes provided in the \
                       `--beacon-nodes flag`. This option changes that behaviour such that these \
                       api calls only go out to the first available and synced beacon node")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("broadcast")
                .long("broadcast")
                .value_name("API_TOPICS")
                .help("Comma-separated list of beacon API topics to broadcast to all beacon nodes. \
                       Possible values are: none, attestations, blocks, subscriptions, \
                       sync-committee. Default (when flag is omitted) is to broadcast \
                       subscriptions only."
                )
                .takes_value(true),
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
                        to a beacon node (and/or proposer node). These certificates must be in PEM format and are used \
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
        .arg(
            Arg::with_name("produce-block-v3")
                .long("produce-block-v3")
                .help("Enable block production via the block v3 endpoint for this validator client. \
                       This should only be enabled when paired with a beacon node \
                       that has this endpoint implemented. This flag will be enabled by default in \
                       future.")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("distributed")
                .long("distributed")
                .help("Enables functionality required for running the validator in a distributed validator cluster.")
                .takes_value(false)
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
                 .requires("http")
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
                .requires("http")
                .value_name("PORT")
                .help("Set the listen TCP port for the RESTful HTTP API server.")
                .default_value_if("http", None, "5062")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("http-allow-origin")
                .long("http-allow-origin")
                .requires("http")
                .value_name("ORIGIN")
                .help("Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5062).")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("http-allow-keystore-export")
                .long("http-allow-keystore-export")
                .requires("http")
                .help("If present, allow access to the DELETE /lighthouse/keystores HTTP \
                    API method, which allows exporting keystores and passwords to HTTP API \
                    consumers who have access to the API token. This method is useful for \
                    exporting validators, however it should be used with caution since it \
                    exposes private key data to authorized users.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("http-store-passwords-in-secrets-dir")
                .long("http-store-passwords-in-secrets-dir")
                .requires("http")
                .help("If present, any validators created via the HTTP will have keystore \
                    passwords stored in the secrets-dir rather than the validator \
                    definitions file.")
                .takes_value(false),
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
                .requires("metrics")
                .value_name("ADDRESS")
                .help("Set the listen address for the Prometheus metrics HTTP server.")
                .default_value_if("metrics", None, "127.0.0.1")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("metrics-port")
                .long("metrics-port")
                .requires("metrics")
                .value_name("PORT")
                .help("Set the listen TCP port for the Prometheus metrics HTTP server.")
                .default_value_if("metrics", None, "5064")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("metrics-allow-origin")
                .long("metrics-allow-origin")
                .requires("metrics")
                .value_name("ORIGIN")
                .help("Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5064).")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enable-high-validator-count-metrics")
                .long("enable-high-validator-count-metrics")
                .help("Enable per validator metrics for > 64 validators. \
                    Note: This flag is automatically enabled for <= 64 validators. \
                    Enabling this metric for higher validator counts will lead to higher volume \
                    of prometheus metrics being collected.")
                .takes_value(false),
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
        .arg(
            Arg::with_name("latency-measurement-service")
                .long("latency-measurement-service")
                .value_name("BOOLEAN")
                .help("Set to 'true' to enable a service that periodically attempts to measure latency to BNs. \
                    Set to 'false' to disable.")
                .default_value("true")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("validator-registration-batch-size")
                .long("validator-registration-batch-size")
                .value_name("INTEGER")
                .help("Defines the number of validators per \
                    validator/register_validator request sent to the BN. This value \
                    can be reduced to avoid timeouts from builders.")
                .default_value("500")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("builder-boost-factor")
                .long("builder-boost-factor")
                .value_name("UINT64")
                .help("Defines the boost factor, \
                    a percentage multiplier to apply to the builder's payload value \
                    when choosing between a builder payload header and payload from \
                    the local execution node.")
                .conflicts_with("prefer-builder-proposals")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("prefer-builder-proposals")
                .long("prefer-builder-proposals")
                .help("If this flag is set, Lighthouse will always prefer blocks \
                    constructed by builders, regardless of payload value.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("disable-slashing-protection-web3signer")
                .long("disable-slashing-protection-web3signer")
                .help("Disable Lighthouse's slashing protection for all web3signer keys. This can \
                       reduce the I/O burden on the VC but is only safe if slashing protection \
                       is enabled on the remote signer and is implemented correctly. DO NOT ENABLE \
                       THIS FLAG UNLESS YOU ARE CERTAIN THAT SLASHING PROTECTION IS ENABLED ON \
                       THE REMOTE SIGNER. YOU WILL GET SLASHED IF YOU USE THIS FLAG WITHOUT \
                       ENABLING WEB3SIGNER'S SLASHING PROTECTION.")
                .takes_value(false)
        )
        /*
         * Experimental/development options.
         */
        .arg(
            Arg::with_name("web3-signer-keep-alive-timeout")
                .long("web3-signer-keep-alive-timeout")
                .value_name("MILLIS")
                .default_value("90000")
                .help("Keep-alive timeout for each web3signer connection. Set to 'null' to never \
                       timeout")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("web3-signer-max-idle-connections")
                .long("web3-signer-max-idle-connections")
                .value_name("COUNT")
                .help("Maximum number of idle connections to maintain per web3signer host. Default \
                       is unlimited.")
                .takes_value(true),
        )
}
