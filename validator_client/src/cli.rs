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
        /* REST API related arguments */
        .arg(
            Arg::with_name("http")
                .long("http")
                .help("Enable the RESTful HTTP API server. Disabled by default.")
                .takes_value(false),
        )
        /*
         * Note: there is purposefully no `--http-address` flag provided.
         *
         * The HTTP server is **not** encrypted (i.e., not HTTPS) and therefore it is unsafe to
         * publish on a public network.
         *
         * We restrict the user to `127.0.0.1` and they must provide some other transport-layer
         * encryption (e.g., SSH tunnels).
         */
        .arg(
            Arg::with_name("http-port")
                .long("http-port")
                .value_name("PORT")
                .help("Set the listen TCP port for the RESTful HTTP API server. This server does **not** \
                provide encryption and is completely unsuitable to expose to a public network. \
                We do not provide a --http-address flag and restrict the user to listening on \
                127.0.0.1. For access via the Internet, apply a transport-layer security like \
                a HTTPS reverse-proxy or SSH tunnelling.")
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
}
