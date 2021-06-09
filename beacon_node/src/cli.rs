use clap::{App, Arg};

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("beacon_node")
        .visible_aliases(&["b", "bn", "beacon"])
        .version(crate_version!())
        .author("Sigma Prime <contact@sigmaprime.io>")
        .setting(clap::AppSettings::ColoredHelp)
        .about("The primary component which connects to the Ethereum 2.0 P2P network and \
                downloads, verifies and stores blocks. Provides a HTTP API for querying \
                the beacon chain and publishing messages to the network.")
        /*
         * Configuration directory locations.
         */
        .arg(
            Arg::with_name("network-dir")
                .long("network-dir")
                .value_name("DIR")
                .help("Data directory for network keys. Defaults to network/ inside the beacon node \
                       dir.")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("freezer-dir")
                .long("freezer-dir")
                .value_name("DIR")
                .help("Data directory for the freezer database.")
                .takes_value(true)
        )
        /*
         * Network parameters.
         */
        .arg(
            Arg::with_name("subscribe-all-subnets")
                .long("subscribe-all-subnets")
                .help("Subscribe to all subnets regardless of validator count. \
                       This will also advertise the beacon node as being long-lived subscribed to all subnets.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("import-all-attestations")
                .long("import-all-attestations")
                .help("Import and aggregate all attestations, regardless of validator subscriptions. \
                       This will only import attestations from already-subscribed subnets, use with \
                       --subscribe-all-subnets to ensure all attestations are received for import.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("zero-ports")
                .long("zero-ports")
                .short("z")
                .help("Sets all listening TCP/UDP ports to 0, allowing the OS to choose some \
                       arbitrary free ports.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("listen-address")
                .long("listen-address")
                .value_name("ADDRESS")
                .help("The address lighthouse will listen for UDP and TCP connections.")
                .default_value("0.0.0.0")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .value_name("PORT")
                .help("The TCP/UDP port to listen on. The UDP port can be modified by the --discovery-port flag.")
                .default_value("9000")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("discovery-port")
                .long("discovery-port")
                .value_name("PORT")
                .help("The UDP port that discovery will listen on. Defaults to `port`")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("target-peers")
                .long("target-peers")
                .help("The target number of peers.")
                .default_value("50")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("boot-nodes")
                .long("boot-nodes")
                .allow_hyphen_values(true)
                .value_name("ENR/MULTIADDR LIST")
                .help("One or more comma-delimited base64-encoded ENR's to bootstrap the p2p network. Multiaddr is also supported.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("disable-upnp")
                .long("disable-upnp")
                .help("Disables UPnP support. Setting this will prevent Lighthouse from attempting to automatically establish external port mappings.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("private")
                .long("private")
                .help("Prevents sending various client identification information.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("enr-udp-port")
                .long("enr-udp-port")
                .value_name("PORT")
                .help("The UDP port of the local ENR. Set this only if you are sure other nodes can connect to your local node on this port.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enr-tcp-port")
                .long("enr-tcp-port")
                .value_name("PORT")
                .help("The TCP port of the local ENR. Set this only if you are sure other nodes can connect to your local node on this port.\
                    The --port flag is used if this is not set.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enr-address")
                .long("enr-address")
                .value_name("ADDRESS")
                .help("The IP address/ DNS address to broadcast to other peers on how to reach this node. \
                If a DNS address is provided, the enr-address is set to the IP address it resolves to and \
                does not auto-update based on PONG responses in discovery. \
                Set this only if you are sure other nodes can connect to your local node on this address. \
                Discovery will automatically find your external address,if possible.")
                .requires("enr-udp-port")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enr-match")
                .short("e")
                .long("enr-match")
                .help("Sets the local ENR IP address and port to match those set for lighthouse. \
                Specifically, the IP address will be the value of --listen-address and the UDP port will be --discovery-port.")
        )
        .arg(
            Arg::with_name("disable-enr-auto-update")
                .short("x")
                .long("disable-enr-auto-update")
                .help("Discovery automatically updates the nodes local ENR with an external IP address and port as seen by other peers on the network. \
                This disables this feature, fixing the ENR's IP/PORT to those specified on boot."),
        )
        .arg(
            Arg::with_name("libp2p-addresses")
                .long("libp2p-addresses")
                .value_name("MULTIADDR")
                .help("One or more comma-delimited multiaddrs to manually connect to a libp2p peer \
                       without an ENR.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("disable-discovery")
                .long("disable-discovery")
                .help("Disables the discv5 discovery protocol. The node will not search for new peers or participate in the discovery protocol.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("trusted-peers")
                .long("trusted-peers")
                .value_name("TRUSTED_PEERS")
                .help("One or more comma-delimited trusted peer ids which always have the highest score according to the peer scoring system.")
                .takes_value(true),
        )
        /* REST API related arguments */
        .arg(
            Arg::with_name("http")
                .long("http")
                .help("Enable the RESTful HTTP API server. Disabled by default.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("http-address")
                .long("http-address")
                .value_name("ADDRESS")
                .help("Set the listen address for the RESTful HTTP API server.")
                .default_value("127.0.0.1")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("http-port")
                .long("http-port")
                .value_name("PORT")
                .help("Set the listen TCP port for the RESTful HTTP API server.")
                .default_value("5052")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("http-allow-origin")
                .long("http-allow-origin")
                .value_name("ORIGIN")
                .help("Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5052).")
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
                .default_value("5054")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("metrics-allow-origin")
                .long("metrics-allow-origin")
                .value_name("ORIGIN")
                .help("Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5054).")
                .takes_value(true),
        )

        /*
         * Monitoring metrics
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

        /*
         * Standard staking flags
         */

        .arg(
            Arg::with_name("staking")
                .long("staking")
                .help("Standard option for a staking beacon node. Equivalent to \
                `lighthouse bn --http --eth1 `. This will enable the http server on localhost:5052 \
                and try connecting to an eth1 node on localhost:8545")
                .takes_value(false)
        )

        /*
         * Eth1 Integration
         */
        .arg(
            Arg::with_name("eth1")
                .long("eth1")
                .help("If present the node will connect to an eth1 node. This is required for \
                       block production, you must use this flag if you wish to serve a validator.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("dummy-eth1")
                .long("dummy-eth1")
                .conflicts_with("eth1")
                .help("If present, uses an eth1 backend that generates static dummy data.\
                      Identical to the method used at the 2019 Canada interop.")
        )
        .arg(
            Arg::with_name("eth1-endpoint")
                .long("eth1-endpoint")
                .value_name("HTTP-ENDPOINT")
                .help("Deprecated. Use --eth1-endpoints.")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("eth1-endpoints")
                .long("eth1-endpoints")
                .value_name("HTTP-ENDPOINTS")
                .conflicts_with("eth1-endpoint")
                .help("One or more comma-delimited server endpoints for web3 connection. \
                       If multiple endpoints are given the endpoints are used as fallback in the \
                       given order. Also enables the --eth1 flag. \
                       Defaults to http://127.0.0.1:8545.")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("eth1-purge-cache")
                .long("eth1-purge-cache")
                .value_name("PURGE-CACHE")
                .help("Purges the eth1 block and deposit caches")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("eth1-blocks-per-log-query")
                .long("eth1-blocks-per-log-query")
                .value_name("BLOCKS")
                .help("Specifies the number of blocks that a deposit log query should span. \
                    This will reduce the size of responses from the Eth1 endpoint.")
                .default_value("1000")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("slots-per-restore-point")
                .long("slots-per-restore-point")
                .value_name("SLOT_COUNT")
                .help("Specifies how often a freezer DB restore point should be stored. \
                       Cannot be changed after initialization. \
                       [default: 2048 (mainnet) or 64 (minimal)]")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("block-cache-size")
                .long("block-cache-size")
                .value_name("SIZE")
                .help("Specifies how many blocks the database should cache in memory [default: 5]")
                .takes_value(true)
        )

        /*
         * Database purging and compaction.
         */
        .arg(
            Arg::with_name("purge-db")
                .long("purge-db")
                .help("If present, the chain database will be deleted. Use with caution.")
        )
        .arg(
            Arg::with_name("compact-db")
                .long("compact-db")
                .help("If present, apply compaction to the database on start-up. Use with caution. \
                       It is generally not recommended unless auto-compaction is disabled.")
        )
        .arg(
            Arg::with_name("auto-compact-db")
                .long("auto-compact-db")
                .help("Enable or disable automatic compaction of the database on finalization.")
                .takes_value(true)
                .default_value("true")
        )

        /*
         * Misc.
         */
        .arg(
            Arg::with_name("graffiti")
                .long("graffiti")
                .help(
                    "Specify your custom graffiti to be included in blocks. \
                    Defaults to the current version and commit, truncated to fit in 32 bytes. "
                )
                .value_name("GRAFFITI")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("max-skip-slots")
                .long("max-skip-slots")
                .help(
                    "Refuse to skip more than this many slots when processing a block or attestation. \
                    This prevents nodes on minority forks from wasting our time and disk space, \
                    but could also cause unnecessary consensus failures, so is disabled by default."
                )
                .value_name("NUM_SLOTS")
                .takes_value(true)
        )
        /*
         * Slasher.
         */
        .arg(
            Arg::with_name("slasher")
                .long("slasher")
                .help(
                    "Run a slasher alongside the beacon node. It is currently only recommended for \
                     expert users because of the immaturity of the slasher UX and the extra \
                     resources required."
                )
                .takes_value(false)
        )
        .arg(
            Arg::with_name("slasher-dir")
                .long("slasher-dir")
                .help(
                    "Set the slasher's database directory."
                )
                .value_name("PATH")
                .takes_value(true)
                .requires("slasher")
        )
        .arg(
            Arg::with_name("slasher-update-period")
                .long("slasher-update-period")
                .help(
                    "Configure how often the slasher runs batch processing."
                )
                .value_name("SECONDS")
                .requires("slasher")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("slasher-history-length")
                .long("slasher-history-length")
                .help(
                    "Configure how many epochs of history the slasher keeps. Immutable after \
                     initialization."
                )
                .value_name("EPOCHS")
                .requires("slasher")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("slasher-max-db-size")
                .long("slasher-max-db-size")
                .help(
                    "Maximum size of the LMDB database used by the slasher."
                )
                .value_name("GIGABYTES")
                .requires("slasher")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("slasher-chunk-size")
                .long("slasher-chunk-size")
                .help(
                    "Number of epochs per validator per chunk stored on disk."
                )
                .value_name("EPOCHS")
                .requires("slasher")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("slasher-validator-chunk-size")
                .long("slasher-validator-chunk-size")
                .help(
                    "Number of validators per chunk stored on disk."
                )
                .value_name("NUM_VALIDATORS")
                .requires("slasher")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("slasher-broadcast")
                .long("slasher-broadcast")
                .help("Broadcast slashings found by the slasher to the rest of the network \
                       [disabled by default].")
                .requires("slasher")
        )
        .arg(
            Arg::with_name("wss-checkpoint")
                .long("wss-checkpoint")
                .help(
                    "Used to input a Weak Subjectivity State Checkpoint in `block_root:epoch_number` format,\
                     where block_root is an '0x' prefixed 32-byte hex string and epoch_number is an integer."
                )
                .value_name("WSS_CHECKPOINT")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("validator-monitor-auto")
                .long("validator-monitor-auto")
                .help("Enables the automatic detection and monitoring of validators connected to the \
                    HTTP API and using the subnet subscription endpoint. This generally has the \
                    effect of providing additional logging and metrics for locally controlled \
                    validators.")
        )
        .arg(
            Arg::with_name("validator-monitor-pubkeys")
                .long("validator-monitor-pubkeys")
                .help("A comma-separated list of 0x-prefixed validator public keys. \
                        These validators will receive special monitoring and additional \
                        logging.")
                .value_name("PUBKEYS")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("validator-monitor-file")
                .long("validator-monitor-file")
                .help("As per --validator-monitor-pubkeys, but the comma-separated list is \
                    contained within a file at the given path.")
                .value_name("PATH")
                .takes_value(true)
        )
}
