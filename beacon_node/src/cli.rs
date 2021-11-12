use clap::{App, Arg};

pub fn cli_app<'a>() -> App<'a> {
    App::new("beacon_node")
        .visible_aliases(&["b", "bn", "beacon"])
        .version(crate_version!())
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("The primary component which connects to the Ethereum 2.0 P2P network and \
                downloads, verifies and stores blocks. Provides a HTTP API for querying \
                the beacon chain and publishing messages to the network.")
        /*
         * Configuration directory locations.
         */
        .arg(
            Arg::new("network-dir")
                .long("network-dir")
                .value_name("DIR")
                .about("Data directory for network keys. Defaults to network/ inside the beacon node \
                       dir.")
                .takes_value(true)
        )
        .arg(
            Arg::new("freezer-dir")
                .long("freezer-dir")
                .value_name("DIR")
                .about("Data directory for the freezer database.")
                .takes_value(true)
        )
        /*
         * Network parameters.
         */
        .arg(
            Arg::new("subscribe-all-subnets")
                .long("subscribe-all-subnets")
                .about("Subscribe to all subnets regardless of validator count. \
                       This will also advertise the beacon node as being long-lived subscribed to all subnets.")
                .takes_value(false),
        )
        .arg(
            Arg::new("import-all-attestations")
                .long("import-all-attestations")
                .about("Import and aggregate all attestations, regardless of validator subscriptions. \
                       This will only import attestations from already-subscribed subnets, use with \
                       --subscribe-all-subnets to ensure all attestations are received for import.")
                .takes_value(false),
        )
        .arg(
            Arg::new("disable-packet-filter")
                .long("disable-packet-filter")
                .about("Disables the discovery packet filter. Useful for testing in smaller networks")
                .takes_value(false),
        )
        .arg(
            Arg::new("shutdown-after-sync")
                .long("shutdown-after-sync")
                .about("Shutdown beacon node as soon as sync is completed. Backfill sync will \
                       not be performed before shutdown.")
                .takes_value(false),
        )
        .arg(
            Arg::new("zero-ports")
                .long("zero-ports")
                .short('z')
                .about("Sets all listening TCP/UDP ports to 0, allowing the OS to choose some \
                       arbitrary free ports.")
                .takes_value(false),
        )
        .arg(
            Arg::new("listen-address")
                .long("listen-address")
                .value_name("ADDRESS")
                .about("The address lighthouse will listen for UDP and TCP connections.")
                .default_value("0.0.0.0")
                .takes_value(true)
        )
        .arg(
            Arg::new("port")
                .long("port")
                .value_name("PORT")
                .about("The TCP/UDP port to listen on. The UDP port can be modified by the --discovery-port flag.")
                .default_value("9000")
                .takes_value(true),
        )
        .arg(
            Arg::new("discovery-port")
                .long("discovery-port")
                .value_name("PORT")
                .about("The UDP port that discovery will listen on. Defaults to `port`")
                .takes_value(true),
        )
        .arg(
            Arg::new("target-peers")
                .long("target-peers")
                .about("The target number of peers.")
                .default_value("50")
                .takes_value(true),
        )
        .arg(
            Arg::new("boot-nodes")
                .long("boot-nodes")
                .allow_hyphen_values(true)
                .value_name("ENR/MULTIADDR LIST")
                .about("One or more comma-delimited base64-encoded ENR's to bootstrap the p2p network. Multiaddr is also supported.")
                .takes_value(true),
        )
        .arg(
            Arg::new("disable-upnp")
                .long("disable-upnp")
                .about("Disables UPnP support. Setting this will prevent Lighthouse from attempting to automatically establish external port mappings.")
                .takes_value(false),
        )
        .arg(
            Arg::new("private")
                .long("private")
                .about("Prevents sending various client identification information.")
                .takes_value(false),
        )
        .arg(
            Arg::new("enr-udp-port")
                .long("enr-udp-port")
                .value_name("PORT")
                .about("The UDP port of the local ENR. Set this only if you are sure other nodes can connect to your local node on this port.")
                .takes_value(true),
        )
        .arg(
            Arg::new("enr-tcp-port")
                .long("enr-tcp-port")
                .value_name("PORT")
                .about("The TCP port of the local ENR. Set this only if you are sure other nodes can connect to your local node on this port.\
                    The --port flag is used if this is not set.")
                .takes_value(true),
        )
        .arg(
            Arg::new("enr-address")
                .long("enr-address")
                .value_name("ADDRESS")
                .about("The IP address/ DNS address to broadcast to other peers on how to reach this node. \
                If a DNS address is provided, the enr-address is set to the IP address it resolves to and \
                does not auto-update based on PONG responses in discovery. \
                Set this only if you are sure other nodes can connect to your local node on this address. \
                Discovery will automatically find your external address,if possible.")
                .requires("enr-udp-port")
                .takes_value(true),
        )
        .arg(
            Arg::new("enr-match")
                .short('e')
                .long("enr-match")
                .about("Sets the local ENR IP address and port to match those set for lighthouse. \
                Specifically, the IP address will be the value of --listen-address and the UDP port will be --discovery-port.")
        )
        .arg(
            Arg::new("disable-enr-auto-update")
                .short('x')
                .long("disable-enr-auto-update")
                .about("Discovery automatically updates the nodes local ENR with an external IP address and port as seen by other peers on the network. \
                This disables this feature, fixing the ENR's IP/PORT to those specified on boot."),
        )
        .arg(
            Arg::new("libp2p-addresses")
                .long("libp2p-addresses")
                .value_name("MULTIADDR")
                .about("One or more comma-delimited multiaddrs to manually connect to a libp2p peer \
                       without an ENR.")
                .takes_value(true),
        )
        .arg(
            Arg::new("disable-discovery")
                .long("disable-discovery")
                .about("Disables the discv5 discovery protocol. The node will not search for new peers or participate in the discovery protocol.")
                .takes_value(false),
        )
        .arg(
            Arg::new("trusted-peers")
                .long("trusted-peers")
                .value_name("TRUSTED_PEERS")
                .about("One or more comma-delimited trusted peer ids which always have the highest score according to the peer scoring system.")
                .takes_value(true),
        )
        /* REST API related arguments */
        .arg(
            Arg::new("http")
                .long("http")
                .about("Enable the RESTful HTTP API server. Disabled by default.")
                .takes_value(false),
        )
        .arg(
            Arg::new("http-address")
                .long("http-address")
                .value_name("ADDRESS")
                .about("Set the listen address for the RESTful HTTP API server.")
                .default_value("127.0.0.1")
                .takes_value(true),
        )
        .arg(
            Arg::new("http-port")
                .long("http-port")
                .value_name("PORT")
                .about("Set the listen TCP port for the RESTful HTTP API server.")
                .default_value("5052")
                .takes_value(true),
        )
        .arg(
            Arg::new("http-allow-origin")
                .long("http-allow-origin")
                .value_name("ORIGIN")
                .about("Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5052).")
                .takes_value(true),
        )
        .arg(
            Arg::new("http-disable-legacy-spec")
                .long("http-disable-legacy-spec")
                .about("Disable serving of legacy data on the /config/spec endpoint. May be \
                       disabled by default in a future release.")
        )
        .arg(
            Arg::new("http-enable-tls")
                .long("http-enable-tls")
                .about("Serves the RESTful HTTP API server over TLS. This feature is currently \
                    experimental.")
                .takes_value(false)
                .requires("http-tls-cert")
                .requires("http-tls-key")
        )
        .arg(
            Arg::new("http-tls-cert")
                .long("http-tls-cert")
                .about("The path of the certificate to be used when serving the HTTP API server \
                    over TLS.")
                .takes_value(true)
        )
        .arg(
            Arg::new("http-tls-key")
                .long("http-tls-key")
                .about("The path of the private key to be used when serving the HTTP API server \
                    over TLS. Must not be password-protected.")
                .takes_value(true)
        )
        /* Prometheus metrics HTTP server related arguments */
        .arg(
            Arg::new("metrics")
                .long("metrics")
                .about("Enable the Prometheus metrics HTTP server. Disabled by default.")
                .takes_value(false),
        )
        .arg(
            Arg::new("metrics-address")
                .long("metrics-address")
                .value_name("ADDRESS")
                .about("Set the listen address for the Prometheus metrics HTTP server.")
                .default_value("127.0.0.1")
                .takes_value(true),
        )
        .arg(
            Arg::new("metrics-port")
                .long("metrics-port")
                .value_name("PORT")
                .about("Set the listen TCP port for the Prometheus metrics HTTP server.")
                .default_value("5054")
                .takes_value(true),
        )
        .arg(
            Arg::new("metrics-allow-origin")
                .long("metrics-allow-origin")
                .value_name("ORIGIN")
                .about("Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5054).")
                .takes_value(true),
        )

        /*
         * Monitoring metrics
         */

        .arg(
            Arg::new("monitoring-endpoint")
                .long("monitoring-endpoint")
                .value_name("ADDRESS")
                .about("Enables the monitoring service for sending system metrics to a remote endpoint. \
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
            Arg::new("staking")
                .long("staking")
                .about("Standard option for a staking beacon node. Equivalent to \
                `lighthouse bn --http --eth1 `. This will enable the http server on localhost:5052 \
                and try connecting to an eth1 node on localhost:8545")
                .takes_value(false)
        )

        /*
         * Eth1 Integration
         */
        .arg(
            Arg::new("eth1")
                .long("eth1")
                .about("If present the node will connect to an eth1 node. This is required for \
                       block production, you must use this flag if you wish to serve a validator.")
                .takes_value(false),
        )
        .arg(
            Arg::new("dummy-eth1")
                .long("dummy-eth1")
                .conflicts_with("eth1")
                .about("If present, uses an eth1 backend that generates static dummy data.\
                      Identical to the method used at the 2019 Canada interop.")
        )
        .arg(
            Arg::new("eth1-endpoint")
                .long("eth1-endpoint")
                .value_name("HTTP-ENDPOINT")
                .about("Deprecated. Use --eth1-endpoints.")
                .takes_value(true)
        )
        .arg(
            Arg::new("eth1-endpoints")
                .long("eth1-endpoints")
                .value_name("HTTP-ENDPOINTS")
                .conflicts_with("eth1-endpoint")
                .about("One or more comma-delimited server endpoints for web3 connection. \
                       If multiple endpoints are given the endpoints are used as fallback in the \
                       given order. Also enables the --eth1 flag. \
                       Defaults to http://127.0.0.1:8545.")
                .takes_value(true)
        )
        .arg(
            Arg::new("eth1-purge-cache")
                .long("eth1-purge-cache")
                .value_name("PURGE-CACHE")
                .about("Purges the eth1 block and deposit caches")
                .takes_value(false)
        )
        .arg(
            Arg::new("eth1-blocks-per-log-query")
                .long("eth1-blocks-per-log-query")
                .value_name("BLOCKS")
                .about("Specifies the number of blocks that a deposit log query should span. \
                    This will reduce the size of responses from the Eth1 endpoint.")
                .default_value("1000")
                .takes_value(true)
        )
        .arg(
            Arg::new("slots-per-restore-point")
                .long("slots-per-restore-point")
                .value_name("SLOT_COUNT")
                .about("Specifies how often a freezer DB restore point should be stored. \
                       Cannot be changed after initialization. \
                       [default: 2048 (mainnet) or 64 (minimal)]")
                .takes_value(true)
        )
        .arg(
            Arg::new("block-cache-size")
                .long("block-cache-size")
                .value_name("SIZE")
                .about("Specifies how many blocks the database should cache in memory [default: 5]")
                .takes_value(true)
        )

        /*
         * Database purging and compaction.
         */
        .arg(
            Arg::new("purge-db")
                .long("purge-db")
                .about("If present, the chain database will be deleted. Use with caution.")
        )
        .arg(
            Arg::new("compact-db")
                .long("compact-db")
                .about("If present, apply compaction to the database on start-up. Use with caution. \
                       It is generally not recommended unless auto-compaction is disabled.")
        )
        .arg(
            Arg::new("auto-compact-db")
                .long("auto-compact-db")
                .about("Enable or disable automatic compaction of the database on finalization.")
                .takes_value(true)
                .default_value("true")
        )

        /*
         * Misc.
         */
        .arg(
            Arg::new("graffiti")
                .long("graffiti")
                .about(
                    "Specify your custom graffiti to be included in blocks. \
                    Defaults to the current version and commit, truncated to fit in 32 bytes. "
                )
                .value_name("GRAFFITI")
                .takes_value(true)
        )
        .arg(
            Arg::new("max-skip-slots")
                .long("max-skip-slots")
                .about(
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
            Arg::new("slasher")
                .long("slasher")
                .about(
                    "Run a slasher alongside the beacon node. It is currently only recommended for \
                     expert users because of the immaturity of the slasher UX and the extra \
                     resources required."
                )
                .takes_value(false)
        )
        .arg(
            Arg::new("slasher-dir")
                .long("slasher-dir")
                .about(
                    "Set the slasher's database directory."
                )
                .value_name("PATH")
                .takes_value(true)
                .requires("slasher")
        )
        .arg(
            Arg::new("slasher-update-period")
                .long("slasher-update-period")
                .about(
                    "Configure how often the slasher runs batch processing."
                )
                .value_name("SECONDS")
                .requires("slasher")
                .takes_value(true)
        )
        .arg(
            Arg::new("slasher-slot-offset")
                .long("slasher-slot-offset")
                .about(
                    "Set the delay from the start of the slot at which the slasher should ingest \
                     attestations. Only effective if the slasher-update-period is a multiple of the \
                     slot duration."
                )
                .value_name("SECONDS")
                .requires("slasher")
                .takes_value(true)
        )
        .arg(
            Arg::new("slasher-history-length")
                .long("slasher-history-length")
                .about(
                    "Configure how many epochs of history the slasher keeps. Immutable after \
                     initialization."
                )
                .value_name("EPOCHS")
                .requires("slasher")
                .takes_value(true)
        )
        .arg(
            Arg::new("slasher-max-db-size")
                .long("slasher-max-db-size")
                .about(
                    "Maximum size of the LMDB database used by the slasher."
                )
                .value_name("GIGABYTES")
                .requires("slasher")
                .takes_value(true)
        )
        .arg(
            Arg::new("slasher-chunk-size")
                .long("slasher-chunk-size")
                .about(
                    "Number of epochs per validator per chunk stored on disk."
                )
                .value_name("EPOCHS")
                .requires("slasher")
                .takes_value(true)
        )
        .arg(
            Arg::new("slasher-validator-chunk-size")
                .long("slasher-validator-chunk-size")
                .about(
                    "Number of validators per chunk stored on disk."
                )
                .value_name("NUM_VALIDATORS")
                .requires("slasher")
                .takes_value(true)
        )
        .arg(
            Arg::new("slasher-broadcast")
                .long("slasher-broadcast")
                .about("Broadcast slashings found by the slasher to the rest of the network \
                       [disabled by default].")
                .requires("slasher")
        )
        .arg(
            Arg::new("wss-checkpoint")
                .long("wss-checkpoint")
                .about(
                    "Specify a weak subjectivity checkpoint in `block_root:epoch` format to verify \
                     the node's sync against. The block root should be 0x-prefixed. Note that this \
                     flag is for verification only, to perform a checkpoint sync from a recent \
                     state use --checkpoint-sync-url."
                )
                .value_name("WSS_CHECKPOINT")
                .takes_value(true)
        )
        .arg(
            Arg::new("checkpoint-state")
                .long("checkpoint-state")
                .about("Set a checkpoint state to start syncing from. Must be aligned and match \
                       --checkpoint-block. Using --checkpoint-sync-url instead is recommended.")
                .value_name("STATE_SSZ")
                .takes_value(true)
                .requires("checkpoint-block")
        )
        .arg(
            Arg::new("checkpoint-block")
                .long("checkpoint-block")
                .about("Set a checkpoint block to start syncing from. Must be aligned and match \
                       --checkpoint-state. Using --checkpoint-sync-url instead is recommended.")
                .value_name("BLOCK_SSZ")
                .takes_value(true)
                .requires("checkpoint-state")
        )
        .arg(
            Arg::new("checkpoint-sync-url")
                .long("checkpoint-sync-url")
                .about("Set the remote beacon node HTTP endpoint to use for checkpoint sync.")
                .value_name("BEACON_NODE")
                .takes_value(true)
                .conflicts_with("checkpoint-state")
        )
        .arg(
            Arg::new("reconstruct-historic-states")
                .long("reconstruct-historic-states")
                .about("After a checkpoint sync, reconstruct historic states in the database.")
                .takes_value(false)
        )
        .arg(
            Arg::new("validator-monitor-auto")
                .long("validator-monitor-auto")
                .about("Enables the automatic detection and monitoring of validators connected to the \
                    HTTP API and using the subnet subscription endpoint. This generally has the \
                    effect of providing additional logging and metrics for locally controlled \
                    validators.")
        )
        .arg(
            Arg::new("validator-monitor-pubkeys")
                .long("validator-monitor-pubkeys")
                .about("A comma-separated list of 0x-prefixed validator public keys. \
                        These validators will receive special monitoring and additional \
                        logging.")
                .value_name("PUBKEYS")
                .takes_value(true)
        )
        .arg(
            Arg::new("validator-monitor-file")
                .long("validator-monitor-file")
                .about("As per --validator-monitor-pubkeys, but the comma-separated list is \
                    contained within a file at the given path.")
                .value_name("PATH")
                .takes_value(true)
        )
        .arg(
            Arg::new("disable-lock-timeouts")
                .long("disable-lock-timeouts")
                .about("Disable the timeouts applied to some internal locks by default. This can \
                       lead to less spurious failures on slow hardware but is considered \
                       experimental as it may obscure performance issues.")
                .takes_value(false)
        )
}
