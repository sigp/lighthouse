use clap::{App, Arg, ArgGroup};
use strum::VariantNames;
use types::ProgressiveBalancesMode;

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
        .arg(
            Arg::with_name("blobs-dir")
                .long("blobs-dir")
                .value_name("DIR")
                .help("Data directory for the blobs database.")
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
            Arg::with_name("disable-packet-filter")
                .long("disable-packet-filter")
                .help("Disables the discovery packet filter. Useful for testing in smaller networks")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("shutdown-after-sync")
                .long("shutdown-after-sync")
                .help("Shutdown beacon node as soon as sync is completed. Backfill sync will \
                       not be performed before shutdown.")
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
                .help("The address lighthouse will listen for UDP and TCP connections. To listen \
                      over IpV4 and IpV6 set this flag twice with the different values.\n\
                      Examples:\n\
                      - --listen-address '0.0.0.0' will listen over IPv4.\n\
                      - --listen-address '::' will listen over IPv6.\n\
                      - --listen-address '0.0.0.0' --listen-address '::' will listen over both \
                      IPv4 and IPv6. The order of the given addresses is not relevant. However, \
                      multiple IPv4, or multiple IPv6 addresses will not be accepted.")
                .multiple(true)
                .max_values(2)
                .default_value("0.0.0.0")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .value_name("PORT")
                .help("The TCP/UDP ports to listen on. There are two UDP ports. \
                      The discovery UDP port will be set to this value and the Quic UDP port will be set to this value + 1. The discovery port can be modified by the \
                      --discovery-port flag and the quic port can be modified by the --quic-port flag. If listening over both IPv4 and IPv6 the --port flag \
                      will apply to the IPv4 address and --port6 to the IPv6 address.")
                .default_value("9000")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port6")
                .long("port6")
                .value_name("PORT")
                .help("The TCP/UDP ports to listen on over IPv6 when listening over both IPv4 and \
                      IPv6. Defaults to 9090 when required. The Quic UDP port will be set to this value + 1.")
                .default_value("9090")
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
            Arg::with_name("quic-port")
                .long("quic-port")
                .value_name("PORT")
                .help("The UDP port that quic will listen on. Defaults to `port` + 1")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("discovery-port6")
                .long("discovery-port6")
                .value_name("PORT")
                .help("The UDP port that discovery will listen on over IPv6 if listening over \
                      both IPv4 and IPv6. Defaults to `port6`")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("quic-port6")
                .long("quic-port6")
                .value_name("PORT")
                .help("The UDP port that quic will listen on over IPv6 if listening over \
                      both IPv4 and IPv6. Defaults to `port6` + 1")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("target-peers")
                .long("target-peers")
                .help("The target number of peers.")
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
            Arg::with_name("network-load")
                .long("network-load")
                .value_name("INTEGER")
                .help("Lighthouse's network can be tuned for bandwidth/performance. Setting this to a high value, will increase the bandwidth lighthouse uses, increasing the likelihood of redundant information in exchange for faster communication. This can increase profit of validators marginally by receiving messages faster on the network. Lower values decrease bandwidth usage, but makes communication slower which can lead to validator performance reduction. Values are in the range [1,5].")
                .default_value("3")
                .set(clap::ArgSettings::Hidden)
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
                .help("The UDP4 port of the local ENR. Set this only if you are sure other nodes \
                      can connect to your local node on this port over IPv4.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enr-quic-port")
                .long("enr-quic-port")
                .value_name("PORT")
                .help("The quic UDP4 port that will be set on the local ENR. Set this only if you are sure other nodes \
                      can connect to your local node on this port over IPv4.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enr-udp6-port")
                .long("enr-udp6-port")
                .value_name("PORT")
                .help("The UDP6 port of the local ENR. Set this only if you are sure other nodes \
                      can connect to your local node on this port over IPv6.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enr-quic6-port")
                .long("enr-quic6-port")
                .value_name("PORT")
                .help("The quic UDP6 port that will be set on the local ENR. Set this only if you are sure other nodes \
                      can connect to your local node on this port over IPv6.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enr-tcp-port")
                .long("enr-tcp-port")
                .value_name("PORT")
                .help("The TCP4 port of the local ENR. Set this only if you are sure other nodes \
                      can connect to your local node on this port over IPv4. The --port flag is \
                      used if this is not set.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enr-tcp6-port")
                .long("enr-tcp6-port")
                .value_name("PORT")
                .help("The TCP6 port of the local ENR. Set this only if you are sure other nodes \
                      can connect to your local node on this port over IPv6. The --port6 flag is \
                      used if this is not set.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enr-address")
                .long("enr-address")
                .value_name("ADDRESS")
                .help("The IP address/ DNS address to broadcast to other peers on how to reach \
                      this node. If a DNS address is provided, the enr-address is set to the IP \
                      address it resolves to and does not auto-update based on PONG responses in \
                      discovery. Set this only if you are sure other nodes can connect to your \
                      local node on this address. This will update the `ip4` or `ip6` ENR fields \
                      accordingly. To update both, set this flag twice with the different values.")
                .multiple(true)
                .max_values(2)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enr-match")
                .short("e")
                .long("enr-match")
                .help("Sets the local ENR IP address and port to match those set for lighthouse. \
                      Specifically, the IP address will be the value of --listen-address and the \
                      UDP port will be --discovery-port.")
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
        // NOTE: This is hidden because it is primarily a developer feature for testnets and
        // debugging. We remove it from the list to avoid clutter.
        .arg(
            Arg::with_name("disable-discovery")
                .long("disable-discovery")
                .help("Disables the discv5 discovery protocol. The node will not search for new peers or participate in the discovery protocol.")
                .hidden(true)
        )
        .arg(
            Arg::with_name("disable-quic")
                .long("disable-quic")
                .help("Disables the quic transport. The node will rely solely on the TCP transport for libp2p connections.")
        )
        .arg(
            Arg::with_name("disable-peer-scoring")
                .long("disable-peer-scoring")
                .help("Disables peer scoring in lighthouse. WARNING: This is a dev only flag is only meant to be used in local testing scenarios \
                        Using this flag on a real network may cause your node to become eclipsed and see a different view of the network")
                .takes_value(false)
                .hidden(true),
        )
        .arg(
            Arg::with_name("trusted-peers")
                .long("trusted-peers")
                .value_name("TRUSTED_PEERS")
                .help("One or more comma-delimited trusted peer ids which always have the highest score according to the peer scoring system.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("genesis-backfill")
                .long("genesis-backfill")
                .help("Attempts to download blocks all the way back to genesis when checkpoint syncing.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("enable-private-discovery")
                .long("enable-private-discovery")
                .help("Lighthouse by default does not discover private IP addresses. Set this flag to enable connection attempts to local addresses.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("self-limiter")
            .long("self-limiter")
            .help(
                "Enables the outbound rate limiter (requests made by this node).\
                \
                Rate limit quotas per protocol can be set in the form of \
                <protocol_name>:<tokens>/<time_in_seconds>. To set quotas for multiple protocols, \
                separate them by ';'. If the self rate limiter is enabled and a protocol is not \
                present in the configuration, the quotas used for the inbound rate limiter will be \
                used."
            )
            .min_values(0)
            .hidden(true)
        )
        .arg(
            Arg::with_name("proposer-only")
                .long("proposer-only")
                .help("Sets this beacon node at be a block proposer only node. \
                       This will run the beacon node in a minimal configuration that is sufficient for block publishing only. This flag should be used \
                       for a beacon node being referenced by validator client using the --proposer-node flag. This configuration is for enabling more secure setups.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("inbound-rate-limiter")
            .long("inbound-rate-limiter")
            .help(
                "Configures the inbound rate limiter (requests received by this node).\
                \
                Rate limit quotas per protocol can be set in the form of \
                <protocol_name>:<tokens>/<time_in_seconds>. To set quotas for multiple protocols, \
                separate them by ';'. If the inbound rate limiter is enabled and a protocol is not \
                present in the configuration, the default quotas will be used. \
                \
                This is enabled by default, using default quotas. To disable rate limiting pass \
                `disabled` to this option instead."
            )
            .takes_value(true)
            .hidden(true)
        )
        .arg(
            Arg::with_name("disable-backfill-rate-limiting")
                .long("disable-backfill-rate-limiting")
                .help("Disable the backfill sync rate-limiting. This allow users to just sync the entire chain as fast \
                    as possible, however it can result in resource contention which degrades staking performance. Stakers \
                    should generally choose to avoid this flag since backfill sync is not required for staking.")
                .takes_value(false),
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
                .requires("enable_http")
                .value_name("ADDRESS")
                .help("Set the listen address for the RESTful HTTP API server.")
                .default_value_if("enable_http", None, "127.0.0.1")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("http-port")
                .long("http-port")
                .requires("enable_http")
                .value_name("PORT")
                .help("Set the listen TCP port for the RESTful HTTP API server.")
                .default_value_if("enable_http", None, "5052")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("http-allow-origin")
                .long("http-allow-origin")
                .requires("enable_http")
                .value_name("ORIGIN")
                .help("Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5052).")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("http-disable-legacy-spec")
                .long("http-disable-legacy-spec")
                .requires("enable_http")
                .hidden(true)
        )
        .arg(
            Arg::with_name("http-spec-fork")
                .long("http-spec-fork")
                .requires("enable_http")
                .value_name("FORK")
                .help("Serve the spec for a specific hard fork on /eth/v1/config/spec. It should \
                       not be necessary to set this flag.")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("http-enable-tls")
                .long("http-enable-tls")
                .help("Serves the RESTful HTTP API server over TLS. This feature is currently \
                    experimental.")
                .takes_value(false)
                .requires("http-tls-cert")
                .requires("http-tls-key")
        )
        .arg(
            Arg::with_name("http-tls-cert")
                .long("http-tls-cert")
                .requires("enable_http")
                .help("The path of the certificate to be used when serving the HTTP API server \
                    over TLS.")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("http-tls-key")
                .long("http-tls-key")
                .requires("enable_http")
                .help("The path of the private key to be used when serving the HTTP API server \
                    over TLS. Must not be password-protected.")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("http-allow-sync-stalled")
                .long("http-allow-sync-stalled")
                .requires("enable_http")
                .help("Forces the HTTP to indicate that the node is synced when sync is actually \
                    stalled. This is useful for very small testnets. TESTING ONLY. DO NOT USE ON \
                    MAINNET.")
        )
        .arg(
            Arg::with_name("http-sse-capacity-multiplier")
                .long("http-sse-capacity-multiplier")
                .requires("enable_http")
                .takes_value(true)
                .default_value_if("enable_http", None, "1")
                .value_name("N")
                .help("Multiplier to apply to the length of HTTP server-sent-event (SSE) channels. \
                       Increasing this value can prevent messages from being dropped.")
        )
        .arg(
            Arg::with_name("http-duplicate-block-status")
                .long("http-duplicate-block-status")
                .requires("enable_http")
                .takes_value(true)
                .default_value_if("enable_http", None, "202")
                .value_name("STATUS_CODE")
                .help("Status code to send when a block that is already known is POSTed to the \
                       HTTP API.")
        )
        .arg(
            Arg::with_name("http-enable-beacon-processor")
                .long("http-enable-beacon-processor")
                .requires("enable_http")
                .value_name("BOOLEAN")
                .help("The beacon processor is a scheduler which provides quality-of-service and \
                    DoS protection. When set to \"true\", HTTP API requests will be queued and scheduled \
                    alongside other tasks. When set to \"false\", HTTP API responses will be executed \
                    immediately.")
                .takes_value(true)
                .default_value_if("enable_http", None, "true")
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
                .requires("metrics")
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
                .default_value_if("metrics", None, "5054")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("metrics-allow-origin")
                .long("metrics-allow-origin")
                .value_name("ORIGIN")
                .requires("metrics")
                .help("Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5054).")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("shuffling-cache-size")
            .long("shuffling-cache-size")
            .help("Some HTTP API requests can be optimised by caching the shufflings at each epoch. \
            This flag allows the user to set the shuffling cache size in epochs. \
            Shufflings are dependent on validator count and setting this value to a large number can consume a large amount of memory.")
            .takes_value(true)
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
        .arg(
            Arg::with_name("monitoring-endpoint-period")
                .long("monitoring-endpoint-period")
                .value_name("SECONDS")
                .help("Defines how many seconds to wait between each message sent to \
                       the monitoring-endpoint. Default: 60s")
                .requires("monitoring-endpoint")
                .takes_value(true),
        )

        /*
         * Standard staking flags
         */

        .arg(
            Arg::with_name("staking")
                .long("staking")
                .help("Standard option for a staking beacon node. This will enable the HTTP server \
                       on localhost:5052 and import deposit logs from the execution node. This is \
                       equivalent to `--http` on merge-ready networks, or `--http --eth1` pre-merge")
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
                .help("One http endpoint for a web3 connection to an execution node. \
                       Note: This flag is now only useful for testing, use `--execution-endpoint` \
                       flag to connect to an execution node on mainnet and testnets.
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
            Arg::with_name("eth1-cache-follow-distance")
                .long("eth1-cache-follow-distance")
                .value_name("BLOCKS")
                .help("Specifies the distance between the Eth1 chain head and the last block which \
                       should be imported into the cache. Setting this value lower can help \
                       compensate for irregular Proof-of-Work block times, but setting it too low \
                       can make the node vulnerable to re-orgs.")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("slots-per-restore-point")
                .long("slots-per-restore-point")
                .value_name("SLOT_COUNT")
                .help("Specifies how often a freezer DB restore point should be stored. \
                       Cannot be changed after initialization. \
                       [default: 8192 (mainnet) or 64 (minimal)]")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("epochs-per-migration")
                .long("epochs-per-migration")
                .value_name("N")
                .help("The number of epochs to wait between running the migration of data from the \
                       hot DB to the cold DB. Less frequent runs can be useful for minimizing disk \
                       writes")
                .default_value("1")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("block-cache-size")
                .long("block-cache-size")
                .value_name("SIZE")
                .help("Specifies how many blocks the database should cache in memory [default: 5]")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("historic-state-cache-size")
                .long("historic-state-cache-size")
                .value_name("SIZE")
                .help("Specifies how many states from the freezer database should cache in memory [default: 1]")
                .takes_value(true)
        )
        /*
         * Execution Layer Integration
         */
        .arg(
            Arg::with_name("merge")
                .long("merge")
                .help("Deprecated. The feature activates automatically when --execution-endpoint \
                    is supplied.")
                .takes_value(false)
                .hidden(true)
        )
        .arg(
            Arg::with_name("execution-endpoint")
                .long("execution-endpoint")
                .value_name("EXECUTION-ENDPOINT")
                .alias("execution-endpoints")
                .help("Server endpoint for an execution layer JWT-authenticated HTTP \
                       JSON-RPC connection. Uses the same endpoint to populate the \
                       deposit cache.")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("execution-jwt")
                .long("execution-jwt")
                .value_name("EXECUTION-JWT")
                .alias("jwt-secrets")
                .help("File path which contains the hex-encoded JWT secret for the \
                       execution endpoint provided in the --execution-endpoint flag.")
                .requires("execution-endpoint")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("execution-jwt-secret-key")
                .long("execution-jwt-secret-key")
                .value_name("EXECUTION-JWT-SECRET-KEY")
                .alias("jwt-secret-key")
                .help("Hex-encoded JWT secret for the \
                       execution endpoint provided in the --execution-endpoint flag.")
                .requires("execution-endpoint")
                .conflicts_with("execution-jwt")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("execution-jwt-id")
                .long("execution-jwt-id")
                .value_name("EXECUTION-JWT-ID")
                .alias("jwt-id")
                .help("Used by the beacon node to communicate a unique identifier to execution nodes \
                       during JWT authentication. It corresponds to the 'id' field in the JWT claims object.\
                       Set to empty by default")
                .requires("execution-jwt")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("execution-jwt-version")
                .long("execution-jwt-version")
                .value_name("EXECUTION-JWT-VERSION")
                .alias("jwt-version")
                .help("Used by the beacon node to communicate a client version to execution nodes \
                       during JWT authentication. It corresponds to the 'clv' field in the JWT claims object.\
                       Set to empty by default")
                .requires("execution-jwt")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("suggested-fee-recipient")
                .long("suggested-fee-recipient")
                .value_name("SUGGESTED-FEE-RECIPIENT")
                .help("Emergency fallback fee recipient for use in case the validator client does \
                       not have one configured. You should set this flag on the validator \
                       client instead of (or in addition to) setting it here.")
                .requires("execution-endpoint")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("builder")
                .long("builder")
                .alias("payload-builder")
                .alias("payload-builders")
                .help("The URL of a service compatible with the MEV-boost API.")
                .requires("execution-endpoint")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("execution-timeout-multiplier")
                .long("execution-timeout-multiplier")
                .value_name("NUM")
                .help("Unsigned integer to multiply the default execution timeouts by.")
                .default_value("1")
                .takes_value(true)
        )
        /* Deneb settings */
        .arg(
            Arg::with_name("trusted-setup-file-override")
                .long("trusted-setup-file-override")
                .value_name("FILE")
                .help("Path to a json file containing the trusted setup params. \
                      NOTE: This will override the trusted setup that is generated \
                      from the mainnet kzg ceremony. Use with caution")
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
        .arg(
            Arg::with_name("prune-payloads")
                .long("prune-payloads")
                .help("Prune execution payloads from Lighthouse's database. This saves space but \
                       imposes load on the execution client, as payloads need to be \
                       reconstructed and sent to syncing peers.")
                .takes_value(true)
                .default_value("true")
        )
        .arg(
            Arg::with_name("prune-blobs")
                .long("prune-blobs")
                .value_name("BOOLEAN")
                .help("Prune blobs from Lighthouse's database when they are older than the data \
                       data availability boundary relative to the current epoch.")
                .takes_value(true)
                .default_value("true")
        )
        .arg(
            Arg::with_name("epochs-per-blob-prune")
                .long("epochs-per-blob-prune")
                .value_name("EPOCHS")
                .help("The epoch interval with which to prune blobs from Lighthouse's \
                       database when they are older than the data availability boundary \
                       relative to the current epoch.")
                .takes_value(true)
                .default_value("1")
        )
        .arg(
            Arg::with_name("blob-prune-margin-epochs")
                .long("blob-prune-margin-epochs")
                .value_name("EPOCHS")
                .help("The margin for blob pruning in epochs. The oldest blobs are pruned \
                       up until data_availability_boundary - blob_prune_margin_epochs.")
                .takes_value(true)
                .default_value("0")
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
                    "Refuse to skip more than this many slots when processing an attestation. \
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
            Arg::with_name("slasher-slot-offset")
                .long("slasher-slot-offset")
                .help(
                    "Set the delay from the start of the slot at which the slasher should ingest \
                     attestations. Only effective if the slasher-update-period is a multiple of the \
                     slot duration."
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
                    "Maximum size of the MDBX database used by the slasher."
                )
                .value_name("GIGABYTES")
                .requires("slasher")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("slasher-att-cache-size")
                .long("slasher-att-cache-size")
                .help("Set the maximum number of attestation roots for the slasher to cache")
                .value_name("COUNT")
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
                       [Enabled by default].")
                .takes_value(true)
                .default_value("true")
        )
        .arg(
            Arg::with_name("slasher-backend")
                .long("slasher-backend")
                .value_name("DATABASE")
                .help("Set the database backend to be used by the slasher.")
                .takes_value(true)
                .possible_values(slasher::DatabaseBackend::VARIANTS)
                .requires("slasher")
        )
        .arg(
            Arg::with_name("wss-checkpoint")
                .long("wss-checkpoint")
                .help(
                    "Specify a weak subjectivity checkpoint in `block_root:epoch` format to verify \
                     the node's sync against. The block root should be 0x-prefixed. Note that this \
                     flag is for verification only, to perform a checkpoint sync from a recent \
                     state use --checkpoint-sync-url."
                )
                .value_name("WSS_CHECKPOINT")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("checkpoint-state")
                .long("checkpoint-state")
                .help("Set a checkpoint state to start syncing from. Must be aligned and match \
                       --checkpoint-block. Using --checkpoint-sync-url instead is recommended.")
                .value_name("STATE_SSZ")
                .takes_value(true)
                .requires("checkpoint-block")
        )
        .arg(
            Arg::with_name("checkpoint-block")
                .long("checkpoint-block")
                .help("Set a checkpoint block to start syncing from. Must be aligned and match \
                       --checkpoint-state. Using --checkpoint-sync-url instead is recommended.")
                .value_name("BLOCK_SSZ")
                .takes_value(true)
                .requires("checkpoint-state")
        )
        .arg(
            Arg::with_name("checkpoint-sync-url")
                .long("checkpoint-sync-url")
                .help("Set the remote beacon node HTTP endpoint to use for checkpoint sync.")
                .value_name("BEACON_NODE")
                .takes_value(true)
                .conflicts_with("checkpoint-state")
        )
        .arg(
            Arg::with_name("checkpoint-sync-url-timeout")
                .long("checkpoint-sync-url-timeout")
                .help("Set the timeout for checkpoint sync calls to remote beacon node HTTP endpoint.")
                .value_name("SECONDS")
                .takes_value(true)
                .default_value("180")
        )
        .arg(
            Arg::with_name("reconstruct-historic-states")
                .long("reconstruct-historic-states")
                .help("After a checkpoint sync, reconstruct historic states in the database. This requires syncing all the way back to genesis.")
                .takes_value(false)
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
        .arg(
            Arg::with_name("validator-monitor-individual-tracking-threshold")
                .long("validator-monitor-individual-tracking-threshold")
                .help("Once the validator monitor reaches this number of local validators \
                    it will stop collecting per-validator Prometheus metrics and issuing \
                    per-validator logs. Instead, it will provide aggregate metrics and logs. \
                    This avoids infeasibly high cardinality in the Prometheus database and \
                    high log volume when using many validators. Defaults to 64.")
                .value_name("INTEGER")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("disable-lock-timeouts")
                .long("disable-lock-timeouts")
                .help("Disable the timeouts applied to some internal locks by default. This can \
                       lead to less spurious failures on slow hardware but is considered \
                       experimental as it may obscure performance issues.")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("disable-proposer-reorgs")
                .long("disable-proposer-reorgs")
                .help("Do not attempt to reorg late blocks from other validators when proposing.")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("proposer-reorg-threshold")
                .long("proposer-reorg-threshold")
                .value_name("PERCENT")
                .help("Percentage of vote weight below which to attempt a proposer reorg. \
                       Default: 20%")
                .conflicts_with("disable-proposer-reorgs")
        )
        .arg(
            Arg::with_name("proposer-reorg-epochs-since-finalization")
                .long("proposer-reorg-epochs-since-finalization")
                .value_name("EPOCHS")
                .help("Maximum number of epochs since finalization at which proposer reorgs are \
                       allowed. Default: 2")
                .conflicts_with("disable-proposer-reorgs")
        )
        .arg(
            Arg::with_name("proposer-reorg-cutoff")
                .long("proposer-reorg-cutoff")
                .value_name("MILLISECONDS")
                .help("Maximum delay after the start of the slot at which to propose a reorging \
                       block. Lower values can prevent failed reorgs by ensuring the block has \
                       ample time to propagate and be processed by the network. The default is \
                       1/12th of a slot (1 second on mainnet)")
                .conflicts_with("disable-proposer-reorgs")
        )
        .arg(
            Arg::with_name("proposer-reorg-disallowed-offsets")
                .long("proposer-reorg-disallowed-offsets")
                .value_name("N1,N2,...")
                .help("Comma-separated list of integer offsets which can be used to avoid \
                       proposing reorging blocks at certain slots. An offset of N means that \
                       reorging proposals will not be attempted at any slot such that \
                       `slot % SLOTS_PER_EPOCH == N`. By default only re-orgs at offset 0 will be \
                       avoided. Any offsets supplied with this flag will impose additional \
                       restrictions.")
                .conflicts_with("disable-proposer-reorgs")
        )
        .arg(
            Arg::with_name("prepare-payload-lookahead")
                .long("prepare-payload-lookahead")
                .value_name("MILLISECONDS")
                .help("The time before the start of a proposal slot at which payload attributes \
                       should be sent. Low values are useful for execution nodes which don't \
                       improve their payload after the first call, and high values are useful \
                       for ensuring the EL is given ample notice. Default: 1/3 of a slot.")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("always-prepare-payload")
                .long("always-prepare-payload")
                .help("Send payload attributes with every fork choice update. This is intended for \
                       use by block builders, relays and developers. You should set a fee \
                       recipient on this BN and also consider adjusting the \
                       --prepare-payload-lookahead flag.")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("fork-choice-before-proposal-timeout")
                .long("fork-choice-before-proposal-timeout")
                .help("Set the maximum number of milliseconds to wait for fork choice before \
                       proposing a block. You can prevent waiting at all by setting the timeout \
                       to 0, however you risk proposing atop the wrong parent block.")
                .default_value("250")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("paranoid-block-proposal")
                .long("paranoid-block-proposal")
                .help("Paranoid enough to be reading the source? Nice. This flag reverts some \
                       block proposal optimisations and forces the node to check every attestation \
                       it includes super thoroughly. This may be useful in an emergency, but not \
                       otherwise.")
                .hidden(true)
                .takes_value(false)
        )
        .arg(
            Arg::with_name("builder-fallback-skips")
                .long("builder-fallback-skips")
                .help("If this node is proposing a block and has seen this number of skip slots \
                        on the canonical chain in a row, it will NOT query any connected builders, \
                        and will use the local execution engine for payload construction.")
                .default_value("3")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("builder-fallback-skips-per-epoch")
                .long("builder-fallback-skips-per-epoch")
                .help("If this node is proposing a block and has seen this number of skip slots \
                        on the canonical chain in the past `SLOTS_PER_EPOCH`, it will NOT query \
                        any connected builders, and will use the local execution engine for \
                        payload construction.")
                .default_value("8")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("builder-fallback-epochs-since-finalization")
                .long("builder-fallback-epochs-since-finalization")
                .help("If this node is proposing a block and the chain has not finalized within \
                        this number of epochs, it will NOT query any connected builders, \
                        and will use the local execution engine for payload construction. Setting \
                        this value to anything less than 2 will cause the node to NEVER query \
                        connected builders. Setting it to 2 will cause this condition to be hit \
                        if there are skips slots at the start of an epoch, right before this node \
                        is set to propose.")
                .default_value("3")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("builder-fallback-disable-checks")
                .long("builder-fallback-disable-checks")
                .help("This flag disables all checks related to chain health. This means the builder \
                        API will always be used for payload construction, regardless of recent chain \
                        conditions.")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("builder-profit-threshold")
                .long("builder-profit-threshold")
                .value_name("WEI_VALUE")
                .help("The minimum reward in wei provided to the proposer by a block builder for \
                    an external payload to be considered for inclusion in a proposal. If this \
                    threshold is not met, the local EE's payload will be used. This is currently \
                    *NOT* in comparison to the value of the local EE's payload. It simply checks \
                    whether the total proposer reward from an external payload is equal to or \
                    greater than this value. In the future, a comparison to a local payload is \
                    likely to be added. Example: Use 250000000000000000 to set the threshold to \
                     0.25 ETH.")
                .default_value("0")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("ignore-builder-override-suggestion-threshold")
                .long("ignore-builder-override-suggestion-threshold")
                .value_name("PERCENTAGE")
                .help("When the EE advises Lighthouse to ignore the builder payload, this flag \
                    specifies a percentage threshold for the difference between the reward from \
                    the builder payload and the local EE's payload. This threshold must be met \
                    for Lighthouse to consider ignoring the EE's suggestion. If the reward from \
                    the builder's payload doesn't exceed the local payload by at least this \
                    percentage, the local payload will be used. The conditions under which the \
                    EE may make this suggestion depend on the EE's implementation, with the \
                    primary intent being to safeguard against potential censorship attacks \
                    from builders. Setting this flag to 0 will cause Lighthouse to always \
                    ignore the EE's suggestion. Default: 10.0 (equivalent to 10%).")
                .default_value("10.0")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("builder-user-agent")
                .long("builder-user-agent")
                .value_name("STRING")
                .help("The HTTP user agent to send alongside requests to the builder URL. The \
                       default is Lighthouse's version string.")
                .requires("builder")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("count-unrealized")
                .long("count-unrealized")
                .hidden(true)
                .help("This flag is deprecated and has no effect.")
                .takes_value(true)
                .default_value("true")
        )
        .arg(
            Arg::with_name("count-unrealized-full")
                .long("count-unrealized-full")
                .hidden(true)
                .help("This flag is deprecated and has no effect.")
                .takes_value(true)
                .default_value("false")
        )
        .arg(
            Arg::with_name("reset-payload-statuses")
                .long("reset-payload-statuses")
                .help("When present, Lighthouse will forget the payload statuses of any \
                       already-imported blocks. This can assist in the recovery from a consensus \
                       failure caused by the execution layer.")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("disable-deposit-contract-sync")
                .long("disable-deposit-contract-sync")
                .help("Explictly disables syncing of deposit logs from the execution node. \
                      This overrides any previous option that depends on it. \
                      Useful if you intend to run a non-validating beacon node.")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("disable-optimistic-finalized-sync")
                .long("disable-optimistic-finalized-sync")
                .help("Force Lighthouse to verify every execution block hash with the execution \
                       client during finalized sync. By default block hashes will be checked in \
                       Lighthouse and only passed to the EL if initial verification fails.")
        )
        .arg(
            Arg::with_name("light-client-server")
                .long("light-client-server")
                .help("Act as a full node supporting light clients on the p2p network \
                       [experimental]")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("gui")
                .long("gui")
                .help("Enable the graphical user interface and all its requirements. \
                      This enables --http and --validator-monitor-auto and enables SSE logging.")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("always-prefer-builder-payload")
            .long("always-prefer-builder-payload")
            .help("If set, the beacon node always uses the payload from the builder instead of the local payload.")
            // The builder profit threshold flag is used to provide preference
            // to local payloads, therefore it fundamentally conflicts with
            // always using the builder.
            .conflicts_with("builder-profit-threshold")
            .conflicts_with("ignore-builder-override-suggestion-threshold")
        )
        .arg(
            Arg::with_name("invalid-gossip-verified-blocks-path")
            .long("invalid-gossip-verified-blocks-path")
            .value_name("PATH")
            .help("If a block succeeds gossip validation whilst failing full validation, store \
                    the block SSZ as a file at this path. This feature is only recommended for \
                    developers. This directory is not pruned, users should be careful to avoid \
                    filling up their disks.")
        )
        .arg(
            Arg::with_name("progressive-balances")
                .long("progressive-balances")
                .value_name("MODE")
                .help("Options to enable or disable the progressive balances cache for \
                        unrealized FFG progression calculation. The default `checked` mode compares \
                        the progressive balances from the cache against results from the existing \
                        method. If there is a mismatch, it falls back to the existing method. The \
                        optimized mode (`fast`) is faster but is still experimental, and is \
                        not recommended for mainnet usage at this time.")
                .takes_value(true)
                .possible_values(ProgressiveBalancesMode::VARIANTS)
        )
        .arg(
            Arg::with_name("beacon-processor-max-workers")
                .long("beacon-processor-max-workers")
                .value_name("INTEGER")
                .help("Specifies the maximum concurrent tasks for the task scheduler. Increasing \
                        this value may increase resource consumption. Reducing the value \
                        may result in decreased resource usage and diminished performance. The \
                        default value is the number of logical CPU cores on the host.")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("beacon-processor-work-queue-len")
                .long("beacon-processor-work-queue-len")
                .value_name("INTEGER")
                .help("Specifies the length of the inbound event queue. \
                        Higher values may prevent messages from being dropped while lower values \
                        may help protect the node from becoming overwhelmed.")
                .default_value("16384")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("beacon-processor-reprocess-queue-len")
                .long("beacon-processor-reprocess-queue-len")
                .value_name("INTEGER")
                .help("Specifies the length of the queue for messages requiring delayed processing. \
                        Higher values may prevent messages from being dropped while lower values \
                        may help protect the node from becoming overwhelmed.")
                .default_value("12288")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("beacon-processor-attestation-batch-size")
                .long("beacon-processor-attestation-batch-size")
                .value_name("INTEGER")
                .help("Specifies the number of gossip attestations in a signature verification batch. \
                       Higher values may reduce CPU usage in a healthy network whilst lower values may \
                       increase CPU usage in an unhealthy or hostile network.")
                .default_value("64")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("beacon-processor-aggregate-batch-size")
                .long("beacon-processor-aggregate-batch-size")
                .value_name("INTEGER")
                .help("Specifies the number of gossip aggregate attestations in a signature \
                       verification batch. \
                       Higher values may reduce CPU usage in a healthy network while lower values may \
                       increase CPU usage in an unhealthy or hostile network.")
                .default_value("64")
                .takes_value(true)
        )
        .group(ArgGroup::with_name("enable_http").args(&["http", "gui", "staking"]).multiple(true))
}
