use clap::{App, Arg, SubCommand};

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
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
            Arg::with_name("testnet-dir")
                .long("testnet-dir")
                .value_name("DIR")
                .help("Path to directory containing eth2_testnet specs. Defaults to \
                      a hard-coded Lighthouse testnet. Only effective if there is no \
                      existing database.")
                .takes_value(true)
        )
        /*
         * Network parameters.
         */
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
                .help("The UDP port that discovery will listen on.")
                .default_value("9000")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("maxpeers")
                .long("maxpeers")
                .help("The maximum number of peers.")
                .default_value("10")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("boot-nodes")
                .long("boot-nodes")
                .allow_hyphen_values(true)
                .value_name("ENR-LIST")
                .help("One or more comma-delimited base64-encoded ENR's to bootstrap the p2p network.")
                .takes_value(true),
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
                .help("The IP address to broadcast to other peers on how to reach this node. \
                Set this only if you are sure other nodes can connect to your local node on this address. \
                Discovery will automatically find your external address,if possible.
           ")
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
                .short("s")
                .long("disable-enr-auto-update")
                .help("Discovery automatically updates the nodes local ENR with an external IP address and port as seen by other peers on the network. \
                This disables this feature, fixing the ENR's IP/PORT to those specified on boot.")
                .takes_value(true),
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
            Arg::with_name("p2p-priv-key")
                .long("p2p-priv-key")
                .value_name("HEX")
                .help("A secp256k1 secret key, represented as ASCII-encoded hex bytes (with or \
                       without 0x prefix). Default is either loaded from disk or generated \
                       automatically.")
                .takes_value(true),
        )
        /* Client/chain related arguments */
        .arg(
            Arg::with_name("disabled-forks")
                .long("disabled-forks")
                .value_name("STRING")
                .help("A comma separated list of forks that will be disabled.")
                .takes_value(true),
        )
        /* REST API related arguments */
        .arg(
            Arg::with_name("http")
                .long("http")
                .help("Enable RESTful HTTP API server. Disabled by default.")
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
        /* Websocket related arguments */
        .arg(
            Arg::with_name("ws")
                .long("ws")
                .help("Enable the websocket server. Disabled by default.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("ws-address")
                .long("ws-address")
                .value_name("ADDRESS")
                .help("Set the listen address for the websocket server.")
                .default_value("127.0.0.1")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ws-port")
                .long("ws-port")
                .value_name("PORT")
                .help("Set the listen TCP port for the websocket server.")
                .default_value("5053")
                .takes_value(true),
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
                .help("Specifies the server for a web3 connection to the Eth1 chain. Also enables the --eth1 flag.")
                .takes_value(true)
                .default_value("http://127.0.0.1:8545")
        )
        .arg(
            Arg::with_name("slots-per-restore-point")
                .long("slots-per-restore-point")
                .value_name("SLOT_COUNT")
                .help("Specifies how often a freezer DB restore point should be stored. \
                       DO NOT DECREASE AFTER INITIALIZATION. [default: 2048 (mainnet) or 64 (minimal)]")
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
            Arg::with_name("state-cache-size")
                .long("state-cache-size")
                .value_name("SIZE")
                .help("Specifies how many states the database should cache in memory [default: 5]")
                .takes_value(true)
        )
        /*
         * The "testnet" sub-command.
         *
         * Allows for creating a new datadir with testnet-specific configs.
         */
        .subcommand(SubCommand::with_name("testnet")
            .about("Create a new Lighthouse datadir using a testnet strategy.")
            .arg(
                Arg::with_name("random-datadir")
                    .long("random-datadir")
                    .short("r")
                    .help("If present, append a random string to the datadir path. Useful for fast development \
                          iteration.")
            )
            .arg(
                Arg::with_name("force")
                    .long("force")
                    .short("f")
                    .help("If present, will create new config and database files and move the any existing to a \
                           backup directory.")
                    .conflicts_with("random-datadir")
            )
            .arg(
                Arg::with_name("random-propagation")
                    .long("random-propagation")
                    .value_name("INTEGER")
                    .takes_value(true)
                    .help("Specifies (as a percentage) the likelihood of propagating blocks and \
                           attestations. This should only be used for testing networking elements. The \
                           value must like in the range 1-100. Default is 100.")
            )
            .arg(
                Arg::with_name("slot-time")
                    .long("slot-time")
                    .short("t")
                    .value_name("MILLISECONDS")
                    .help("Defines the slot time when creating a new testnet. The default is \
                           specified by the spec.")
            )
            /*
             * `recent`
             *
             * Start a new node, with a specified number of validators with a genesis time in the last
             * 30-minutes.
             */
            .subcommand(SubCommand::with_name("recent")
                .about("Creates a new genesis state where the genesis time was at the previous \
                       MINUTES boundary (e.g., when MINUTES == 30; 12:00, 12:30, 13:00, etc.)")
                .arg(Arg::with_name("validator_count")
                    .value_name("VALIDATOR_COUNT")
                    .required(true)
                    .help("The number of validators in the genesis state"))
                .arg(Arg::with_name("minutes")
                    .long("minutes")
                    .short("m")
                    .value_name("MINUTES")
                    .required(true)
                    .default_value("30")
                    .help("The maximum number of minutes that will have elapsed before genesis"))
            )
            /*
             * `quick`
             *
             * Start a new node, specifying the number of validators and genesis time
             */
            .subcommand(SubCommand::with_name("quick")
                .about("Creates a new genesis state from the specified validator count and genesis time. \
                        Compatible with the `quick-start genesis` defined in the eth2.0-pm repo.")
                .arg(Arg::with_name("validator_count")
                    .value_name("VALIDATOR_COUNT")
                    .required(true)
                    .help("The number of validators in the genesis state"))
                .arg(Arg::with_name("genesis_time")
                    .value_name("UNIX_EPOCH_SECONDS")
                    .required(true)
                    .help("The genesis time for the given state."))
            )
            /*
             * `yaml`
             *
             * Start a new node, using a genesis state loaded from a YAML file
             */
            .subcommand(SubCommand::with_name("file")
                .about("Creates a new datadir where the genesis state is read from file. May fail to parse \
                       a file that was generated to a different spec than that specified by --spec.")
                .arg(Arg::with_name("format")
                    .value_name("FORMAT")
                    .required(true)
                    .possible_values(&["ssz"])
                    .help("The encoding of the state in the file."))
                .arg(Arg::with_name("file")
                    .value_name("FILE")
                    .required(true)
                    .help("A file from which to read the state"))
            )
        )
}
