use clap::{App, Arg, SubCommand};

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("beacon_node")
        .visible_aliases(&["b", "bn", "beacon"])
        .version(crate_version!())
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Eth 2.0 Client")
        /*
         * Configuration directory locations.
         */
        .arg(
            Arg::with_name("network-dir")
                .long("network-dir")
                .value_name("DIR")
                .help("Data directory for network keys.")
                .takes_value(true)
                .global(true)
        )
        .arg(
            Arg::with_name("freezer-dir")
                .long("freezer-dir")
                .value_name("DIR")
                .help("Data directory for the freezer database.")
                .takes_value(true)
                .global(true)
        )
        /*
         * Network parameters.
         */
        .arg(
            Arg::with_name("port-bump")
                .long("port-bump")
                .short("b")
                .value_name("INCREMENT")
                .help("Sets all listening TCP/UDP ports to default values, but with each port increased by \
                      INCREMENT. Useful when starting multiple nodes on a single machine. Using increments \
                      in multiples of 10 is recommended.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("listen-address")
                .long("listen-address")
                .value_name("ADDRESS")
                .help("The address lighthouse will listen for UDP and TCP connections. (default 127.0.0.1).")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .value_name("PORT")
                .help("The TCP/UDP port to listen on. The UDP port can be modified by the --discovery-port flag.")
                .conflicts_with("port-bump")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("maxpeers")
                .long("maxpeers")
                .help("The maximum number of peers (default 10).")
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
            Arg::with_name("discovery-port")
                .long("disc-port")
                .value_name("PORT")
                .help("The discovery UDP port.")
                .conflicts_with("port-bump")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("discovery-address")
                .long("discovery-address")
                .value_name("ADDRESS")
                .help("The IP address to broadcast to other peers on how to reach this node.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("topics")
                .long("topics")
                .value_name("STRING")
                .help("One or more comma-delimited gossipsub topic strings to subscribe to.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("libp2p-addresses")
                .long("libp2p-addresses")
                .value_name("MULTIADDR")
                .help("One or more comma-delimited multiaddrs to manually connect to a libp2p peer without an ENR.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("p2p-priv-key")
                .long("p2p-priv-key")
                .value_name("HEX")
                .help("A secp256k1 secret key, represented as ASCII-encoded hex bytes (with or without 0x prefix).")
                .takes_value(true),
        )
        /* REST API related arguments */
        .arg(
            Arg::with_name("no-api")
                .long("no-api")
                .help("Disable RESTful HTTP API server.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("api-address")
                .long("api-address")
                .value_name("ADDRESS")
                .help("Set the listen address for the RESTful HTTP API server.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("api-port")
                .long("api-port")
                .value_name("PORT")
                .help("Set the listen TCP port for the RESTful HTTP API server.")
                .conflicts_with("port-bump")
                .takes_value(true),
        )
        /* Websocket related arguments */
        .arg(
            Arg::with_name("no-ws")
                .long("no-ws")
                .help("Disable websocket server.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("ws-address")
                .long("ws-address")
                .value_name("ADDRESS")
                .help("Set the listen address for the websocket server.")
                .conflicts_with_all(&["no-ws"])
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ws-port")
                .long("ws-port")
                .value_name("PORT")
                .help("Set the listen TCP port for the websocket server.")
                .conflicts_with_all(&["no-ws", "port-bump"])
                .takes_value(true),
        )

        /*
         * Eth1 Integration
         */
        .arg(
            Arg::with_name("dummy-eth1")
                .long("dummy-eth1")
                .help("If present, uses an eth1 backend that generates static dummy data.\
                      Identical to the method used at the 2019 Canada interop.")
        )
        .arg(
            Arg::with_name("eth1-endpoint")
                .long("eth1-endpoint")
                .value_name("HTTP-ENDPOINT")
                .help("Specifies the server for a web3 connection to the Eth1 chain.")
                .takes_value(true)
                .default_value("http://localhost:8545")
        )
        .arg(
            Arg::with_name("eth1-follow")
                .long("eth1-follow")
                .value_name("BLOCK_COUNT")
                .help("Specifies how many blocks we should cache behind the eth1 head. A larger number means a smaller cache.")
                .takes_value(true)
                // TODO: set this higher once we're not using testnets all the time.
                .default_value("0")
        )
        .arg(
            Arg::with_name("deposit-contract")
                .long("deposit-contract")
                .short("e")
                .value_name("DEPOSIT-CONTRACT")
                .help("Specifies the deposit contract address on the Eth1 chain.")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("deposit-contract-deploy")
                .long("deposit-contract-deploy")
                .value_name("BLOCK_NUMBER")
                .help("Specifies the block number that the deposit contract was deployed at.")
                .takes_value(true)
                // TODO: set this higher once we're not using testnets all the time.
                .default_value("0")
        )
        /*
         * The "testnet" sub-command.
         *
         * Allows for creating a new datadir with testnet-specific configs.
         */
        .subcommand(SubCommand::with_name("testnet")
            .about("Create a new Lighthouse datadir using a testnet strategy.")
            .arg(
                Arg::with_name("eth2-config")
                    .long("eth2-config")
                    .value_name("TOML_FILE")
                    .help("A existing eth2_spec TOML file (e.g., eth2_spec.toml).")
                    .takes_value(true)
                    .conflicts_with("spec")
            )
            .arg(
                Arg::with_name("client-config")
                    .long("client-config")
                    .value_name("TOML_FILE")
                    .help("An existing beacon_node TOML file (e.g., beacon_node.toml).")
                    .takes_value(true)
            )
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
                Arg::with_name("slot-time")
                    .long("slot-time")
                    .short("t")
                    .value_name("MILLISECONDS")
                    .help("Defines the slot time when creating a new testnet.")
            )
            /*
             * `boostrap`
             *
             * Start a new node by downloading genesis and network info from another node via the
             * HTTP API.
             */
            .subcommand(SubCommand::with_name("bootstrap")
                .about("Connects to the given HTTP server, downloads a genesis state and attempts to peer with it.")
                .arg(Arg::with_name("server")
                    .value_name("HTTP_SERVER")
                    .required(true)
                    .default_value("http://localhost:5052")
                    .help("A HTTP server, with a http:// prefix"))
                .arg(Arg::with_name("libp2p-port")
                    .short("p")
                    .long("port")
                    .value_name("TCP_PORT")
                    .help("A libp2p listen port used to peer with the bootstrap server. This flag is useful \
                           when port-fowarding is used: you may connect using a different port than \
                           the one the server is immediately listening on."))
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
                    .default_value("0")
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
            /*
             * `prysm`
             *
             * Connect to the Prysmatic Labs testnet.
             */
            .subcommand(SubCommand::with_name("prysm")
                .about("Connect to the Prysmatic Labs testnet on Goerli.")
            )
        )
}
