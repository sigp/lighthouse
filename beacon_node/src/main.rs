mod config;
mod run;

use clap::{App, Arg, SubCommand};
use config::get_configs;
use env_logger::{Builder, Env};
use slog::{crit, o, warn, Drain, Level};

pub const DEFAULT_DATA_DIR: &str = ".lighthouse";
pub const CLIENT_CONFIG_FILENAME: &str = "beacon-node.toml";
pub const ETH2_CONFIG_FILENAME: &str = "eth2-spec.toml";
pub const TESTNET_CONFIG_FILENAME: &str = "testnet.toml";

fn main() {
    // debugging output for libp2p and external crates
    Builder::from_env(Env::default()).init();

    let matches = App::new("Lighthouse")
        .version(version::version().as_str())
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Eth 2.0 Client")
        /*
         * Configuration directory locations.
         */
        .arg(
            Arg::with_name("datadir")
                .long("datadir")
                .value_name("DIR")
                .help("Data directory for keys and databases.")
                .takes_value(true)
                .global(true)
        )
        .arg(
            Arg::with_name("logfile")
                .long("logfile")
                .value_name("FILE")
                .help("File path where output will be written.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("network-dir")
                .long("network-dir")
                .value_name("DIR")
                .help("Data directory for network keys.")
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
        /*
         * gRPC parameters.
         */
        .arg(
            Arg::with_name("no-grpc")
                .long("no-grpc")
                .help("Disable the gRPC server.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("rpc-address")
                .long("rpc-address")
                .value_name("ADDRESS")
                .help("Listen address for RPC endpoint.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("rpc-port")
                .long("rpc-port")
                .value_name("PORT")
                .help("Listen port for RPC endpoint.")
                .conflicts_with("port-bump")
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
            Arg::with_name("eth1-server")
                .long("eth1-server")
                .value_name("SERVER")
                .help("Specifies the server for a web3 connection to the Eth1 chain.")
                .takes_value(true)
        )
        /*
         * Database parameters.
         */
        .arg(
            Arg::with_name("db")
                .long("db")
                .value_name("DB")
                .help("Type of database to use.")
                .takes_value(true)
                .possible_values(&["disk", "memory"])
                .default_value("disk"),
        )
        /*
         * Logging.
         */
        .arg(
            Arg::with_name("debug-level")
                .long("debug-level")
                .value_name("LEVEL")
                .help("The title of the spec constants for chain config.")
                .takes_value(true)
                .possible_values(&["info", "debug", "trace", "warn", "error", "crit"])
                .default_value("trace"),
        )
        /*
         * The "testnet" sub-command.
         *
         * Allows for creating a new datadir with testnet-specific configs.
         */
        .subcommand(SubCommand::with_name("testnet")
            .about("Create a new Lighthouse datadir using a testnet strategy.")
            .arg(
                Arg::with_name("spec")
                    .short("s")
                    .long("spec")
                    .value_name("TITLE")
                    .help("Specifies the default eth2 spec type. Only effective when creating a new datadir.")
                    .takes_value(true)
                    .required(true)
                    .possible_values(&["mainnet", "minimal", "interop"])
                    .default_value("minimal")
            )
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
                    .default_value("15")
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
                .about("Creates a new datadir where the genesis state is read from YAML. May fail to parse \
                       a file that was generated to a different spec than that specified by --spec.")
                .arg(Arg::with_name("format")
                    .value_name("FORMAT")
                    .required(true)
                    .possible_values(&["yaml", "ssz", "json"])
                    .help("The encoding of the state in the file."))
                .arg(Arg::with_name("file")
                    .value_name("YAML_FILE")
                    .required(true)
                    .help("A YAML file from which to read the state"))
            )
        )
        .get_matches();

    // build the initial logger
    let decorator = slog_term::TermDecorator::new().build();
    let decorator = logging::AlignedTermDecorator::new(decorator, logging::MAX_MESSAGE_WIDTH);
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build();

    let drain = match matches.value_of("debug-level") {
        Some("info") => drain.filter_level(Level::Info),
        Some("debug") => drain.filter_level(Level::Debug),
        Some("trace") => drain.filter_level(Level::Trace),
        Some("warn") => drain.filter_level(Level::Warning),
        Some("error") => drain.filter_level(Level::Error),
        Some("crit") => drain.filter_level(Level::Critical),
        _ => unreachable!("guarded by clap"),
    };

    let log = slog::Logger::root(drain.fuse(), o!());

    if std::mem::size_of::<usize>() != 8 {
        crit!(
            log,
            "Lighthouse only supports 64bit CPUs";
            "detected" => format!("{}bit", std::mem::size_of::<usize>() * 8)
        );
    }

    warn!(
        log,
        "Ethereum 2.0 is pre-release. This software is experimental."
    );

    let log_clone = log.clone();

    // Load the process-wide configuration.
    //
    // May load this from disk or create a new configuration, depending on the CLI flags supplied.
    let (client_config, eth2_config, log) = match get_configs(&matches, log) {
        Ok(configs) => configs,
        Err(e) => {
            crit!(log_clone, "Failed to load configuration. Exiting"; "error" => e);
            return;
        }
    };

    // Start the node using a `tokio` executor.
    match run::run_beacon_node(client_config, eth2_config, &log) {
        Ok(_) => {}
        Err(e) => crit!(log, "Beacon node failed to start"; "reason" => format!("{:}", e)),
    }
}
