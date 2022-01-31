use std::path::PathBuf;
use clap::{ArgEnum, Args, Parser, Subcommand};
use lazy_static::lazy_static;
use lighthouse_version::VERSION;

lazy_static! {
    pub static ref SHORT_VERSION String = VERSION.replace("Lighthouse/", "");
    pub static ref LONG_VERSION: String = format!(
        "{}\n\
                 BLS library: {}\n\
                 SHA256 hardware acceleration: {}\n\
                 Specs: mainnet (true), minimal ({}), gnosis ({})",
        VERSION.replace("Lighthouse/", ""),
        bls_library_name(),
        have_sha_extensions(),
        cfg!(feature = "spec-minimal"),
        cfg!(feature = "gnosis"),
    );
}

#[derive(Parser)]
#[clap(
name = "Lighthouse",
version = SHORT_VERSION.as_str(),
long_version = LONG_VERSION.as_str(),
author = "Sigma Prime <contact@sigmaprime.io>",
about = "Ethereum 2.0 client by Sigma Prime. Provides a full-featured beacon \
             node, a validator client and utilities for managing validator accounts."
)]
struct Lighthouse {
    #[clap(
        long,
        help = "The filepath to a YAML or TOML file with flag values. The filename must \
                    end in `.toml`, `.yml`, or `.yaml`. To override any options in \
                   the config file, specify the same option in the command line.",
        global = true
    )]
    config_file: Option<PathBuf>,
    #[clap(
        long,
        short,
        value_name = "DEPRECATED",
        help = "This flag is deprecated, it will be disallowed in a future release. This \
                       value is now derived from the --network or --testnet-dir flags.",
        global = true
    )]
    spec: Option<String>,
    #[clap(
        short = 'l',
        help = "Enables environment logging giving access to sub-protocol logs such as discv5 and libp2p"
    )]
    env_log: bool,
    #[clap(
        long,
        value_name = "FILE",
        help = "File path where the log file will be stored. Once it grows to the \
                value specified in `--logfile-max-size` a new log file is generated where \
                future logs are stored. \
                Once the number of log files exceeds the value specified in \
                `--logfile-max-number` the oldest log file will be overwritten.",
        global = true
    )]
    logfile: Option<PathBuf>,
    #[clap(
    long,
    value_name = "LEVEL",
    help = "The verbosity level used when emitting logs to the log file.",
    possible_values = &["info","debug","trace","warn","error","crit"],
    default_value = "debug",
    global = true
    )]
    logfile_debug_level: String,
    #[clap(
        long,
        value_name = "SIZE",
        help = "The maximum size  = in MB, each log file can grow to before rotating. If set \
                   to 0, background file logging is disabled.",
        default_value = "200",
        global = true
    )]
    logfile_max_size: u64,
    #[clap(
        long,
        value_name = "COUNT",
        help = "The maximum number of log files that will be stored. If set to 0, \
                   background file logging is disabled.",
        default_value = "5",
        global = true
    )]
    logfile_max_number: usize,
    #[clap(
        long,
        help = "If present, compress old log files. This can help reduce the space needed \
                   to store old logs.",
        global = true
    )]
    logfile_compress: bool,
    #[clap(
    long,
    value_name = "FORMAT",
    help = "Specifies the log format used when emitting logs to the terminal.",
    possible_values = &["JSON"],
    global = true
    )]
    log_format: Option<String>,
    #[clap(
    long,
    value_name = "LEVEL",
    help = "Specifies the verbosity level used when emitting logs to the terminal.",
    possible_values = &["info","debug","trace","warn","error","crit"],
    global = true,
    default_value = "info"
    )]
    debug_level: String,
    #[clap(
        long,
        short,
        value_name = "DIR",
        global = true,
        help = "Used to specify a custom root data directory for lighthouse keys and databases. \
                   Defaults to $HOME/.lighthouse/{network} where network is the value of the `network` flag \
                   Note: Users should specify separate custom datadirs for different networks."
    )]
    datadir: Option<String>,
    #[clap(
        long,
        short,
        value_name = "DIR",
        help = "Path to directory containing eth2_testnet specs. Defaults to \
                     a hard-coded Lighthouse testnet. Only effective if there is no \
                     existing database.",
        global = true
    )]
    testnet_dir: Option<String>,
    #[clap(
    long,
    value_name = "network",
    help = "Name of the Eth2 chain Lighthouse will sync and follow.",
    possible_values = HARDCODED_NET_NAMES,
    conflicts_with = "testnet_dir_flag",
    global = true
    )]
    network: Option<String>,
    #[clap(
        long,
        hide = true,
        help = "Dumps the config to a desired location. Used for testing only.",
        global = true
    )]
    dump_config: Option<PathBuf>,
    #[clap(
        long,
        hide = true,
        help = "Shuts down immediately after the Beacon Node or Validator has successfully launched. \
    Used for testing only, DO NOT USE IN PRODUCTION.",
        global = true
    )]
    immediate_shutdown: bool,
    #[clap(
        long,
        help = "If present, do not configure the system allocator. Providing this flag will \
    generally increase memory usage, it should only be provided when debugging \
    specific memory allocation issues.",
        global = true
    )]
    disable_malloc_tuning: bool,
    #[clap(
        long,
        value_name = "INTEGER",
        help = "Used to coordinate manual overrides to the TERMINAL_TOTAL_DIFFICULTY parameter. \
                      Accepts a 256-bit decimal integer  = not a hex value,. \
                      This flag should only be used if the user has a clear understanding that \
                      the broad Ethereum community has elected to override the terminal difficulty. \
                      Incorrect use of this flag will cause your node to experience a consensus
                      failure. Be extremely careful with this flag.",
        global = true
    )]
    terminal_total_difficulty_override: Option<String>,
    #[clap(
        long,
        value_name = "TERMINAL_BLOCK_HASH",
        help = "Used to coordinate manual overrides to the TERMINAL_BLOCK_HASH parameter. \
                      This flag should only be used if the user has a clear understanding that \
                      the broad Ethereum community has elected to override the terminal PoW block. \
                      Incorrect use of this flag will cause your node to experience a consensus
                      failure. Be extremely careful with this flag.",
        requires = "terminal_block_hash_epoch_override",
        global = true
    )]
    terminal_block_hash_override: Option<String>,
    #[clap(
        long,
        value_name = "EPOCH",
        help = "Used to coordinate manual overrides to the TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH \
                      parameter. This flag should only be used if the user has a clear understanding \
                      that the broad Ethereum community has elected to override the terminal PoW block. \
                      Incorrect use of this flag will cause your node to experience a consensus
                      failure. Be extremely careful with this flag.",
        requires = "terminal_block_hash_override",
        global = true
    )]
    terminal_block_hash_epoch_override: Option<String>,
    beacon_node: BeaconNode,
    validator_client: ValidatorClient,
    boot_node: BootNode,
}

#[derive(Parser)]
#[clap(name = "beacon_node",
visible_aliases = &["b", "bn", "beacon"],
author = "Sigma Prime <contact@sigmaprime.io>",
about = "The primary component which connects to the Ethereum 2.0 P2P network and \
                downloads, verifies and stores blocks. Provides a HTTP API for querying \
                the beacon chain and publishing messages to the network.",
)]
struct BeaconNode {
    #[clap(
        long,
        value_name = "DIR",
        help = "Data directory for network keys. Defaults to network/ inside the beacon node \
                       dir.",
        takes_value = true
    )]
    network_dir: Option<String>,
    #[clap(
        long,
        value_name = "DIR",
        help = "Data directory for the freezer database.",
        takes_value = true
    )]
    freezer_dir: Option<String>,
    #[clap(
        long,
        help = "Subscribe to all subnets regardless of validator count. \
                       This will also advertise the beacon node as being long-lived subscribed to all subnets.",
        takes_value = false
    )]
    subscribe_all_subnets: Option<String>,
    #[clap(
        long,
        help = "Import and aggregate all attestations, regardless of validator subscriptions. \
                       This will only import attestations from already-subscribed subnets, use with \
                       --subscribe-all-subnets to ensure all attestations are received for import.",
        takes_value = false
    )]
    import_all_attestations: Option<String>,
    #[clap(
        long,
        help = "Disables the discovery packet filter. Useful for testing in smaller networks",
        takes_value = false
    )]
    disable_packet_filter: Option<String>,
    #[clap(
        long,
        help = "Shutdown beacon node as soon as sync is completed. Backfill sync will \
                       not be performed before shutdown.",
        takes_value = false
    )]
    shutdown_after_sync: Option<String>,
    #[clap(
        long,
        short = 'z',
        help = "Sets all listening TCP/UDP ports to 0, allowing the OS to choose some \
                       arbitrary free ports.",
        takes_value = false
    )]
    zero_ports: Option<String>,
    #[clap(
        long,
        value_name = "ADDRESS",
        help = "The address lighthouse will listen for UDP and TCP connections.",
        default_value = "0.0.0.0",
        takes_value = true
    )]
    listen_address: Option<String>,
    #[clap(
        long,
        value_name = "PORT",
        help = "The TCP/UDP port to listen on. The UDP port can be modified by the --discovery-port flag.",
        default_value = "9000",
        takes_value = true
    )]
    port: Option<String>,
    #[clap(
        long,
        value_name = "PORT",
        help = "The UDP port that discovery will listen on. Defaults to `port`",
        takes_value = true
    )]
    discovery_port: Option<String>,
    #[clap(
        long,
        help = "The target number of peers.",
        default_value = "50",
        takes_value = true
    )]
    target_peers: Option<String>,
    #[clap(
        long,
        allow_hyphen_values = true,
        value_name = "ENR/MULTIADDR LIST",
        help = "One or more comma-delimited base64-encoded ENR's to bootstrap the p2p network. Multiaddr is also supported.",
        takes_value = true
    )]
    boot_nodes: Option<String>,
    #[clap(
        long,
        value_name = "INTEGER",
        help = "Lighthouse's network can be tuned for bandwidth/performance. Setting this to a high value, will increase the bandwidth lighthouse uses, increasing the likelihood of redundant information in exchange for faster communication. This can increase profit of validators marginally by receiving messages faster on the network. Lower values decrease bandwidth usage, but makes communication slower which can lead to validator performance reduction. Values are in the range [1,5].",
        default_value = "3",
        hide = true,
        takes_value = true
    )]
    network_load: Option<String>,
    #[clap(
        long,
        help = "Disables UPnP support. Setting this will prevent Lighthouse from attempting to automatically establish external port mappings.",
        takes_value = false
    )]
    disable_upnp: Option<String>,
    #[clap(
        long,
        help = "Prevents sending various client identification information.",
        takes_value = false
    )]
    private: Option<String>,
    #[clap(
        long,
        value_name = "PORT",
        help = "The UDP port of the local ENR. Set this only if you are sure other nodes can connect to your local node on this port.",
        takes_value = true
    )]
    enr_udp_port: Option<String>,
    #[clap(
        long,
        value_name = "PORT",
        help = "The TCP port of the local ENR. Set this only if you are sure other nodes can connect to your local node on this port.\
                    The --port flag is used if this is not set.",
        takes_value = true
    )]
    enr_tcp_port: Option<String>,
    #[clap(
        long,
        value_name = "ADDRESS",
        help = "The IP address/ DNS address to broadcast to other peers on how to reach this node. \
                If a DNS address is provided, the enr-address is set to the IP address it resolves to and \
                does not auto-update based on PONG responses in discovery. \
                Set this only if you are sure other nodes can connect to your local node on this address. \
                Discovery will automatically find your external address,if possible.",
        requires = "enr_udp_port",
        takes_value = true
    )]
    enr_address: Option<String>,
    #[clap(
        short = 'e',
        long,
        help = "Sets the local ENR IP address and port to match those set for lighthouse. \
                Specifically, the IP address will be the value of --listen-address and the UDP port will be --discovery-port."
    )]
    enr_match: Option<String>,
    #[clap(
        short = 'x',
        long,
        help = "Discovery automatically updates the nodes local ENR with an external IP address and port as seen by other peers on the network. \
                This disables this feature, fixing the ENR's IP/PORT to those specified on boot."
    )]
    disable_enr_auto_update: Option<String>,
    #[clap(
        long,
        value_name = "MULTIADDR",
        help = "One or more comma-delimited multiaddrs to manually connect to a libp2p peer \
                       without an ENR.",
        takes_value = true
    )]
    libp2p_addresses: Option<String>,
    #[clap(
        long,
        help = "Disables the discv5 discovery protocol. The node will not search for new peers or participate in the discovery protocol.",
        takes_value = false
    )]
    disable_discovery: Option<String>,
    #[clap(
        long,
        value_name = "TRUSTED_PEERS",
        help = "One or more comma-delimited trusted peer ids which always have the highest score according to the peer scoring system.",
        takes_value = true
    )]
    trusted_peers: Option<String>,
    #[clap(
        long,
        help = "Enable the RESTful HTTP API server. Disabled by default.",
        takes_value = false
    )]
    http: Option<String>,
    #[clap(
        long,
        value_name = "ADDRESS",
        help = "Set the listen address for the RESTful HTTP API server.",
        default_value = "127.0.0.1",
        takes_value = true
    )]
    http_address: Option<String>,
    #[clap(
        long,
        value_name = "PORT",
        help = "Set the listen TCP port for the RESTful HTTP API server.",
        default_value = "5052",
        takes_value = true
    )]
    http_port: Option<String>,
    #[clap(
        long,
        value_name = "ORIGIN",
        help = "Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5052).",
        takes_value = true
    )]
    http_allow_origin: Option<String>,
    #[clap(
        long,
        help = "Disable serving of legacy data on the /config/spec endpoint. May be \
                       disabled by default in a future release."
    )]
    http_disable_legacy_spec: Option<String>,
    #[clap(
        long,
        help = "Serves the RESTful HTTP API server over TLS. This feature is currently \
                    experimental.",
        takes_value = false,
        requires = "http_tls_cert",
        requires = "http_tls_key"
    )]
    http_enable_tls: Option<String>,
    #[clap(
        long,
        help = "The path of the certificate to be used when serving the HTTP API server \
                    over TLS.",
        takes_value = true
    )]
    http_tls_cert: Option<String>,
    #[clap(
        long,
        help = "The path of the private key to be used when serving the HTTP API server \
                    over TLS. Must not be password-protected.",
        takes_value = true
    )]
    http_tls_key: Option<String>,
    #[clap(
        long,
        help = "Forces the HTTP to indicate that the node is synced when sync is actually \
                    stalled. This is useful for very small testnets. TESTING ONLY. DO NOT USE ON \
                    MAINNET."
    )]
    http_allow_sync_stalled: Option<String>,
    #[clap(
        long,
        help = "Enable the Prometheus metrics HTTP server. Disabled by default.",
        takes_value = false
    )]
    metrics: Option<String>,
    #[clap(
        long,
        value_name = "ADDRESS",
        help = "Set the listen address for the Prometheus metrics HTTP server.",
        default_value = "127.0.0.1",
        takes_value = true
    )]
    metrics_address: Option<String>,
    #[clap(
        long,
        value_name = "PORT",
        help = "Set the listen TCP port for the Prometheus metrics HTTP server.",
        default_value = "5054",
        takes_value = true
    )]
    metrics_port: Option<String>,
    #[clap(
        long,
        value_name = "ORIGIN",
        help = "Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5054).",
        takes_value = true
    )]
    metrics_allow_origin: Option<String>,
    #[clap(
        long,
        value_name = "ADDRESS",
        help = "Enables the monitoring service for sending system metrics to a remote endpoint. \
                This can be used to monitor your setup on certain services (e.g. beaconcha.in). \
                This flag sets the endpoint where the beacon node metrics will be sent. \
                Note: This will send information to a remote sever which may identify and associate your \
                validators, IP address and other personal information. Always use a HTTPS connection \
                and never provide an untrusted URL.",
        takes_value = true
    )]
    monitoring_endpoint: Option<String>,
    #[clap(
        long,
        help = "Standard option for a staking beacon node. Equivalent to \
                `lighthouse bn --http --eth1 `. This will enable the http server on localhost:5052 \
                and try connecting to an eth1 node on localhost:8545",
        takes_value = false
    )]
    staking: Option<String>,
    #[clap(
        long,
        help = "If present the node will connect to an eth1 node. This is required for \
                       block production, you must use this flag if you wish to serve a validator.",
        takes_value = false
    )]
    eth1: Option<String>,
    #[clap(
        long,
        conflicts_with = "eth1",
        help = "If present, uses an eth1 backend that generates static dummy data.\
                      Identical to the method used at the 2019 Canada interop."
    )]
    dummy_eth1: Option<String>,
    #[clap(
        long,
        value_name = "HTTP-ENDPOINT",
        help = "Deprecated. Use --eth1-endpoints.",
        takes_value = true
    )]
    eth1_endpoint: Option<String>,
    #[clap(
        long,
        value_name = "HTTP-ENDPOINTS",
        conflicts_with = "eth1_endpoint",
        help = "One or more comma-delimited server endpoints for web3 connection. \
                       If multiple endpoints are given the endpoints are used as fallback in the \
                       given order. Also enables the --eth1 flag. \
                       Defaults to http://127.0.0.1:8545.",
        takes_value = true
    )]
    eth1_endpoints: Option<String>,
    #[clap(
        long,
        value_name = "PURGE-CACHE",
        help = "Purges the eth1 block and deposit caches",
        takes_value = false
    )]
    eth1_purge_cache: Option<String>,
    #[clap(
        long,
        value_name = "BLOCKS",
        help = "Specifies the number of blocks that a deposit log query should span. \
                    This will reduce the size of responses from the Eth1 endpoint.",
        default_value = "1000",
        takes_value = true
    )]
    eth1_blocks_per_log_query: Option<String>,
    #[clap(
        long,
        value_name = "SLOT_COUNT",
        help = "Specifies how often a freezer DB restore point should be stored. \
                       Cannot be changed after initialization. \
                       [default: 2048 (mainnet) or 64 (minimal)]",
        takes_value = true
    )]
    slots_per_restore_point: Option<String>,
    #[clap(
        long,
        value_name = "SIZE",
        help = "Specifies how many blocks the database should cache in memory [default: 5]",
        takes_value = true
    )]
    block_cache_size: Option<String>,
    #[clap(    long,
    help = "Enable the features necessary to run merge testnets. This feature \
                       is unstable and is for developers only.",
    takes_value = false,,
    )]
    merge: Option<String>,
    #[clap(
        long,
        value_name = "EXECUTION-ENDPOINTS",
        help = "One or more comma-delimited server endpoints for HTTP JSON-RPC connection. \
                       If multiple endpoints are given the endpoints are used as fallback in the \
                       given order. Also enables the --merge flag. \
                       If this flag is omitted and the --eth1-endpoints is supplied, those values \
                       will be used. Defaults to http://127.0.0.1:8545.",
        takes_value = true
    )]
    execution_endpoints: Option<String>,
    #[clap(
        long,
        value_name = "FEE-RECIPIENT",
        help = "Once the merge has happened, this address will receive transaction fees \
                       collected from any blocks produced by this node. Defaults to a junk \
                       address whilst the merge is in development stages. THE DEFAULT VALUE \
                       WILL BE REMOVED BEFORE THE MERGE ENTERS PRODUCTION",
        requires = "merge",
        takes_value = true
    )]
    fee_recipient: Option<String>,
    #[clap(
        long,
        help = "If present, the chain database will be deleted. Use with caution."
    )]
    purge_db: Option<String>,
    #[clap(
        long,
        help = "If present, apply compaction to the database on start-up. Use with caution. \
                       It is generally not recommended unless auto-compaction is disabled."
    )]
    compact_db: Option<String>,
    #[clap(
        long,
        help = "Enable or disable automatic compaction of the database on finalization.",
        takes_value = true,
        default_value = "true"
    )]
    auto_compact_db: Option<String>,
    #[clap(
        long,
        help = "Specify your custom graffiti to be included in blocks. \
                    Defaults to the current version and commit, truncated to fit in 32 bytes. ",
        value_name = "GRAFFITI",
        takes_value = true
    )]
    graffiti: Option<String>,
    #[clap(
        long,
        help = "Refuse to skip more than this many slots when processing a block or attestation. \
                    This prevents nodes on minority forks from wasting our time and disk space, \
                    but could also cause unnecessary consensus failures, so is disabled by default.",
        value_name = "NUM_SLOTS",
        takes_value = true
    )]
    max_skip_slots: Option<String>,
    #[clap(
        long,
        help = "Run a slasher alongside the beacon node. It is currently only recommended for \
                     expert users because of the immaturity of the slasher UX and the extra \
                     resources required.",
        takes_value = false
    )]
    slasher: Option<String>,
    #[clap(
        long,
        help = "Set the slasher's database directory.",
        value_name = "PATH",
        takes_value = true,
        requires = "slasher"
    )]
    slasher_dir: Option<String>,
    #[clap(
        long,
        help = "Configure how often the slasher runs batch processing.",
        value_name = "SECONDS",
        requires = "slasher",
        takes_value = true
    )]
    slasher_update_period: Option<String>,
    #[clap(
        long,
        help = "Set the delay from the start of the slot at which the slasher should ingest \
                     attestations. Only effective if the slasher-update-period is a multiple of the \
                     slot duration.",
        value_name = "SECONDS",
        requires = "slasher",
        takes_value = true
    )]
    slasher_slot_offset: Option<String>,
    #[clap(
        long,
        help = "Configure how many epochs of history the slasher keeps. Immutable after \
                     initialization.",
        value_name = "EPOCHS",
        requires = "slasher",
        takes_value = true
    )]
    slasher_history_length: Option<String>,
    #[clap(
        long,
        help = "Maximum size of the MDBX database used by the slasher.",
        value_name = "GIGABYTES",
        requires = "slasher",
        takes_value = true
    )]
    slasher_max_db_size: Option<String>,
    #[clap(
        long,
        help = "Set the maximum number of attestation roots for the slasher to cache",
        value_name = "COUNT",
        requires = "slasher",
        takes_value = true
    )]
    slasher_att_cache_size: Option<String>,
    #[clap(
        long,
        help = "Number of epochs per validator per chunk stored on disk.",
        value_name = "EPOCHS",
        requires = "slasher",
        takes_value = true
    )]
    slasher_chunk_size: Option<String>,
    #[clap(
        long,
        help = "Number of validators per chunk stored on disk.",
        value_name = "NUM_VALIDATORS",
        requires = "slasher",
        takes_value = true
    )]
    slasher_validator_chunk_size: Option<String>,
    #[clap(
        long,
        help = "Broadcast slashings found by the slasher to the rest of the network \
                       [disabled by default].",
        requires = "slasher"
    )]
    slasher_broadcast: Option<String>,
    #[clap(
        long,
        help = "Specify a weak subjectivity checkpoint in `block_root:epoch` format to verify \
                     the node's sync against. The block root should be 0x-prefixed. Note that this \
                     flag is for verification only, to perform a checkpoint sync from a recent \
                     state use --checkpoint-sync-url.",
        value_name = "WSS_CHECKPOINT",
        takes_value = true
    )]
    wss_checkpoint: Option<String>,
    #[clap(
        long,
        help = "Set a checkpoint state to start syncing from. Must be aligned and match \
                       --checkpoint-block. Using --checkpoint-sync-url instead is recommended.",
        value_name = "STATE_SSZ",
        takes_value = true,
        requires = "checkpoint_block"
    )]
    checkpoint_state: Option<String>,
    #[clap(
        long,
        help = "Set a checkpoint block to start syncing from. Must be aligned and match \
                       --checkpoint-state. Using --checkpoint-sync-url instead is recommended.",
        value_name = "BLOCK_SSZ",
        takes_value = true,
        requires = "checkpoint_state"
    )]
    checkpoint_block: Option<String>,
    #[clap(
        long,
        help = "Set the remote beacon node HTTP endpoint to use for checkpoint sync.",
        value_name = "BEACON_NODE",
        takes_value = true,
        conflicts_with = "checkpoint_state"
    )]
    checkpoint_sync_url: Option<String>,
    #[clap(
        long,
        help = "After a checkpoint sync, reconstruct historic states in the database.",
        takes_value = false
    )]
    reconstruct_historic_state: Option<String>,
    #[clap(
        long,
        help = "Enables the automatic detection and monitoring of validators connected to the \
                    HTTP API and using the subnet subscription endpoint. This generally has the \
                    effect of providing additional logging and metrics for locally controlled \
                    validators."
    )]
    validator_monitor_auto: Option<String>,
    #[clap(
        long,
        help = "A comma-separated list of 0x-prefixed validator public keys. \
                        These validators will receive special monitoring and additional \
                        logging.",
        value_name = "PUBKEYS",
        takes_value = true
    )]
    validator_monitor_pubkeys: Option<String>,
    #[clap(
        long,
        help = "As per --validator-monitor-pubkeys, but the comma-separated list is \
                    contained within a file at the given path.",
        value_name = "PATH",
        takes_value = true
    )]
    validator_monitor_file: Option<String>,
    #[clap(
        long,
        help = "Disable the timeouts applied to some internal locks by default. This can \
                       lead to less spurious failures on slow hardware but is considered \
                       experimental as it may obscure performance issues.",
        takes_value = false
    )]
    disable_lock_timeouts: Option<String>,
}

#[derive(Parser)]
#[clap(name = "validator_client",
visible_aliases = &["v", "vc", "validator"],
about = "When connected to a beacon node, performs the duties of a staked \
                validator (e.g., proposing blocks and attestations).",)]
struct ValidatorClient {
    #[clap(
        long,
        value_name = "NETWORK_ADDRESS",
        help = "Deprecated. Use --beacon-nodes.",
        takes_value = true,
        conflicts_with = "beacon_nodes"
    )]
    beacon_node: Option<String>,
    #[clap(
        long,
        value_name = "NETWORK_ADDRESSES",
        help = "Comma-separated addresses to one or more beacon node HTTP APIs. \
                       Default is http://localhost:5052.",
        takes_value = true
    )]
    beacon_nodes: Option<String>,
    #[clap(    long,
    value_name = "NETWORK_ADDRESS",
    help = "Deprecated. Use --beacon-nodes.",
    takes_value = true,
    conflicts_with_all = &[BEACON_NODE_FLAG, BEACON_NODES_FLAG],
    )]
    server: Option<String>,
    #[clap(
        long,
        value_name = "VALIDATORS_DIR",
        help = "The directory which contains the validator keystores, deposit data for \
                    each validator along with the common slashing protection database \
                    and the validator_definitions.yml",
        takes_value = true,
        conflicts_with = "datadir"
    )]
    validators_dir: Option<String>,
    #[clap(
        long,
        value_name = "SECRETS_DIRECTORY",
        help = "The directory which contains the password to unlock the validator \
                    voting keypairs. Each password should be contained in a file where the \
                    name is the 0x-prefixed hex representation of the validators voting public \
                    key. Defaults to ~/.lighthouse/{network}/secrets.",
        takes_value = true,
        conflicts_with = "datadir"
    )]
    secrets_dir: Option<String>,
    #[clap(
        long,
        help = "DEPRECATED. This flag does nothing and will be removed in a future release."
    )]
    delete_lockfiles: Option<String>,
    #[clap(
        long,
        help = "If present, do not require the slashing protection database to exist before \
                     running. You SHOULD NOT use this flag unless you're certain that a new \
                     slashing protection database is required. Usually, your database \
                     will have been initialized when you imported your validator keys. If you \
                     misplace your database and then run with this flag you risk being slashed."
    )]
    init_slashing_protection: Option<String>,
    #[clap(
        long,
        help = "If present, do not attempt to discover new validators in the validators-dir. Validators \
                will need to be manually added to the validator_definitions.yml file."
    )]
    disable_auto_discover: Option<String>,
    #[clap(
        long,
        help = "If present, the validator client will still poll for duties if the beacon
                      node is not synced."
    )]
    allow_unsynced: Option<String>,
    #[clap(
        long,
        help = "If present, the validator client will use longer timeouts for requests \
                        made to the beacon node. This flag is generally not recommended, \
                        longer timeouts can cause missed duties when fallbacks are used."
    )]
    use_long_timeouts: Option<String>,
    #[clap(
        long,
        value_name = "CERTIFICATE-FILES",
        takes_value = true,
        help = "Comma-separated paths to custom TLS certificates to use when connecting \
                        to a beacon node. These certificates must be in PEM format and are used \
                        in addition to the OS trust store. Commas must only be used as a \
                        delimiter, and must not be part of the certificate path."
    )]
    beacon_nodes_tls_certs: Option<String>,
    #[clap(
        long,
        help = "Specify your custom graffiti to be included in blocks.",
        value_name = "GRAFFITI",
        takes_value = true
    )]
    graffiti: Option<String>,
    #[clap(
        long,
        help = "Specify a graffiti file to load validator graffitis from.",
        value_name = "GRAFFITI-FILE",
        takes_value = true,
        conflicts_with = "graffiti"
    )]
    graffiti_file: Option<String>,
    #[clap(
        long,
        help = "Enable the RESTful HTTP API server. Disabled by default.",
        takes_value = false
    )]
    http: Option<String>,
    #[clap(
        long,
        value_name = "ADDRESS",
        help = "Set the address for the HTTP address. The HTTP server is not encrypted \
                        and therefore it is unsafe to publish on a public network. When this \
                        flag is used, it additionally requires the explicit use of the \
                        `--unencrypted-http-transport` flag to ensure the user is aware of the \
                        risks involved. For access via the Internet, users should apply \
                        transport-layer security like a HTTPS reverse-proxy or SSH tunnelling.",
        requires = "unencrypted_http_transport"
    )]
    http_address: Option<String>,
    #[clap(
        long,
        help = "This is a safety flag to ensure that the user is aware that the http \
                        transport is unencrypted and using a custom HTTP address is unsafe.",
        requires = "http_address"
    )]
    unencrypted_http_transport: Option<String>,
    #[clap(
        long,
        value_name = "PORT",
        help = "Set the listen TCP port for the RESTful HTTP API server.",
        default_value = "5062",
        takes_value = true
    )]
    http_port: Option<String>,
    #[clap(
        long,
        value_name = "ORIGIN",
        help = "Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5062).",
        takes_value = true
    )]
    http_allow_origin: Option<String>,
    #[clap(
        long,
        help = "Enable the Prometheus metrics HTTP server. Disabled by default.",
        takes_value = false
    )]
    metrics: Option<String>,
    #[clap(
        long,
        value_name = "ADDRESS",
        help = "Set the listen address for the Prometheus metrics HTTP server.",
        default_value = "127.0.0.1",
        takes_value = true
    )]
    metrics_address: Option<String>,
    #[clap(
        long,
        value_name = "PORT",
        help = "Set the listen TCP port for the Prometheus metrics HTTP server.",
        default_value = "5064",
        takes_value = true
    )]
    metrics_port: Option<String>,
    #[clap(
        long,
        value_name = "ORIGIN",
        help = "Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5064).",
        takes_value = true
    )]
    metrics_allow_origin: Option<String>,
    #[clap(
        long,
        value_name = "ADDRESS",
        help = "Enables the monitoring service for sending system metrics to a remote endpoint. \
                This can be used to monitor your setup on certain services (e.g. beaconcha.in). \
                This flag sets the endpoint where the beacon node metrics will be sent. \
                Note: This will send information to a remote sever which may identify and associate your \
                validators, IP address and other personal information. Always use a HTTPS connection \
                and never provide an untrusted URL.",
        takes_value = true
    )]
    monitoring_endpoint: Option<String>,
    #[clap(
        long,
        value_name = "ENABLE_DOPPELGANGER_PROTECTION",
        help = "If this flag is set, Lighthouse will delay startup for three epochs and \
                    monitor for messages on the network by any of the validators managed by this \
                    client. This will result in three (possibly four) epochs worth of missed \
                    attestations. If an attestation is detected during this period, it means it is \
                    very likely that you are running a second validator client with the same keys. \
                    This validator client will immediately shutdown if this is detected in order \
                    to avoid potentially committing a slashable offense. Use this flag in order to \
                    ENABLE this functionality, without this flag Lighthouse will begin attesting \
                    immediately.",
        takes_value = false
    )]
    enable_doppelganger_protection: Option<String>,
}

#[derive(Parser)]
#[clap(
    name = "boot_node",
    about = "Start a special Lighthouse process that only serves as a discv5 boot-node. This \
        process will *not* import blocks or perform most typical beacon node functions. Instead, it \
        will simply run the discv5 service and assist nodes on the network to discover each other. \
        This is the recommended way to provide a network boot-node since it has a reduced attack \
        surface compared to a full beacon node."
)]
struct BootNode {
    #[clap(
        long,
        value_name = "IP-ADDRESS",
        help = "The external IP address/ DNS address to broadcast to other peers on how to reach this node. \
    If a DNS address is provided, the enr-address is set to the IP address it resolves to and \
     does not auto-update based on PONG responses in discovery.",
        required = true,
        takes_value = true,
        conflicts_with = "network_dir"
    )]
    enr_address: Option<String>,
    #[clap(
        long,
        value_name = "PORT",
        help = "The UDP port to listen on.",
        default_value = "9000",
        takes_value = true
    )]
    port: Option<String>,
    #[clap(
        long,
        value_name = "ADDRESS",
        help = "The address the bootnode will listen for UDP connections.",
        default_value = "0.0.0.0",
        takes_value = true
    )]
    listen_address: Option<String>,
    #[clap(
        long,
        allow_hyphen_values = true,
        value_name = "ENR-LIST/Multiaddr",
        help = "One or more comma-delimited base64-encoded ENR's or multiaddr strings of peers to \
        initially add to the local routing table",
        takes_value = true
    )]
    boot_nodes: Option<String>,
    #[clap(
        long,
        value_name = "PORT",
        help = "The UDP port of the boot node's ENR. This is the port that external peers will dial \
        to reach this boot node. Set this only if the external port differs from the listening port.",
        takes_value = true,
        conflicts_with = "network_dir"
    )]
    enr_udp_port: Option<String>,
    #[clap(
        short = 'x',
        long,
        help = "Discovery can automatically update the node's local ENR with an external IP address \
        and port as seen by other peers on the network. , This enables this feature."
    )]
    enable_enr_auto_update: Option<String>,
    #[clap(
        long,
        help = "Disables discv5 packet filter. Useful for testing in smaller networks"
    )]
    disable_packet_filter: Option<String>,
    #[clap(
        value_name = "NETWORK_DIR",
        long,
        help = "The directory which contains the enr and it's assoicated private key",
        takes_value = true
    )]
    network_dir: Option<String>,
}


