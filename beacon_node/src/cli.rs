use clap::{ArgEnum, Args, Subcommand};
pub use clap::{IntoApp, Parser};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(name = "beacon_node",
visible_aliases = &["b", "bn", "beacon"],
author = "Sigma Prime <contact@sigmaprime.io>",
about = "The primary component which connects to the Ethereum 2.0 P2P network and \
                downloads, verifies and stores blocks. Provides a HTTP API for querying \
                the beacon chain and publishing messages to the network.",
)]
pub struct BeaconNode {
    #[clap(
        long,
        value_name = "DIR",
        help = "Data directory for network keys. Defaults to network/ inside the beacon node \
                       dir."
    )]
    pub network_dir: Option<String>,
    #[clap(
        long,
        value_name = "DIR",
        help = "Data directory for the freezer database."
    )]
    pub freezer_dir: Option<String>,
    #[clap(
        long,
        help = "Subscribe to all subnets regardless of validator count. \
                       This will also advertise the beacon node as being long-lived subscribed to all subnets."
    )]
    pub subscribe_all_subnets: bool,
    #[clap(
        long,
        help = "Import and aggregate all attestations, regardless of validator subscriptions. \
                       This will only import attestations from already-subscribed subnets, use with \
                       --subscribe-all-subnets to ensure all attestations are received for import."
    )]
    pub import_all_attestations: bool,
    #[clap(
        long,
        help = "Disables the discovery packet filter. Useful for testing in smaller networks"
    )]
    pub disable_packet_filter: bool,
    #[clap(
        long,
        help = "Shutdown beacon node as soon as sync is completed. Backfill sync will \
                       not be performed before shutdown."
    )]
    pub shutdown_after_sync: bool,
    #[clap(
        long,
        short = 'z',
        help = "Sets all listening TCP/UDP ports to 0, allowing the OS to choose some \
                       arbitrary free ports."
    )]
    pub zero_ports: bool,
    #[clap(
        long,
        value_name = "ADDRESS",
        help = "The address lighthouse will listen for UDP and TCP connections.",
        default_value = "0.0.0.0"
    )]
    pub listen_address: String,
    #[clap(
        long,
        value_name = "PORT",
        help = "The TCP/UDP port to listen on. The UDP port can be modified by the --discovery-port flag.",
        default_value = "9000"
    )]
    pub port: String,
    #[clap(
        long,
        value_name = "PORT",
        help = "The UDP port that discovery will listen on. Defaults to `port`"
    )]
    pub discovery_port: Option<String>,
    #[clap(long, help = "The target number of peers.", default_value = "50")]
    target_peers: String,
    #[clap(
        long,
        allow_hyphen_values = true,
        value_name = "ENR/MULTIADDR LIST",
        help = "One or more comma-delimited base64-encoded ENR's to bootstrap the p2p network. Multiaddr is also supported."
    )]
    pub boot_nodes: Option<String>,
    #[clap(
        long,
        value_name = "INTEGER",
        help = "Lighthouse's network can be tuned for bandwidth/performance. Setting this to a high value, will increase the bandwidth lighthouse uses, increasing the likelihood of redundant information in exchange for faster communication. This can increase profit of validators marginally by receiving messages faster on the network. Lower values decrease bandwidth usage, but makes communication slower which can lead to validator performance reduction. Values are in the range [1,5].",
        default_value = "3",
        hide = true
    )]
    pub network_load: String,
    #[clap(
        long,
        help = "Disables UPnP support. Setting this will prevent Lighthouse from attempting to automatically establish external port mappings."
    )]
    pub disable_upnp: bool,
    #[clap(
        long,
        help = "Prevents sending various client identification information."
    )]
    pub private: bool,
    #[clap(
        long,
        value_name = "PORT",
        help = "The UDP port of the local ENR. Set this only if you are sure other nodes can connect to your local node on this port."
    )]
    pub enr_udp_port: Option<String>,
    #[clap(
        long,
        value_name = "PORT",
        help = "The TCP port of the local ENR. Set this only if you are sure other nodes can connect to your local node on this port.\
                    The --port flag is used if this is not set."
    )]
    pub enr_tcp_port: Option<String>,
    #[clap(
        long,
        value_name = "ADDRESS",
        help = "The IP address/ DNS address to broadcast to other peers on how to reach this node. \
                If a DNS address is provided, the enr-address is set to the IP address it resolves to and \
                does not auto-update based on PONG responses in discovery. \
                Set this only if you are sure other nodes can connect to your local node on this address. \
                Discovery will automatically find your external address,if possible.",
        requires = "enr_udp_port"
    )]
    pub enr_address: Option<String>,
    #[clap(
        short = 'e',
        long,
        help = "Sets the local ENR IP address and port to match those set for lighthouse. \
                Specifically, the IP address will be the value of --listen-address and the UDP port will be --discovery-port."
    )]
    pub enr_match: Option<String>,
    #[clap(
        short = 'x',
        long,
        help = "Discovery automatically updates the nodes local ENR with an external IP address and port as seen by other peers on the network. \
                This disables this feature, fixing the ENR's IP/PORT to those specified on boot."
    )]
    pub disable_enr_auto_update: Option<String>,
    #[clap(
        long,
        value_name = "MULTIADDR",
        help = "One or more comma-delimited multiaddrs to manually connect to a libp2p peer \
                       without an ENR."
    )]
    pub libp2p_addresses: Option<String>,
    #[clap(
        long,
        help = "Disables the discv5 discovery protocol. The node will not search for new peers or participate in the discovery protocol."
    )]
    pub disable_discovery: bool,
    #[clap(
        long,
        value_name = "TRUSTED_PEERS",
        help = "One or more comma-delimited trusted peer ids which always have the highest score according to the peer scoring system."
    )]
    pub trusted_peers: Option<String>,
    #[clap(
        long,
        help = "Enable the RESTful HTTP API server. Disabled by default."
    )]
    pub http: bool,
    #[clap(
        long,
        value_name = "ADDRESS",
        help = "Set the listen address for the RESTful HTTP API server.",
        default_value = "127.0.0.1"
    )]
    pub http_address: String,
    #[clap(
        long,
        value_name = "PORT",
        help = "Set the listen TCP port for the RESTful HTTP API server.",
        default_value = "5052"
    )]
    pub http_port: String,
    #[clap(
        long,
        value_name = "ORIGIN",
        help = "Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5052)."
    )]
    pub http_allow_origin: Option<String>,
    #[clap(
        long,
        help = "Disable serving of legacy data on the /config/spec endpoint. May be \
                       disabled by default in a future release."
    )]
    pub http_disable_legacy_spec: Option<String>,
    #[clap(
        long,
        help = "Serves the RESTful HTTP API server over TLS. This feature is currently \
                    experimental.",
        requires = "http_tls_cert",
        requires = "http_tls_key"
    )]
    pub http_enable_tls: bool,
    #[clap(
        long,
        help = "The path of the certificate to be used when serving the HTTP API server \
                    over TLS."
    )]
    pub http_tls_cert: Option<String>,
    #[clap(
        long,
        help = "The path of the private key to be used when serving the HTTP API server \
                    over TLS. Must not be password-protected."
    )]
    pub http_tls_key: Option<String>,
    #[clap(
        long,
        help = "Forces the HTTP to indicate that the node is synced when sync is actually \
                    stalled. This is useful for very small testnets. TESTING ONLY. DO NOT USE ON \
                    MAINNET."
    )]
    pub http_allow_sync_stalled: Option<String>,
    #[clap(
        long,
        help = "Enable the Prometheus metrics HTTP server. Disabled by default."
    )]
    pub metrics: bool,
    #[clap(
        long,
        value_name = "ADDRESS",
        help = "Set the listen address for the Prometheus metrics HTTP server.",
        default_value = "127.0.0.1"
    )]
    pub metrics_address: String,
    #[clap(
        long,
        value_name = "PORT",
        help = "Set the listen TCP port for the Prometheus metrics HTTP server.",
        default_value = "5054"
    )]
    pub metrics_port: String,
    #[clap(
        long,
        value_name = "ORIGIN",
        help = "Set the value of the Access-Control-Allow-Origin response HTTP header. \
                    Use * to allow any origin (not recommended in production). \
                    If no value is supplied, the CORS allowed origin is set to the listen \
                    address of this server (e.g., http://localhost:5054)."
    )]
    pub metrics_allow_origin: Option<String>,
    #[clap(
        long,
        value_name = "ADDRESS",
        help = "Enables the monitoring service for sending system metrics to a remote endpoint. \
                This can be used to monitor your setup on certain services (e.g. beaconcha.in). \
                This flag sets the endpoint where the beacon node metrics will be sent. \
                Note: This will send information to a remote sever which may identify and associate your \
                validators, IP address and other personal information. Always use a HTTPS connection \
                and never provide an untrusted URL."
    )]
    pub monitoring_endpoint: Option<String>,
    #[clap(
        long,
        help = "Standard option for a staking beacon node. Equivalent to \
                `lighthouse bn --http --eth1 `. This will enable the http server on localhost:5052 \
                and try connecting to an eth1 node on localhost:8545"
    )]
    pub staking: bool,
    #[clap(
        long,
        help = "If present the node will connect to an eth1 node. This is required for \
                       block production, you must use this flag if you wish to serve a validator."
    )]
    pub eth1: bool,
    #[clap(
        long,
        conflicts_with = "eth1",
        help = "If present, uses an eth1 backend that generates static dummy data.\
                      Identical to the method used at the 2019 Canada interop."
    )]
    pub dummy_eth1: Option<String>,
    #[clap(
        long,
        value_name = "HTTP-ENDPOINT",
        help = "Deprecated. Use --eth1-endpoints."
    )]
    pub eth1_endpoint: Option<String>,
    #[clap(
        long,
        value_name = "HTTP-ENDPOINTS",
        conflicts_with = "eth1_endpoint",
        help = "One or more comma-delimited server endpoints for web3 connection. \
                       If multiple endpoints are given the endpoints are used as fallback in the \
                       given order. Also enables the --eth1 flag. \
                       Defaults to http://127.0.0.1:8545."
    )]
    pub eth1_endpoints: Option<String>,
    #[clap(
        long,
        value_name = "PURGE-CACHE",
        help = "Purges the eth1 block and deposit caches"
    )]
    pub eth1_purge_cache: bool,
    #[clap(
        long,
        value_name = "BLOCKS",
        help = "Specifies the number of blocks that a deposit log query should span. \
                    This will reduce the size of responses from the Eth1 endpoint.",
        default_value = "1000"
    )]
    pub eth1_blocks_per_log_query: String,
    #[clap(
        long,
        value_name = "SLOT_COUNT",
        help = "Specifies how often a freezer DB restore point should be stored. \
                       Cannot be changed after initialization. \
                       [default: 2048 (mainnet) or 64 (minimal)]"
    )]
    pub slots_per_restore_point: Option<String>,
    #[clap(
        long,
        value_name = "SIZE",
        help = "Specifies how many blocks the database should cache in memory [default: 5]"
    )]
    pub block_cache_size: Option<String>,
    #[clap(
        long,
        help = "Enable the features necessary to run merge testnets. This feature \
                       is unstable and is for developers only."
    )]
    pub merge: bool,
    #[clap(
        long,
        value_name = "EXECUTION-ENDPOINTS",
        help = "One or more comma-delimited server endpoints for HTTP JSON-RPC connection. \
                       If multiple endpoints are given the endpoints are used as fallback in the \
                       given order. Also enables the --merge flag. \
                       If this flag is omitted and the --eth1-endpoints is supplied, those values \
                       will be used. Defaults to http://127.0.0.1:8545."
    )]
    pub execution_endpoints: Option<String>,
    #[clap(
        long,
        value_name = "FEE-RECIPIENT",
        help = "Once the merge has happened, this address will receive transaction fees \
                       collected from any blocks produced by this node. Defaults to a junk \
                       address whilst the merge is in development stages. THE DEFAULT VALUE \
                       WILL BE REMOVED BEFORE THE MERGE ENTERS PRODUCTION",
        requires = "merge"
    )]
    pub fee_recipient: Option<String>,
    #[clap(
        long,
        help = "If present, the chain database will be deleted. Use with caution."
    )]
    pub purge_db: Option<String>,
    #[clap(
        long,
        help = "If present, apply compaction to the database on start-up. Use with caution. \
                       It is generally not recommended unless auto-compaction is disabled."
    )]
    pub compact_db: Option<String>,
    #[clap(
        long,
        help = "Enable or disable automatic compaction of the database on finalization.",
        default_value = "true"
    )]
    pub auto_compact_db: String,
    #[clap(
        long,
        help = "Specify your custom graffiti to be included in blocks. \
                    Defaults to the current version and commit, truncated to fit in 32 bytes. ",
        value_name = "GRAFFITI"
    )]
    pub graffiti: Option<String>,
    #[clap(
        long,
        help = "Refuse to skip more than this many slots when processing a block or attestation. \
                    This prevents nodes on minority forks from wasting our time and disk space, \
                    but could also cause unnecessary consensus failures, so is disabled by default.",
        value_name = "NUM_SLOTS"
    )]
    pub max_skip_slots: Option<String>,
    #[clap(
        long,
        help = "Run a slasher alongside the beacon node. It is currently only recommended for \
                     expert users because of the immaturity of the slasher UX and the extra \
                     resources required."
    )]
    pub slasher: bool,
    #[clap(
        long,
        help = "Set the slasher's database directory.",
        value_name = "PATH",
        requires = "slasher"
    )]
    pub slasher_dir: Option<String>,
    #[clap(
        long,
        help = "Configure how often the slasher runs batch processing.",
        value_name = "SECONDS",
        requires = "slasher"
    )]
    pub slasher_update_period: Option<String>,
    #[clap(
        long,
        help = "Set the delay from the start of the slot at which the slasher should ingest \
                     attestations. Only effective if the slasher-update-period is a multiple of the \
                     slot duration.",
        value_name = "SECONDS",
        requires = "slasher"
    )]
    pub slasher_slot_offset: Option<String>,
    #[clap(
        long,
        help = "Configure how many epochs of history the slasher keeps. Immutable after \
                     initialization.",
        value_name = "EPOCHS",
        requires = "slasher"
    )]
    pub slasher_history_length: Option<String>,
    #[clap(
        long,
        help = "Maximum size of the MDBX database used by the slasher.",
        value_name = "GIGABYTES",
        requires = "slasher"
    )]
    pub slasher_max_db_size: Option<String>,
    #[clap(
        long,
        help = "Set the maximum number of attestation roots for the slasher to cache",
        value_name = "COUNT",
        requires = "slasher"
    )]
    pub slasher_att_cache_size: Option<String>,
    #[clap(
        long,
        help = "Number of epochs per validator per chunk stored on disk.",
        value_name = "EPOCHS",
        requires = "slasher"
    )]
    pub slasher_chunk_size: Option<String>,
    #[clap(
        long,
        help = "Number of validators per chunk stored on disk.",
        value_name = "NUM_VALIDATORS",
        requires = "slasher"
    )]
    pub slasher_validator_chunk_size: Option<String>,
    #[clap(
        long,
        help = "Broadcast slashings found by the slasher to the rest of the network \
                       [disabled by default].",
        requires = "slasher"
    )]
    pub slasher_broadcast: Option<String>,
    #[clap(
        long,
        help = "Specify a weak subjectivity checkpoint in `block_root:epoch` format to verify \
                     the node's sync against. The block root should be 0x-prefixed. Note that this \
                     flag is for verification only, to perform a checkpoint sync from a recent \
                     state use --checkpoint-sync-url.",
        value_name = "WSS_CHECKPOINT"
    )]
    pub wss_checkpoint: Option<String>,
    #[clap(
        long,
        help = "Set a checkpoint state to start syncing from. Must be aligned and match \
                       --checkpoint-block. Using --checkpoint-sync-url instead is recommended.",
        value_name = "STATE_SSZ",
        requires = "checkpoint_block"
    )]
    pub checkpoint_state: Option<String>,
    #[clap(
        long,
        help = "Set a checkpoint block to start syncing from. Must be aligned and match \
                       --checkpoint-state. Using --checkpoint-sync-url instead is recommended.",
        value_name = "BLOCK_SSZ",
        requires = "checkpoint_state"
    )]
    pub checkpoint_block: Option<String>,
    #[clap(
        long,
        help = "Set the remote beacon node HTTP endpoint to use for checkpoint sync.",
        value_name = "BEACON_NODE",
        conflicts_with = "checkpoint_state"
    )]
    pub checkpoint_sync_url: Option<String>,
    #[clap(
        long,
        help = "After a checkpoint sync, reconstruct historic states in the database."
    )]
    pub reconstruct_historic_state: bool,
    #[clap(
        long,
        help = "Enables the automatic detection and monitoring of validators connected to the \
                    HTTP API and using the subnet subscription endpoint. This generally has the \
                    effect of providing additional logging and metrics for locally controlled \
                    validators."
    )]
    pub validator_monitor_auto: Option<String>,
    #[clap(
        long,
        help = "A comma-separated list of 0x-prefixed validator public keys. \
                        These validators will receive special monitoring and additional \
                        logging.",
        value_name = "PUBKEYS"
    )]
    pub validator_monitor_pubkeys: Option<String>,
    #[clap(
        long,
        help = "As per --validator-monitor-pubkeys, but the comma-separated list is \
                    contained within a file at the given path.",
        value_name = "PATH"
    )]
    pub validator_monitor_file: Option<String>,
    #[clap(
        long,
        help = "Disable the timeouts applied to some internal locks by default. This can \
                       lead to less spurious failures on slow hardware but is considered \
                       experimental as it may obscure performance issues."
    )]
    pub disable_lock_timeouts: bool,
}
