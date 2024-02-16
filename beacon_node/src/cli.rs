use std::{num::NonZeroUsize, path::PathBuf};

use crate::IpAddr;
use crate::NetworkConfigurable;
use beacon_chain::chain_config::DEFAULT_RE_ORG_MAX_EPOCHS_SINCE_FINALIZATION;
pub use clap::Parser;
use lighthouse_network::{Multiaddr, PeerIdSerialized};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::ops::RangeInclusive;
use types::Address;
use types::Epoch;
use types::ProgressiveBalancesMode;

const NETWORK_LOAD_RANGE: RangeInclusive<u8> = 1..=5;

fn network_load_in_range(s: &str) -> Result<u8, String> {
    let network_load: u8 = s
        .parse()
        .map_err(|_| format!("`{s}` isn't a port number"))?;
    if NETWORK_LOAD_RANGE.contains(&network_load) {
        Ok(network_load)
    } else {
        Err(format!(
            "network-load not in range {}-{}",
            NETWORK_LOAD_RANGE.start(),
            NETWORK_LOAD_RANGE.end()
        ))
    }
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(
    name = "beacon_node",
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
    pub network_dir: Option<PathBuf>,

    #[clap(
        long,
        value_name = "DIR",
        help = "Data directory for the freezer database."
    )]
    pub freezer_dir: Option<PathBuf>,

    #[clap(
        long,
        value_name = "DIR",
        help = "Data directory for the blobs database."
    )]
    pub blobs_dir: Option<PathBuf>,

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
        value_delimiter = ' ',
        num_args = 0..=2,
        value_name = "ADDRESS",
        help = "The address lighthouse will listen for UDP and TCP connections. To listen \
                over IpV4 and IpV6 set this flag twice with the different values.\n\
                Examples:\n\
                - --listen-address '0.0.0.0' will listen over IPv4.\n\
                - --listen-address '::' will listen over IPv6.\n\
                - --listen-address '0.0.0.0' --listen-address '::' will listen over both \
                - --listen-address '0.0.0.0' '::' will also listen over both \
                IPv4 and IPv6. The order of the given addresses is not relevant. However, \
                multiple IPv4, or multiple IPv6 addresses will not be accepted.",
        default_value = "0.0.0.0"
    )]
    pub listen_addresses: Vec<std::net::IpAddr>,

    #[clap(
        long,
        value_name = "PORT",
        default_value_t = 9000,
        help = "The TCP/UDP ports to listen on. There are two UDP ports. \
                The discovery UDP port will be set to this value and the Quic UDP port will be set to this value + 1. The discovery port can be modified by the \
                --discovery-port flag and the quic port can be modified by the --quic-port flag. If listening over both IPv4 and IPv6 the --port flag \
                will apply to the IPv4 address and --port6 to the IPv6 address."
    )]
    pub port: u16,

    #[clap(
        long,
        value_name = "PORT",
        default_value_t = 9090,
        help = "The TCP/UDP ports to listen on over IPv6 when listening over both IPv4 and \
                IPv6. Defaults to 9090 when required. The Quic UDP port will be set to this value + 1."
    )]
    pub port6: u16,

    #[clap(
        long,
        value_name = "PORT",
        help = "The UDP port that discovery will listen on. Defaults to `port`"
    )]
    pub discovery_port: Option<u16>,

    #[clap(
        long,
        value_name = "PORT",
        help = "The UDP port that quic will listen on. Defaults to `port + 1`"
    )]
    pub quic_port: Option<u16>,

    #[clap(
        long,
        value_name = "PORT",
        help = "The UDP port that discovery will listen on over IPv6 if listening over \
                both IPv4 and IPv6. Defaults to `port6`"
    )]
    pub discovery_port6: Option<u16>,

    #[clap(
        long,
        value_name = "PORT",
        help = "The UDP port that quic will listen on over IPv6 if listening over \
                both IPv4 and IPv6. Defaults to `port6` + 1"
    )]
    pub quic_port6: Option<u16>,

    #[clap(long, help = "The target number of peers.")]
    pub target_peers: Option<usize>,

    #[clap(
        long,
        allow_hyphen_values = true,
        value_delimiter = ',',
        value_name = "ENR/MULTIADDR LIST",
        help = "One or more comma-delimited base64-encoded ENR's to bootstrap the p2p network. Multiaddr is also supported."
    )]
    pub boot_nodes: Option<Vec<String>>,

    #[clap(
        long,
        value_name = "INTEGER",
        default_value_t = 3,
        hide = true,
        value_parser = network_load_in_range,
        help = "Lighthouse's network can be tuned for bandwidth/performance. \
                Setting this to a high value, will increase the bandwidth lighthouse uses, \
                increasing the likelihood of redundant information in exchange for faster \
                communication. This can increase profit of validators marginally by receiving \
                messages faster on the network. Lower values decrease bandwidth usage, but makes \
                communication slower which can lead to validator performance reduction. Values \
                are in the range [1,5].", 
    )]
    pub network_load: u8,

    #[clap(
        long,
        help = "Disables UPnP support. Setting this will prevent Lighthouse from attempting to \
                automatically establish external port mappings."
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
        help = "The UDP port of the local ENR. Set this only if you are sure other nodes can \
                connect to your local node on this port."
    )]
    pub enr_udp_port: Option<NonZeroU16>,

    #[clap(
        long,
        value_name = "PORT",
        help = "The quic UDP4 port that will be set on the local ENR. Set this only if you are sure other nodes \
                can connect to your local node on this port over IPv4."
    )]
    pub enr_quic_port: Option<NonZeroU16>,

    #[clap(
        long,
        value_name = "PORT",
        help = "The UDP6 port of the local ENR. Set this only if you are sure other nodes \
                can connect to your local node on this port over IPv6."
    )]
    pub enr_udp6_port: Option<NonZeroU16>,

    #[clap(
        long,
        value_name = "PORT",
        help = "The quic UDP6 port that will be set on the local ENR. Set this only if you are sure other nodes \
                can connect to your local node on this port over IPv6."
    )]
    pub enr_quic6_port: Option<NonZeroU16>,

    #[clap(
        long,
        value_name = "PORT",
        help = "The TCP4 port of the local ENR. Set this only if you are sure other nodes \
                can connect to your local node on this port over IPv4. The --port flag is \
                used if this is not set."
    )]
    pub enr_tcp_port: Option<NonZeroU16>,

    #[clap(
        long,
        value_name = "PORT",
        help = "The TCP6 port of the local ENR. Set this only if you are sure other nodes \
                can connect to your local node on this port over IPv6. The --port6 flag is \
                used if this is not set."
    )]
    pub enr_tcp6_port: Option<NonZeroU16>,

    #[clap(
        long,
        value_name = "PORT",
        value_delimiter = ' ',
        num_args = 0..=2,
        help = "The IP address/ DNS address to broadcast to other peers on how to reach \
                this node. If a DNS address is provided, the enr-address is set to the IP \
                address it resolves to and does not auto-update based on PONG responses in \
                discovery. Set this only if you are sure other nodes can connect to your \
                local node on this address. This will update the `ip4` or `ip6` ENR fields \
                accordingly. To update both, set this flag twice with the different values."
    )]
    pub enr_addresses: Option<Vec<String>>,

    #[clap(
        long,
        short = 'e',
        help = "Sets the local ENR IP address and port to match those set for lighthouse. \
                Specifically, the IP address will be the value of --listen-address and the \
                UDP port will be --discovery-port."
    )]
    pub enr_match: bool,

    #[clap(
        long,
        short = 'x',
        help = "Discovery automatically updates the nodes local ENR with an external IP address \
                and port as seen by other peers on the network. \
                This disables this feature, fixing the ENR's IP/PORT to those specified on boot."
    )]
    pub disable_enr_auto_update: bool,

    #[clap(
        long,
        value_delimiter = ',',
        value_name = "MULTIADDR",
        help = "One or more comma-delimited multiaddrs to manually connect to a libp2p peer \
                without an ENR."
    )]
    pub libp2p_addresses: Option<Vec<Multiaddr>>,

    // NOTE: This is hidden because it is primarily a developer feature for testnets and
    // debugging. We remove it from the list to avoid clutter.
    #[clap(
        long,
        hide = true,
        help = "Disables the discv5 discovery protocol. The node will not search for new peers or \
                participate in the discovery protocol."
    )]
    pub disable_discovery: bool,

    #[clap(
        long,
        help = "Disables the quic transport. The node will rely solely on the TCP transport for libp2p connections."
    )]
    pub disable_quic: bool,

    #[clap(
        long,
        hide = true,
        help = "Disables peer scoring in lighthouse. WARNING: This is a dev only flag is only meant to be used in local testing scenarios \
                Using this flag on a real network may cause your node to become eclipsed and see a different view of the network"
    )]
    pub disable_peer_scoring: bool,

    #[clap(
        long,
        value_name = "TRUSTED_PEERS",
        value_delimiter = ',',
        help = "One or more comma-delimited trusted peer ids which always have the highest \
                score according to the peer scoring system."
    )]
    pub trusted_peers: Option<Vec<PeerIdSerialized>>,

    #[clap(
        long,
        help = "Attempts to download blocks all the way back to genesis when checkpoint syncing."
    )]
    pub genesis_backfill: bool,

    #[clap(
        long,
        help = "Lighthouse by default does not discover private IP addresses. Set this flag to enable connection attempts to local addresses."
    )]
    pub enable_private_discovery: bool,

    #[clap(
        long,
        value_name = "PROTOCOL_NAME:TOKENS/TIME_IN_SECONDS",
        value_delimiter = ';',
        // min_values = 0 TODO doesnt exist
        help =  "Enables the outbound rate limiter (requests made by this node).\
                \
                Rate limit quotas per protocol can be set in the form of \
                <protocol_name>:<tokens>/<time_in_seconds>. To set quotas for multiple protocols, \
                separate them by ';'. If the self rate limiter is enabled and a protocol is not \
                present in the configuration, the quotas used for the inbound rate limiter will be \
                used."
    )]
    pub self_limiter: Option<String>,

    #[clap(
        long,
        help = "Sets this beacon node at be a block proposer only node. \
                This will run the beacon node in a minimal configuration that is sufficient for block publishing only. This flag should be used \
                for a beacon node being referenced by validator client using the --proposer-node flag. This configuration is for enabling more secure setups."
    )]
    pub proposer_only: bool,

    #[clap(
        long,
        value_name = "PROTOCOL_NAME:TOKENS/TIME_IN_SECONDS",
        value_delimiter = ';',
        hide = true,
        help = "Configures the inbound rate limiter (requests received by this node).\
                \
                Rate limit quotas per protocol can be set in the form of \
                <protocol_name>:<tokens>/<time_in_seconds>. To set quotas for multiple protocols, \
                separate them by ';'. If the inbound rate limiter is enabled and a protocol is not \
                present in the configuration, the default quotas will be used. \
                \
                This is enabled by default, using default quotas. To disable rate limiting pass \
                `disabled` to this option instead."
    )]
    pub inbound_rate_limiter: Option<String>,

    #[clap(
        long,
        help = "Disable the backfill sync rate-limiting. This allow users to just sync the entire chain as fast \
                as possible, however it can result in resource contention which degrades staking performance. Stakers \
                should generally choose to avoid this flag since backfill sync is not required for staking."
    )]
    pub disable_backfill_rate_limiting: bool,

    /* REST API related arguments */
    #[clap(
        long,
        group = "enable_http",
        help = "Enable the RESTful HTTP API server. Disabled by default."
    )]
    pub http: bool,

    #[clap(
        long,
        value_name = "ADDRESS",
        requires = "enable_http",
        default_value_t = Ipv4Addr::new(127,0,0,1),
        help = "Set the listen address for the RESTful HTTP API server.",
    )]
    pub http_address: Ipv4Addr,

    #[clap(
        long,
        value_name = "PORT",
        requires = "enable_http",
        help = "Set the listen TCP port for the RESTful HTTP API server."
    )]
    pub http_port: u16,

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
        value_name = "FORK",
        requires = "enable-http",
        help = "Serve the spec for a specific hard fork on /eth/v1/config/spec. It should \
                not be necessary to set this flag."
    )]
    pub http_spec_fork: Option<String>,

    #[clap(
        long,
        requires = "http-tls-cert",
        requires = "http-tls-key",
        help = "Serves the RESTful HTTP API server over TLS. This feature is currently \
                experimental."
    )]
    pub http_enable_tls: bool,

    #[clap(
        long,
        requires = "enable-http",
        value_name = "PATH",
        help = "The path of the certificate to be used when serving the HTTP API server \
                over TLS."
    )]
    pub http_tls_cert: Option<PathBuf>,

    #[clap(
        long,
        requires = "enable-http",
        value_name = "PATH",
        help = "The path of the private key to be used when serving the HTTP API server \
                over TLS. Must not be password-protected."
    )]
    pub http_tls_key: Option<PathBuf>,

    #[clap(
        long,
        requires = "enable-http",
        help = "Forces the HTTP to indicate that the node is synced when sync is actually \
                stalled. This is useful for very small testnets. TESTING ONLY. DO NOT USE ON \
                MAINNET."
    )]
    pub http_allow_sync_stalled: bool,

    #[clap(
        long,
        value_name = "N",
        default_value_t = 1,
        requires = "enable-http",
        help = "Multiplier to apply to the length of HTTP server-sent-event (SSE) channels. \
                Increasing this value can prevent messages from being dropped."
    )]
    pub http_sse_capacity_multiplier: usize,

    #[clap(
        long,
        value_name = "STATUS_CODE",
        default_value_t = 202,
        requires = "enable-http",
        help = "Status code to send when a block that is already known is POSTed to the \
                HTTP API."
    )]
    pub http_duplicate_block_status: u16,

    #[clap(
        long,
        value_name = "BOOLEAN",
        default_value_t = true,
        requires = "enable-http",
        help = "The beacon processor is a scheduler which provides quality-of-service and \
                DoS protection. When set to \"true\", HTTP API requests will be queued and scheduled \
                alongside other tasks. When set to \"false\", HTTP API responses will be executed \
                immediately."
    )]
    pub http_enable_beacon_processor: bool,

    /* Prometheus metrics HTTP server related arguments */
    #[clap(
        long,
        help = "Enable the Prometheus metrics HTTP server. Disabled by default."
    )]
    pub metrics: bool,

    #[clap(
        long,
        value_name = "ADDRESS",
        requires = "metrics",
        default_value_t = Ipv4Addr::new(127,0,0,1),
        help = "Set the listen address for the Prometheus metrics HTTP server.",
    )]
    pub metrics_address: Ipv4Addr,

    #[clap(
        long,
        value_name = "PORT",
        requires = "metrics",
        default_value_t = 5054,
        help = "Set the listen TCP port for the Prometheus metrics HTTP server."
    )]
    pub metrics_port: u16,

    #[clap(
        long,
        value_name = "ORIGIN",
        requires = "metrics",
        help = "Set the value of the Access-Control-Allow-Origin response HTTP header. \
                Use * to allow any origin (not recommended in production). \
                If no value is supplied, the CORS allowed origin is set to the listen \
                address of this server (e.g., http://localhost:5054)."
    )]
    pub metrics_allow_origin: Option<String>,

    #[clap(
        long,
        value_name = "ORIGIN",
        help = "Some HTTP API requests can be optimised by caching the shufflings at each epoch. \
                This flag allows the user to set the shuffling cache size in epochs. \
                Shufflings are dependent on validator count and setting this value to a large \
                number can consume a large amount of memory."
    )]
    pub shuffling_cache_size: Option<usize>,

    /* Monitoring metrics */
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
        value_name = "SECONDS",
        default_value_t = 60,
        requires = "monitoring-endpoint",
        help = "Defines how many seconds to wait between each message sent to \
                the monitoring-endpoint. Default: 60s"
    )]
    pub monitoring_endpoint_period: u64,

    /* Standard staking flags */
    #[clap(
        long,
        group = "enable_http",
        help = "Standard option for a staking beacon node. This will enable the HTTP server \
                on localhost:5052 and import deposit logs from the execution node. This is \
                equivalent to `--http` on merge-ready networks, or `--http --eth1` pre-merge"
    )]
    pub staking: bool,

    /* Eth1 Integration */
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
    pub dummy_eth1: bool,

    #[clap(
        long,
        conflicts_with = "eth1",
        help = "Purges the eth1 block and deposit caches."
    )]
    pub eth1_purge_cache: bool,

    #[clap(
        long,
        value_name = "BLOCKS",
        default_value_t = 1000,
        help = "Specifies the number of blocks that a deposit log query should span. \
                This will reduce the size of responses from the Eth1 endpoint."
    )]
    pub eth1_blocks_per_log_query: usize,

    #[clap(
        long,
        value_name = "BLOCKS",
        help = "Specifies the distance between the Eth1 chain head and the last block which \
                should be imported into the cache. Setting this value lower can help \
                compensate for irregular Proof-of-Work block times, but setting it too low \
                can make the node vulnerable to re-orgs."
    )]
    pub eth1_cache_follow_distance: Option<u64>,

    #[clap(
        long,
        value_name = "SLOT_COUNT",
        help = "Specifies how often a freezer DB restore point should be stored. \
                Cannot be changed after initialization. \
                [default: 8192 (mainnet) or 64 (minimal)]"
    )]
    pub slots_per_restore_point: Option<u64>,

    #[clap(
        long,
        value_name = "N",
        default_value = "1",
        help = "The number of epochs to wait between running the migration of data from the \
                hot DB to the cold DB. Less frequent runs can be useful for minimizing disk \
                writes"
    )]
    pub epochs_per_migration: Option<u64>,

    #[clap(
        long,
        value_name = "SIZE",
        default_value = "5",
        help = "Specifies how many blocks the database should cache in memory."
    )]
    pub block_cache_size: Option<NonZeroUsize>,

    #[clap(
        long,
        value_name = "SIZE",
        default_value = "1",
        help = "Specifies how many states from the freezer database should cache in memory."
    )]
    pub historic_state_cache_size: Option<NonZeroUsize>,

    /* Execution Layer Integration */
    #[clap(
        long,
        value_name = "EXECUTION-ENDPOINT",
        help = "Server endpoint for an execution layer JWT-authenticated HTTP \
                JSON-RPC connection. Uses the same endpoint to populate the \
                deposit cache."
    )]
    pub execution_endpoint: Option<String>,

    #[clap(
        long,
        value_name = "EXECUTION-JWT",
        requires = "execution_endpoint",
        alias = "jwt-secrets",
        help = "File path which contains the hex-encoded JWT secret for the \
                execution endpoint provided in the --execution-endpoint flag."
    )]
    pub execution_jwt: Option<PathBuf>,

    #[clap(
        long,
        value_name = "EXECUTION-JWT-SECRET-KEY",
        requires = "execution_endpoint",
        conflicts_with = "execution_jwt",
        alias = "jwt-secret-key",
        help = "Hex-encoded JWT secret for the \
                execution endpoint provided in the --execution-endpoint flag."
    )]
    pub execution_jwt_secret_key: Option<String>,

    #[clap(
        long,
        value_name = "EXECUTION-JWT-ID",
        requires = "execution_jwt",
        alias = "jwt-id",
        help = "Used by the beacon node to communicate a unique identifier to execution nodes \
                during JWT authentication. It corresponds to the 'id' field in the JWT claims object.\
                Set to empty by default"
    )]
    pub execution_jwt_id: Option<String>,

    #[clap(
        long,
        value_name = "EXECUTION-JWT-VERSION",
        requires = "execution_jwt",
        alias = "jwt-version",
        help = "Used by the beacon node to communicate a client version to execution nodes \
                during JWT authentication. It corresponds to the 'clv' field in the JWT claims object.\
                Set to empty by default"
    )]
    pub execution_jwt_version: Option<String>,

    #[clap(
        long,
        value_name = "SUGGESTED-FEE-RECIPIENT",
        help = "Emergency fallback fee recipient for use in case the validator client does \
                not have one configured. You should set this flag on the validator \
                client instead of (or in addition to) setting it here.",
        requires = "execution-endpoint"
    )]
    pub suggested_fee_recipient: Option<Address>,

    #[clap(
        long,
        alias = "payload-builder",
        alias = "payload-builders",
        value_name = "URL",
        help = "The URL of a service compatible with the MEV-boost API.",
        requires = "execution-endpoint"
    )]
    pub builder: Option<String>,

    #[clap(
        long,
        value_name = "NUM",
        default_value = "1",
        help = "Unsigned integer to multiply the default execution timeouts by."
    )]
    pub execution_timeout_multiplier: Option<u32>,

    /* Deneb settings */
    #[clap(
        long,
        value_name = "FILE",
        help = "Path to a json file containing the trusted setup params. \
                NOTE: This will override the trusted setup that is generated \
                from the mainnet kzg ceremony. Use with caution"
    )]
    pub trusted_setup_file_override: Option<String>,

    /* Database purging and compaction. */
    #[clap(
        long,
        help = "If present, the chain database will be deleted. Use with caution."
    )]
    pub purge_db: bool,

    #[clap(
        long,
        help = "If present, apply compaction to the database on start-up. Use with caution. \
                It is generally not recommended unless auto-compaction is disabled."
    )]
    pub compact_db: bool,

    #[clap(
        long,
        value_name = "BOOLEAN",
        help = "Enable or disable automatic compaction of the database on finalization.",
        default_value = "true"
    )]
    pub auto_compact_db: bool,

    #[clap(
        long,
        value_name = "BOOLEAN",
        help = "Prune execution payloads from Lighthouse's database. This saves space but \
                imposes load on the execution client, as payloads need to be \
                reconstructed and sent to syncing peers.",
        default_value = "true"
    )]
    pub prune_payloads: bool,

    #[clap(
        long,
        value_name = "BOOLEAN",
        help = "Prune blobs from Lighthouse's database when they are older than the \
                data availability boundary relative to the current epoch.",
        default_value = "true"
    )]
    pub prune_blobs: bool,

    #[clap(
        long,
        value_name = "EPOCHS",
        default_value_t = 1,
        help = "The epoch interval with which to prune blobs from Lighthouse's \
                database when they are older than the data availability boundary \
                relative to the current epoch."
    )]
    pub epochs_per_blob_prune: u64,

    #[clap(
        long,
        value_name = "EPOCHS",
        default_value_t = 0,
        help = "The margin for blob pruning in epochs. The oldest blobs are pruned \
                up until data_availability_boundary - blob_prune_margin_epochs."
    )]
    pub blob_prune_margin_epochs: u64,

    /* Misc. */
    #[clap(
        long,
        value_name = "GRAFFITI",
        help = "Specify your custom graffiti to be included in blocks. \
                Defaults to the current version and commit, truncated to fit in 32 bytes. "
    )]
    pub graffiti: Option<String>,

    #[clap(
        long,
        value_name = "NUM_SLOTS",
        help = "Refuse to skip more than this many slots when processing a block or attestation. \
                This prevents nodes on minority forks from wasting our time and disk space, \
                but could also cause unnecessary consensus failures, so is disabled by default."
    )]
    pub max_skip_slots: Option<u64>,

    /* Slasher */
    #[clap(
        long,
        help = "Run a slasher alongside the beacon node. It is currently only recommended for \
                expert users because of the immaturity of the slasher UX and the extra \
                resources required."
    )]
    pub slasher: bool,

    #[clap(
        long,
        value_name = "PATH",
        requires = "slasher",
        help = "Set the slasher's database directory."
    )]
    pub slasher_dir: Option<PathBuf>,

    #[clap(
        long,
        value_name = "SECONDS",
        requires = "slasher",
        help = "Configure how often the slasher runs batch processing."
    )]
    pub slasher_update_period: Option<u64>,

    #[clap(
        long,
        value_name = "SECONDS",
        requires = "slasher",
        help = "Set the delay from the start of the slot at which the slasher should ingest \
                attestations. Only effective if the slasher-update-period is a multiple of the \
                slot duration."
    )]
    pub slasher_slot_offset: Option<f64>,

    #[clap(
        long,
        value_name = "EPOCHS",
        requires = "slasher",
        help = "Configure how many epochs of history the slasher keeps. Immutable after \
                initialization."
    )]
    pub slasher_history_length: Option<usize>,

    #[clap(
        long,
        value_name = "GIGABYTES",
        requires = "slasher",
        help = "Maximum size of the MDBX database used by the slasher."
    )]
    pub slasher_max_db_size: Option<usize>,

    #[clap(
        long,
        value_name = "COUNT",
        requires = "slasher",
        help = "Set the maximum number of attestation roots for the slasher to cache"
    )]
    pub slasher_att_cache_size: Option<NonZeroUsize>,

    #[clap(
        long,
        value_name = "EPOCHS",
        requires = "slasher",
        help = "Number of epochs per validator per chunk stored on disk."
    )]
    pub slasher_chunk_size: Option<usize>,

    #[clap(
        long,
        value_name = "NUM_VALIDATORS",
        requires = "slasher",
        help = "Number of validators per chunk stored on disk."
    )]
    pub slasher_validator_chunk_size: Option<usize>,

    #[clap(
        long,
        requires = "slasher",
        help = "Broadcast slashings found by the slasher to the rest of the network \
                [disabled by default]."
    )]
    pub slasher_broadcast: bool,

    // TODO we need to show the correct slasher variants
    #[clap(
        long,
        requires = "slasher",
        value_enum,
        help = "Set the database backend to be used by the slasher"
    )]
    pub slasher_backend: slasher::DatabaseBackend,

    #[clap(
        long,
        value_name = "WSS_CHECKPOINT",
        help = "Specify a weak subjectivity checkpoint in `block_root:epoch` format to verify \
                the node's sync against. The block root should be 0x-prefixed. Note that this \
                flag is for verification only, to perform a checkpoint sync from a recent \
                state use --checkpoint-sync-url."
    )]
    pub wss_checkpoint: Option<String>,

    #[clap(
        long,
        value_name = "STATE_SSZ",
        requires = "checkpoint-block",
        help = "Set a checkpoint state to start syncing from. Must be aligned and match \
                --checkpoint-block. Using --checkpoint-sync-url instead is recommended."
    )]
    pub checkpoint_state: Option<Vec<u8>>,

    #[clap(
        long,
        value_name = "BLOCK_SSZ",
        requires = "checkpoint-state",
        help = "Set a checkpoint block to start syncing from. Must be aligned and match \
                --checkpoint-state. Using --checkpoint-sync-url instead is recommended."
    )]
    pub checkpoint_block: Option<Vec<u8>>,

    #[clap(
        long,
        value_name = "BEACON_NODE",
        conflicts_with = "checkpoint-state",
        help = "Set the remote beacon node HTTP endpoint to use for checkpoint sync."
    )]
    pub checkpoint_sync_url: Option<String>,

    #[clap(
        long,
        value_name = "SECONDS",
        default_value = "180",
        help = "Set the remote beacon node HTTP endpoint to use for checkpoint sync."
    )]
    pub checkpoint_sync_url_timeout: Option<u64>,

    #[clap(
        long,
        conflicts_with = "checkpoint_sync_url",
        conflicts_with = "checkpoint_state",
        help = "Enable syncing from genesis, which is generally insecure and incompatible with data availability checks. \
                Checkpoint syncing is the preferred method for syncing a node. \
                Only use this flag when testing. DO NOT use on mainnet!"
    )]
    pub allow_insecure_genesis_sync: bool,

    #[clap(
        long,
        help = "After a checkpoint sync, reconstruct historic states in the database. \
                This requires syncing all the way back to genesis."
    )]
    pub reconstruct_historic_states: bool,

    #[clap(
        long,
        help = "Enables the automatic detection and monitoring of validators connected to the \
                HTTP API and using the subnet subscription endpoint. This generally has the \
                effect of providing additional logging and metrics for locally controlled \
                validators."
    )]
    pub validator_monitor_auto: bool,

    #[clap(
        long,
        value_name = "PUBKEYS",
        help = "A comma-separated list of 0x-prefixed validator public keys. \
                These validators will receive special monitoring and additional \
                logging."
    )]
    pub validator_monitor_pubkeys: Option<String>,

    #[clap(
        long,
        value_name = "PATH",
        help = "As per --validator-monitor-pubkeys, but the comma-separated list is \
                contained within a file at the given path."
    )]
    pub validator_monitor_file: Option<PathBuf>,

    #[clap(
        long,
        value_name = "INTEGER",
        default_value_t = 64,
        help = "Once the validator monitor reaches this number of local validators \
                it will stop collecting per-validator Prometheus metrics and issuing \
                per-validator logs. Instead, it will provide aggregate metrics and logs. \
                This avoids infeasibly high cardinality in the Prometheus database and \
                high log volume when using many validators."
    )]
    pub validator_monitor_individual_tracking_threshold: usize,

    #[clap(
        long,
        help = "Disable the timeouts applied to some internal locks by default. This can \
                lead to less spurious failures on slow hardware but is considered \
                experimental as it may obscure performance issues."
    )]
    pub disable_lock_timeouts: bool,

    #[clap(
        long,
        help = "Do not attempt to reorg late blocks from other validators when proposing."
    )]
    pub disable_proposer_reorgs: bool,

    #[clap(
        long,
        value_name = "PERCENT",
        conflicts_with = "disable_proposer_reorgs",
        default_value_t = 20,
        help = "Percentage of vote weight below which to attempt a proposer reorg."
    )]
    pub proposer_reorg_threshold: u64,

    #[clap(
        long,
        value_name = "EPOCHS",
        conflicts_with = "disable_proposer_reorgs",
        default_value_t = DEFAULT_RE_ORG_MAX_EPOCHS_SINCE_FINALIZATION,
        help = "Maximum number of epochs since finalization at which proposer reorgs are allowed."
    )]
    pub proposer_reorg_epochs_since_finalization: Epoch,

    #[clap(
        long,
        value_name = "MILLISECONDS",
        conflicts_with = "disable_proposer_reorgs",
        help = "Maximum delay after the start of the slot at which to propose a reorging \
                block. Lower values can prevent failed reorgs by ensuring the block has \
                ample time to propagate and be processed by the network. The default is \
                1/12th of a slot (1 second on mainnet)."
    )]
    pub proposer_reorg_cutoff: Option<u64>,

    #[clap(
        long,
        value_delimiter = ',',
        value_name = "N1,N2,...",
        conflicts_with = "disable_proposer_reorgs",
        help = "Comma-separated list of integer offsets which can be used to avoid \
                proposing reorging blocks at certain slots. An offset of N means that \
                reorging proposals will not be attempted at any slot such that \
                `slot % SLOTS_PER_EPOCH == N`. By default only re-orgs at offset 0 will be \
                avoided. Any offsets supplied with this flag will impose additional \
                restrictions."
    )]
    pub proposer_reorg_disallowed_offsets: Option<Vec<u64>>,

    #[clap(
        long,
        value_name = "MILLISECONDS",
        help = "The time before the start of a proposal slot at which payload attributes \
                should be sent. Low values are useful for execution nodes which don't \
                improve their payload after the first call, and high values are useful \
                for ensuring the EL is given ample notice. Default: 1/3 of a slot."
    )]
    pub prepare_payload_lookahead: Option<u64>,

    #[clap(
        long,
        help = "Send payload attributes with every fork choice update. This is intended for \
                use by block builders, relays and developers. You should set a fee \
                recipient on this BN and also consider adjusting the \
                --prepare-payload-lookahead flag."
    )]
    pub always_prepare_payload: bool,

    #[clap(
        long,
        value_name = "MILLISECONDS",
        default_value = "250",
        help = "Set the maximum number of milliseconds to wait for fork choice before \
                proposing a block. You can prevent waiting at all by setting the timeout \
                to 0, however you risk proposing atop the wrong parent block."
    )]
    pub fork_choice_before_proposal_timeout: Option<u64>,

    #[clap(
        long,
        hide = true,
        help = "Paranoid enough to be reading the source? Nice. This flag reverts some \
                block proposal optimisations and forces the node to check every attestation \
                it includes super thoroughly. This may be useful in an emergency, but not \
                otherwise."
    )]
    pub paranoid_block_proposal: bool,

    #[clap(
        long,
        value_name = "SLOTS",
        default_value = "3",
        help = "If this node is proposing a block and has seen this number of skip slots \
                on the canonical chain in a row, it will NOT query any connected builders, \
                and will use the local execution engine for payload construction."
    )]
    pub builder_fallback_skips: Option<usize>,

    #[clap(
        long,
        value_name = "SLOTS_PER_EPOCH",
        default_value = "8",
        help = "If this node is proposing a block and has seen this number of skip slots \
                on the canonical chain in the past `SLOTS_PER_EPOCH`, it will NOT query \
                any connected builders, and will use the local execution engine for \
                payload construction."
    )]
    pub builder_fallback_skips_per_epoch: Option<usize>,

    #[clap(
        long,
        value_name = "EPOCHS",
        default_value_t = 3,
        help = "If this node is proposing a block and the chain has not finalized within \
                this number of epochs, it will NOT query any connected builders, \
                and will use the local execution engine for payload construction. Setting \
                this value to anything less than 2 will cause the node to NEVER query \
                connected builders. Setting it to 2 will cause this condition to be hit \
                if there are skips slots at the start of an epoch, right before this node \
                is set to propose."
    )]
    pub builder_fallback_epochs_since_finalization: usize,

    #[clap(
        long,
        default_value_t = false,
        help = "This flag disables all checks related to chain health. This means the builder \
                API will always be used for payload construction, regardless of recent chain \
                conditions."
    )]
    pub builder_fallback_disable_checks: bool,

    #[clap(long, help = "This flag is deprecated and has no effect.")]
    pub builder_profit_threshold: Option<u64>,

    #[clap(
        long,
        requires = "builder",
        help = "The HTTP user agent to send alongside requests to the builder URL. The \
                default is Lighthouse's version string."
    )]
    pub builder_user_agent: Option<String>,

    #[clap(
        long,
        help = "When present, Lighthouse will forget the payload statuses of any \
                already-imported blocks. This can assist in the recovery from a consensus \
                failure caused by the execution layer."
    )]
    pub reset_payload_statuses: bool,

    #[clap(
        long,
        help = "Explicitly disables syncing of deposit logs from the execution node. \
                This overrides any previous option that depends on it. \
                Useful if you intend to run a non-validating beacon node."
    )]
    pub disable_deposit_contract_sync: bool,

    #[clap(
        long,
        help = "Force Lighthouse to verify every execution block hash with the execution \
                client during finalized sync. By default block hashes will be checked in \
                Lighthouse and only passed to the EL if initial verification fails."
    )]
    pub disable_optimistic_finalized_sync: bool,

    #[clap(
        long,
        help = "Act as a full node supporting light clients on the p2p network \
                [experimental]"
    )]
    pub light_client_server: bool,

    #[clap(
        long,
        group = "enable_http",
        help = "Enable the graphical user interface and all its requirements. \
                This enables --http and --validator-monitor-auto and enables SSE logging."
    )]
    pub gui: bool,

    #[clap(long, help = "This flag is deprecated and has no effect.")]
    pub always_prefer_builder_payload: bool,

    #[clap(
        long,
        value_name = "PATH",
        help = "If a block succeeds gossip validation whilst failing full validation, store \
                the block SSZ as a file at this path. This feature is only recommended for \
                developers. This directory is not pruned, users should be careful to avoid \
                filling up their disks."
    )]
    pub invalid_gossip_verified_blocks_path: Option<PathBuf>,

    #[clap(
        long,
        value_name = "MODE",
        value_enum,
        help = "Control the progressive balances cache mode. The default `fast` mode uses \
                the cache to speed up fork choice. A more conservative `checked` mode \
                compares the cache's results against results without the cache. If \
                there is a mismatch, it falls back to the cache-free result. Using the \
                default `fast` mode is recommended unless advised otherwise by the \
                Lighthouse team."
    )]
    pub progressive_balances: Option<ProgressiveBalancesMode>,

    #[clap(
        long,
        value_name = "INTEGER",
        help = "Specifies the maximum concurrent tasks for the task scheduler. Increasing \
                this value may increase resource consumption. Reducing the value \
                may result in decreased resource usage and diminished performance. The \
                default value is the number of logical CPU cores on the host."
    )]
    pub beacon_processor_max_workers: Option<usize>,

    #[clap(
        long,
        value_name = "INTEGER",
        default_value_t = 16384,
        help = "Specifies the length of the inbound event queue. \
                Higher values may prevent messages from being dropped while lower values \
                may help protect the node from becoming overwhelmed."
    )]
    pub beacon_processor_work_queue_len: usize,

    #[clap(
        long,
        value_name = "INTEGER",
        default_value_t = 12288,
        help = "Specifies the length of the queue for messages requiring delayed processing. \
                Higher values may prevent messages from being dropped while lower values \
                may help protect the node from becoming overwhelmed."
    )]
    pub beacon_processor_reprocess_queue_len: usize,

    #[clap(
        long,
        value_name = "INTEGER",
        default_value_t = 64,
        help = "Specifies the number of gossip attestations in a signature verification batch. \
                Higher values may reduce CPU usage in a healthy network whilst lower values may \
                increase CPU usage in an unhealthy or hostile network."
    )]
    pub beacon_processor_attestation_batch_size: usize,

    #[clap(
        long,
        value_name = "INTEGER",
        default_value_t = 64,
        help = "Specifies the number of gossip aggregate attestations in a signature \
                verification batch. Higher values may reduce CPU usage in a healthy \
                network while lower values may increase CPU usage in an unhealthy or hostile network."
    )]
    pub beacon_processor_aggregate_batch_size: usize,

    #[clap(long, help = "This flag is deprecated and has no effect.")]
    pub disable_duplicate_warn_logs: bool,
}

impl BeaconNode {
    pub fn enable_http(&self) -> bool {
        self.http || self.gui || self.staking
    }
}

impl NetworkConfigurable for BeaconNode {
    fn get_network_dir(&self) -> Option<PathBuf> {
        self.network_dir.clone()
    }
    fn get_port(&self) -> u16 {
        self.port
    }
    fn get_boot_nodes(&self) -> Option<Vec<String>> {
        self.boot_nodes.clone()
    }
    fn get_enr_udp_port(&self) -> Option<NonZeroU16> {
        self.enr_udp_port
    }
    fn get_enr_addresses(&self) -> Option<Vec<String>> {
        self.enr_addresses.clone()
    }
    fn is_disable_packet_filter(&self) -> bool {
        self.disable_packet_filter
    }
    fn is_zero_ports(&self) -> bool {
        false
    }
    fn get_listen_addresses(&self) -> Vec<IpAddr> {
        self.listen_addresses.clone()
    }
    fn get_port6(&self) -> u16 {
        self.port6
    }
    fn get_disc_port(&self) -> Option<u16> {
        self.discovery_port
    }
    fn get_disc6_port(&self) -> Option<u16> {
        self.discovery_port6
    }
    fn get_quic_port(&self) -> Option<u16> {
        self.quic_port
    }
    fn get_quic6_port(&self) -> Option<u16> {
        self.quic_port6
    }
}
