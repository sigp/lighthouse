use crate::listen_addr::{ListenAddr, ListenAddress};
use crate::rpc::config::OutboundRateLimiterConfig;
use crate::types::GossipKind;
use crate::{Enr, PeerIdSerialized};
use directory::{
    DEFAULT_BEACON_NODE_DIR, DEFAULT_HARDCODED_NETWORK, DEFAULT_NETWORK_DIR, DEFAULT_ROOT_DIR,
};
use discv5::{Discv5Config, Discv5ConfigBuilder};
use libp2p::gossipsub::{
    FastMessageId, GossipsubConfig, GossipsubConfigBuilder, GossipsubMessage, MessageId,
    RawGossipsubMessage, ValidationMode,
};
use libp2p::Multiaddr;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use types::{ForkContext, ForkName};

/// The maximum transmit size of gossip messages in bytes pre-merge.
const GOSSIP_MAX_SIZE: usize = 1_048_576; // 1M
/// The maximum transmit size of gossip messages in bytes post-merge.
const GOSSIP_MAX_SIZE_POST_MERGE: usize = 10 * 1_048_576; // 10M

/// The cache time is set to accommodate the circulation time of an attestation.
///
/// The p2p spec declares that we accept attestations within the following range:
///
/// ```ignore
/// ATTESTATION_PROPAGATION_SLOT_RANGE = 32
/// attestation.data.slot + ATTESTATION_PROPAGATION_SLOT_RANGE >= current_slot >= attestation.data.slot
/// ```
///
/// Therefore, we must accept attestations across a span of 33 slots (where each slot is 12
/// seconds). We add an additional second to account for the 500ms gossip clock disparity, and
/// another 500ms for "fudge factor".
pub const DUPLICATE_CACHE_TIME: Duration = Duration::from_secs(33 * 12 + 1);

// We treat uncompressed messages as invalid and never use the INVALID_SNAPPY_DOMAIN as in the
// specification. We leave it here for posterity.
// const MESSAGE_DOMAIN_INVALID_SNAPPY: [u8; 4] = [0, 0, 0, 0];
const MESSAGE_DOMAIN_VALID_SNAPPY: [u8; 4] = [1, 0, 0, 0];

/// The maximum size of gossip messages.
pub fn gossip_max_size(is_merge_enabled: bool) -> usize {
    if is_merge_enabled {
        GOSSIP_MAX_SIZE_POST_MERGE
    } else {
        GOSSIP_MAX_SIZE
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
/// Network configuration for lighthouse.
pub struct Config {
    /// Data directory where node's keyfile is stored
    pub network_dir: PathBuf,

    /// IP addresses to listen on.
    listen_addresses: ListenAddress,

    /// The address to broadcast to peers about which address we are listening on. None indicates
    /// that no discovery address has been set in the CLI args.
    pub enr_address: (Option<Ipv4Addr>, Option<Ipv6Addr>),

    /// The udp4 port to broadcast to peers in order to reach back for discovery.
    pub enr_udp4_port: Option<u16>,

    /// The tcp4 port to broadcast to peers in order to reach back for libp2p services.
    pub enr_tcp4_port: Option<u16>,

    /// The udp6 port to broadcast to peers in order to reach back for discovery.
    pub enr_udp6_port: Option<u16>,

    /// The tcp6 port to broadcast to peers in order to reach back for libp2p services.
    pub enr_tcp6_port: Option<u16>,

    /// Target number of connected peers.
    pub target_peers: usize,

    /// Gossipsub configuration parameters.
    #[serde(skip)]
    pub gs_config: GossipsubConfig,

    /// Discv5 configuration parameters.
    #[serde(skip)]
    pub discv5_config: Discv5Config,

    /// List of nodes to initially connect to.
    pub boot_nodes_enr: Vec<Enr>,

    /// List of nodes to initially connect to, on Multiaddr format.
    pub boot_nodes_multiaddr: Vec<Multiaddr>,

    /// List of libp2p nodes to initially connect to.
    pub libp2p_nodes: Vec<Multiaddr>,

    /// List of trusted libp2p nodes which are not scored.
    pub trusted_peers: Vec<PeerIdSerialized>,

    /// Client version
    pub client_version: String,

    /// Disables the discovery protocol from starting.
    pub disable_discovery: bool,

    /// Attempt to construct external port mappings with UPnP.
    pub upnp_enabled: bool,

    /// Subscribe to all subnets for the duration of the runtime.
    pub subscribe_all_subnets: bool,

    /// Import/aggregate all attestations recieved on subscribed subnets for the duration of the
    /// runtime.
    pub import_all_attestations: bool,

    /// A setting specifying a range of values that tune the network parameters of lighthouse. The
    /// lower the value the less bandwidth used, but the slower messages will be received.
    pub network_load: u8,

    /// Indicates if the user has set the network to be in private mode. Currently this
    /// prevents sending client identifying information over identify.
    pub private: bool,

    /// Shutdown beacon node after sync is completed.
    pub shutdown_after_sync: bool,

    /// List of extra topics to initially subscribe to as strings.
    pub topics: Vec<GossipKind>,

    /// Whether metrics are enabled.
    pub metrics_enabled: bool,

    /// Whether light client protocols should be enabled.
    pub enable_light_client_server: bool,

    /// Configuration for the outbound rate limiter (requests made by this node).
    pub outbound_rate_limiter_config: Option<OutboundRateLimiterConfig>,
}

impl Config {
    /// Sets the listening address to use an ipv4 address. The discv5 ip_mode and table filter are
    /// adjusted accordingly to ensure addresses that are present in the enr are globally
    /// reachable.
    pub fn set_ipv4_listening_address(&mut self, addr: Ipv4Addr, tcp_port: u16, udp_port: u16) {
        self.listen_addresses = ListenAddress::V4(ListenAddr {
            addr,
            udp_port,
            tcp_port,
        });
        self.discv5_config.ip_mode = discv5::IpMode::Ip4;
        self.discv5_config.table_filter = |enr| enr.ip4().as_ref().map_or(false, is_global_ipv4)
    }

    /// Sets the listening address to use an ipv6 address. The discv5 ip_mode and table filter is
    /// adjusted accordingly to ensure addresses that are present in the enr are globally
    /// reachable.
    pub fn set_ipv6_listening_address(&mut self, addr: Ipv6Addr, tcp_port: u16, udp_port: u16) {
        self.listen_addresses = ListenAddress::V6(ListenAddr {
            addr,
            udp_port,
            tcp_port,
        });
        self.discv5_config.ip_mode = discv5::IpMode::Ip6 {
            enable_mapped_addresses: false,
        };
        self.discv5_config.table_filter = |enr| enr.ip6().as_ref().map_or(false, is_global_ipv6)
    }

    /// Sets the listening address to use both an ipv4 and ipv6 address. The discv5 ip_mode and
    /// table filter is adjusted accordingly to ensure addresses that are present in the enr are
    /// globally reachable.
    pub fn set_ipv4_ipv6_listening_addresses(
        &mut self,
        v4_addr: Ipv4Addr,
        tcp4_port: u16,
        udp4_port: u16,
        v6_addr: Ipv6Addr,
        tcp6_port: u16,
        udp6_port: u16,
    ) {
        self.listen_addresses = ListenAddress::DualStack(
            ListenAddr {
                addr: v4_addr,
                udp_port: udp4_port,
                tcp_port: tcp4_port,
            },
            ListenAddr {
                addr: v6_addr,
                udp_port: udp6_port,
                tcp_port: tcp6_port,
            },
        );

        self.discv5_config.ip_mode = discv5::IpMode::Ip6 {
            enable_mapped_addresses: true,
        };
        self.discv5_config.table_filter = |enr| match (&enr.ip4(), &enr.ip6()) {
            (None, None) => false,
            (None, Some(ip6)) => is_global_ipv6(ip6),
            (Some(ip4), None) => is_global_ipv4(ip4),
            (Some(ip4), Some(ip6)) => is_global_ipv4(ip4) && is_global_ipv6(ip6),
        };
    }

    pub fn set_listening_addr(&mut self, listen_addr: ListenAddress) {
        match listen_addr {
            ListenAddress::V4(ListenAddr {
                addr,
                udp_port,
                tcp_port,
            }) => self.set_ipv4_listening_address(addr, tcp_port, udp_port),
            ListenAddress::V6(ListenAddr {
                addr,
                udp_port,
                tcp_port,
            }) => self.set_ipv6_listening_address(addr, tcp_port, udp_port),
            ListenAddress::DualStack(
                ListenAddr {
                    addr: ip4addr,
                    udp_port: udp4_port,
                    tcp_port: tcp4_port,
                },
                ListenAddr {
                    addr: ip6addr,
                    udp_port: udp6_port,
                    tcp_port: tcp6_port,
                },
            ) => self.set_ipv4_ipv6_listening_addresses(
                ip4addr, tcp4_port, udp4_port, ip6addr, tcp6_port, udp6_port,
            ),
        }
    }

    pub fn listen_addrs(&self) -> &ListenAddress {
        &self.listen_addresses
    }
}

impl Default for Config {
    /// Generate a default network configuration.
    fn default() -> Self {
        // WARNING: this directory default should be always overwritten with parameters
        // from cli for specific networks.
        let network_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_ROOT_DIR)
            .join(DEFAULT_HARDCODED_NETWORK)
            .join(DEFAULT_BEACON_NODE_DIR)
            .join(DEFAULT_NETWORK_DIR);

        // Note: Using the default config here. Use `gossipsub_config` function for getting
        // Lighthouse specific configuration for gossipsub.
        let gs_config = GossipsubConfigBuilder::default()
            .build()
            .expect("valid gossipsub configuration");

        // Discv5 Unsolicited Packet Rate Limiter
        let filter_rate_limiter = Some(
            discv5::RateLimiterBuilder::new()
                .total_n_every(10, Duration::from_secs(1)) // Allow bursts, average 10 per second
                .ip_n_every(9, Duration::from_secs(1)) // Allow bursts, average 9 per second
                .node_n_every(8, Duration::from_secs(1)) // Allow bursts, average 8 per second
                .build()
                .expect("The total rate limit has been specified"),
        );

        // discv5 configuration
        let discv5_config = Discv5ConfigBuilder::new()
            .enable_packet_filter()
            .session_cache_capacity(5000)
            .request_timeout(Duration::from_secs(1))
            .query_peer_timeout(Duration::from_secs(2))
            .query_timeout(Duration::from_secs(30))
            .request_retries(1)
            .enr_peer_update_min(10)
            .query_parallelism(5)
            .disable_report_discovered_peers()
            .ip_limit() // limits /24 IP's in buckets.
            .incoming_bucket_limit(8) // half the bucket size
            .filter_rate_limiter(filter_rate_limiter)
            .filter_max_bans_per_ip(Some(5))
            .filter_max_nodes_per_ip(Some(10))
            .table_filter(|enr| enr.ip4().map_or(false, |ip| is_global_ipv4(&ip))) // Filter non-global IPs
            .ban_duration(Some(Duration::from_secs(3600)))
            .ping_interval(Duration::from_secs(300))
            .build();

        // NOTE: Some of these get overridden by the corresponding CLI default values.
        Config {
            network_dir,
            listen_addresses: ListenAddress::V4(ListenAddr {
                addr: Ipv4Addr::UNSPECIFIED,
                udp_port: 9000,
                tcp_port: 9000,
            }),
            enr_address: (None, None),
            enr_udp4_port: None,
            enr_tcp4_port: None,
            enr_udp6_port: None,
            enr_tcp6_port: None,
            target_peers: 50,
            gs_config,
            discv5_config,
            boot_nodes_enr: vec![],
            boot_nodes_multiaddr: vec![],
            libp2p_nodes: vec![],
            trusted_peers: vec![],
            client_version: lighthouse_version::version_with_platform(),
            disable_discovery: false,
            upnp_enabled: true,
            network_load: 3,
            private: false,
            subscribe_all_subnets: false,
            import_all_attestations: false,
            shutdown_after_sync: false,
            topics: Vec::new(),
            metrics_enabled: false,
            enable_light_client_server: false,
            outbound_rate_limiter_config: None,
        }
    }
}

/// Controls sizes of gossipsub meshes to tune a Lighthouse node's bandwidth/performance.
pub struct NetworkLoad {
    pub name: &'static str,
    pub mesh_n_low: usize,
    pub outbound_min: usize,
    pub mesh_n: usize,
    pub mesh_n_high: usize,
    pub gossip_lazy: usize,
    pub history_gossip: usize,
    pub heartbeat_interval: Duration,
}

impl From<u8> for NetworkLoad {
    fn from(load: u8) -> NetworkLoad {
        match load {
            1 => NetworkLoad {
                name: "Low",
                mesh_n_low: 1,
                outbound_min: 1,
                mesh_n: 3,
                mesh_n_high: 4,
                gossip_lazy: 3,
                history_gossip: 3,
                heartbeat_interval: Duration::from_millis(1200),
            },
            2 => NetworkLoad {
                name: "Low",
                mesh_n_low: 2,
                outbound_min: 2,
                mesh_n: 4,
                mesh_n_high: 8,
                gossip_lazy: 3,
                history_gossip: 3,
                heartbeat_interval: Duration::from_millis(1000),
            },
            3 => NetworkLoad {
                name: "Average",
                mesh_n_low: 3,
                outbound_min: 2,
                mesh_n: 5,
                mesh_n_high: 10,
                gossip_lazy: 3,
                history_gossip: 3,
                heartbeat_interval: Duration::from_millis(700),
            },
            4 => NetworkLoad {
                name: "Average",
                mesh_n_low: 4,
                outbound_min: 3,
                mesh_n: 8,
                mesh_n_high: 12,
                gossip_lazy: 3,
                history_gossip: 3,
                heartbeat_interval: Duration::from_millis(700),
            },
            // 5 and above
            _ => NetworkLoad {
                name: "High",
                mesh_n_low: 5,
                outbound_min: 3,
                mesh_n: 10,
                mesh_n_high: 15,
                gossip_lazy: 5,
                history_gossip: 6,
                heartbeat_interval: Duration::from_millis(500),
            },
        }
    }
}

/// Return a Lighthouse specific `GossipsubConfig` where the `message_id_fn` depends on the current fork.
pub fn gossipsub_config(network_load: u8, fork_context: Arc<ForkContext>) -> GossipsubConfig {
    // The function used to generate a gossipsub message id
    // We use the first 8 bytes of SHA256(topic, data) for content addressing
    let fast_gossip_message_id = |message: &RawGossipsubMessage| {
        let data = [message.topic.as_str().as_bytes(), &message.data].concat();
        FastMessageId::from(&Sha256::digest(data)[..8])
    };
    fn prefix(
        prefix: [u8; 4],
        message: &GossipsubMessage,
        fork_context: Arc<ForkContext>,
    ) -> Vec<u8> {
        let topic_bytes = message.topic.as_str().as_bytes();
        match fork_context.current_fork() {
            ForkName::Altair | ForkName::Merge | ForkName::Capella => {
                let topic_len_bytes = topic_bytes.len().to_le_bytes();
                let mut vec = Vec::with_capacity(
                    prefix.len() + topic_len_bytes.len() + topic_bytes.len() + message.data.len(),
                );
                vec.extend_from_slice(&prefix);
                vec.extend_from_slice(&topic_len_bytes);
                vec.extend_from_slice(topic_bytes);
                vec.extend_from_slice(&message.data);
                vec
            }
            ForkName::Base => {
                let mut vec = Vec::with_capacity(prefix.len() + message.data.len());
                vec.extend_from_slice(&prefix);
                vec.extend_from_slice(&message.data);
                vec
            }
        }
    }

    let is_merge_enabled = fork_context.fork_exists(ForkName::Merge);
    let gossip_message_id = move |message: &GossipsubMessage| {
        MessageId::from(
            &Sha256::digest(
                prefix(MESSAGE_DOMAIN_VALID_SNAPPY, message, fork_context.clone()).as_slice(),
            )[..20],
        )
    };

    let load = NetworkLoad::from(network_load);

    GossipsubConfigBuilder::default()
        .max_transmit_size(gossip_max_size(is_merge_enabled))
        .heartbeat_interval(load.heartbeat_interval)
        .mesh_n(load.mesh_n)
        .mesh_n_low(load.mesh_n_low)
        .mesh_outbound_min(load.outbound_min)
        .mesh_n_high(load.mesh_n_high)
        .gossip_lazy(load.gossip_lazy)
        .fanout_ttl(Duration::from_secs(60))
        .history_length(12)
        .max_messages_per_rpc(Some(500)) // Responses to IWANT can be quite large
        .history_gossip(load.history_gossip)
        .validate_messages() // require validation before propagation
        .validation_mode(ValidationMode::Anonymous)
        .duplicate_cache_time(DUPLICATE_CACHE_TIME)
        .message_id_fn(gossip_message_id)
        .fast_message_id_fn(fast_gossip_message_id)
        .allow_self_origin(true)
        .build()
        .expect("valid gossipsub configuration")
}

/// Helper function to determine if the IpAddr is a global address or not. The `is_global()`
/// function is not yet stable on IpAddr.
#[allow(clippy::nonminimal_bool)]
fn is_global_ipv4(addr: &Ipv4Addr) -> bool {
    // check if this address is 192.0.0.9 or 192.0.0.10. These addresses are the only two
    // globally routable addresses in the 192.0.0.0/24 range.
    if u32::from_be_bytes(addr.octets()) == 0xc0000009
        || u32::from_be_bytes(addr.octets()) == 0xc000000a
    {
        return true;
    }
    !addr.is_private()
            && !addr.is_loopback()
            && !addr.is_link_local()
            && !addr.is_broadcast()
            && !addr.is_documentation()
            // shared
            && !(addr.octets()[0] == 100 && (addr.octets()[1] & 0b1100_0000 == 0b0100_0000)) &&!(addr.octets()[0] & 240 == 240 && !addr.is_broadcast())
            // addresses reserved for future protocols (`192.0.0.0/24`)
            // reserved
            && !(addr.octets()[0] == 192 && addr.octets()[1] == 0 && addr.octets()[2] == 0)
            // Make sure the address is not in 0.0.0.0/8
            && addr.octets()[0] != 0
}

/// NOTE: Docs taken from https://doc.rust-lang.org/stable/std/net/struct.Ipv6Addr.html#method.is_global
///
/// Returns true if the address appears to be globally reachable as specified by the IANA IPv6
/// Special-Purpose Address Registry. Whether or not an address is practically reachable will
/// depend on your network configuration.
///
/// Most IPv6 addresses are globally reachable; unless they are specifically defined as not
/// globally reachable.
///
/// Non-exhaustive list of notable addresses that are not globally reachable:
///
/// - The unspecified address (is_unspecified)
/// - The loopback address (is_loopback)
/// - IPv4-mapped addresses
/// - Addresses reserved for benchmarking
/// - Addresses reserved for documentation (is_documentation)
/// - Unique local addresses (is_unique_local)
/// - Unicast addresses with link-local scope (is_unicast_link_local)
// TODO: replace with [`Ipv6Addr::is_global`] once
//       [Ip](https://github.com/rust-lang/rust/issues/27709) is stable.
pub const fn is_global_ipv6(addr: &Ipv6Addr) -> bool {
    const fn is_documentation(addr: &Ipv6Addr) -> bool {
        (addr.segments()[0] == 0x2001) && (addr.segments()[1] == 0xdb8)
    }
    const fn is_unique_local(addr: &Ipv6Addr) -> bool {
        (addr.segments()[0] & 0xfe00) == 0xfc00
    }
    const fn is_unicast_link_local(addr: &Ipv6Addr) -> bool {
        (addr.segments()[0] & 0xffc0) == 0xfe80
    }
    !(addr.is_unspecified()
            || addr.is_loopback()
            // IPv4-mapped Address (`::ffff:0:0/96`)
            || matches!(addr.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
            // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
            || matches!(addr.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
            // Discard-Only Address Block (`100::/64`)
            || matches!(addr.segments(), [0x100, 0, 0, 0, _, _, _, _])
            // IETF Protocol Assignments (`2001::/23`)
            || (matches!(addr.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
                && !(
                    // Port Control Protocol Anycast (`2001:1::1`)
                    u128::from_be_bytes(addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                    // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                    || u128::from_be_bytes(addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                    // AMT (`2001:3::/32`)
                    || matches!(addr.segments(), [0x2001, 3, _, _, _, _, _, _])
                    // AS112-v6 (`2001:4:112::/48`)
                    || matches!(addr.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                    // ORCHIDv2 (`2001:20::/28`)
                    || matches!(addr.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x2F)
                ))
            || is_documentation(addr)
            || is_unique_local(addr)
            || is_unicast_link_local(addr))
}
