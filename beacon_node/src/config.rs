use crate::cli::NetworkConfigurable;
use crate::BeaconNode;
use clap_utils::GlobalConfig;
use client::{ClientConfig, ClientGenesis};
use directory::{DEFAULT_BEACON_NODE_DIR, DEFAULT_NETWORK_DIR, DEFAULT_ROOT_DIR};
use environment::RuntimeContext;
use http_api::TlsConfig;
use lighthouse_network::{multiaddr::Protocol, Enr, Multiaddr, NetworkConfig, PeerIdSerialized};
use sensitive_url::SensitiveUrl;
use slog::{info, warn, Logger};
use std::cmp;
use std::cmp::max;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use types::{Address, Checkpoint, Epoch, EthSpec, Hash256, PublicKeyBytes, GRAFFITI_BYTES_LEN};

// TODO(merge): remove this default value. It's just there to make life easy during
// early testnets.
const DEFAULT_SUGGESTED_FEE_RECIPIENT: [u8; 20] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// Gets the fully-initialized global client.
///
/// The top-level `clap` arguments should be provided as `cli_args`.
///
/// The output of this function depends primarily upon the given `cli_args`, however it's behaviour
/// may be influenced by other external services like the contents of the file system or the
/// response of some remote server.
pub fn get_config<E: EthSpec>(
    beacon_config: &BeaconNode,
    global_config: &GlobalConfig,
    context: &RuntimeContext<E>,
) -> Result<ClientConfig, String> {
    let spec = &context.eth2_config.spec;
    let log = context.log();

    let mut client_config = ClientConfig {
        data_dir: get_data_dir(global_config),
        ..Default::default()
    };

    // If necessary, remove any existing database and configuration
    if client_config.data_dir.exists() && beacon_config.purge_db {
        // Remove the chain_db.
        let chain_db = client_config.get_db_path();
        if chain_db.exists() {
            fs::remove_dir_all(chain_db)
                .map_err(|err| format!("Failed to remove chain_db: {}", err))?;
        }

        // Remove the freezer db.
        let freezer_db = client_config.get_freezer_db_path();
        if freezer_db.exists() {
            fs::remove_dir_all(freezer_db)
                .map_err(|err| format!("Failed to remove freezer_db: {}", err))?;
        }
    }

    // Create `datadir` and any non-existing parent directories.
    fs::create_dir_all(&client_config.data_dir)
        .map_err(|e| format!("Failed to create data dir: {}", e))?;

    // logs the chosen data directory
    let mut log_dir = client_config.data_dir.clone();
    // remove /beacon from the end
    log_dir.pop();
    info!(log, "Data directory initialised"; "datadir" => log_dir.into_os_string().into_string().expect("Datadir should be a valid os string"));

    /*
     * Networking
     */
    set_network_config(
        &mut client_config.network,
        beacon_config,
        &client_config.data_dir,
        log,
        false,
    )?;

    /*
     * Staking flag
     * Note: the config values set here can be overwritten by other more specific cli params
     */

    if beacon_config.staking {
        client_config.http_api.enabled = true;
        client_config.sync_eth1_chain = true;
    }

    /*
     * Http API server
     */

    if beacon_config.http {
        client_config.http_api.enabled = true;
    }

    client_config.http_api.listen_addr = beacon_config.http_address;

    client_config.http_api.listen_port = beacon_config.http_port;

    if let Some(allow_origin) = beacon_config.http_allow_origin.as_ref() {
        // Pre-validate the config value to give feedback to the user on node startup, instead of
        // as late as when the first API response is produced.
        hyper::header::HeaderValue::from_str(allow_origin.as_str())
            .map_err(|_| "Invalid allow-origin value")?;
        client_config.http_api.allow_origin = Some(allow_origin.to_string());
    }

    if beacon_config.http_disable_legacy_spec {
        client_config.http_api.serve_legacy_spec = false;
    }

    if beacon_config.http_enable_tls {
        client_config.http_api.tls_config = Some(TlsConfig {
            cert: beacon_config
                .http_tls_cert
                .clone()
                .ok_or("--http-tls-cert was not provided.")?,
            key: beacon_config
                .http_tls_key
                .clone()
                .ok_or("--http-tls-key was not provided.")?,
        });
    }

    if beacon_config.http_allow_sync_stalled {
        client_config.http_api.allow_sync_stalled = true;
    }

    /*
     * Prometheus metrics HTTP server
     */

    if beacon_config.metrics {
        client_config.http_metrics.enabled = true;
    }

    client_config.http_metrics.listen_addr = beacon_config.metrics_address;

    client_config.http_metrics.listen_port = beacon_config.metrics_port;

    if let Some(allow_origin) = beacon_config.metrics_allow_origin.as_ref() {
        // Pre-validate the config value to give feedback to the user on node startup, instead of
        // as late as when the first API response is produced.
        hyper::header::HeaderValue::from_str(allow_origin)
            .map_err(|_| "Invalid allow-origin value")?;

        client_config.http_metrics.allow_origin = Some(allow_origin.to_string());
    }

    /*
     * Explorer metrics
     */
    if let Some(monitoring_endpoint) = beacon_config.monitoring_endpoint.as_ref() {
        client_config.monitoring_api = Some(monitoring_api::Config {
            db_path: None,
            freezer_db_path: None,
            monitoring_endpoint: monitoring_endpoint.to_string(),
        });
    }

    // Log a warning indicating an open HTTP server if it wasn't specified explicitly
    // (e.g. using the --staking flag).
    if beacon_config.staking {
        warn!(
            log,
            "Running HTTP server on port {}", client_config.http_api.listen_port
        );
    }

    // Do not scrape for malloc metrics if we've disabled tuning malloc as it may cause panics.
    if global_config.disable_malloc_tuning {
        client_config.http_metrics.allocator_metrics_enabled = false;
    }

    /*
     * Eth1
     */

    // When present, use an eth1 backend that generates deterministic junk.
    //
    // Useful for running testnets without the overhead of a deposit contract.
    if beacon_config.dummy_eth1 {
        client_config.dummy_eth1_backend = true;
    }

    // When present, attempt to sync to an eth1 node.
    //
    // Required for block production.
    if beacon_config.eth1 {
        client_config.sync_eth1_chain = true;
    }

    // Defines the URL to reach the eth1 node.
    if let Some(endpoint) = beacon_config.eth1_endpoint.as_ref() {
        warn!(
            log,
            "The --eth1-endpoint flag is deprecated";
            "msg" => "please use --eth1-endpoints instead"
        );
        client_config.sync_eth1_chain = true;
        client_config.eth1.endpoints = vec![SensitiveUrl::parse(endpoint)
            .map_err(|e| format!("eth1-endpoint was an invalid URL: {:?}", e))?];
    } else if let Some(endpoints) = beacon_config.eth1_endpoints.as_ref() {
        client_config.sync_eth1_chain = true;
        client_config.eth1.endpoints = endpoints
            .split(',')
            .map(SensitiveUrl::parse)
            .collect::<Result<_, _>>()
            .map_err(|e| format!("eth1-endpoints contains an invalid URL {:?}", e))?;
    }

    client_config.eth1.blocks_per_log_query = beacon_config.eth1_blocks_per_log_query;

    if beacon_config.eth1_purge_cache {
        client_config.eth1.purge_cache = true;
    }

    if let Some(endpoints) = beacon_config.execution_endpoints.as_ref() {
        client_config.sync_eth1_chain = true;
        client_config.execution_endpoints = endpoints
            .split(',')
            .map(SensitiveUrl::parse)
            .collect::<Result<_, _>>()
            .map(Some)
            .map_err(|e| format!("execution-endpoints contains an invalid URL {:?}", e))?;
    } else if beacon_config.merge {
        client_config.execution_endpoints = Some(client_config.eth1.endpoints.clone());
    }

    client_config.suggested_fee_recipient = Some(
        beacon_config
            .fee_recipient
            // TODO(merge): remove this default value. It's just there to make life easy during
            // early testnets.
            .unwrap_or_else(|| Address::from(DEFAULT_SUGGESTED_FEE_RECIPIENT)),
    );

    client_config.freezer_db_path = beacon_config.freezer_dir.clone();

    if let Some(slots_per_restore_point) = beacon_config.slots_per_restore_point {
        client_config.store.slots_per_restore_point = slots_per_restore_point;
    } else {
        client_config.store.slots_per_restore_point = std::cmp::min(
            E::slots_per_historical_root() as u64,
            store::config::DEFAULT_SLOTS_PER_RESTORE_POINT,
        );
    }

    if let Some(block_cache_size) = beacon_config.block_cache_size {
        client_config.store.block_cache_size = block_cache_size;
    }

    client_config.store.compact_on_init = beacon_config.compact_db;
    client_config.store.compact_on_prune = beacon_config
        .auto_compact_db
        .parse()
        .map_err(|_| "auto-compact-db takes a boolean".to_string())?;

    /*
     * Zero-ports
     *
     * Replaces previously set flags.
     * Libp2p and discovery ports are set explicitly by selecting
     * a random free port so that we aren't needlessly updating ENR
     * from lighthouse.
     * Discovery address is set to localhost by default.
     */
    if beacon_config.zero_ports {
        if client_config.network.enr_address == Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))) {
            client_config.network.enr_address = None
        }
        client_config.network.libp2p_port =
            unused_port("tcp").map_err(|e| format!("Failed to get port for libp2p: {}", e))?;
        client_config.network.discovery_port =
            unused_port("udp").map_err(|e| format!("Failed to get port for discovery: {}", e))?;
        client_config.http_api.listen_port = 0;
        client_config.http_metrics.listen_port = 0;
    }

    /*
     * Load the eth2 network dir to obtain some additional config values.
     */
    let eth2_network_config = context
        .eth2_network_config
        .as_ref()
        .ok_or("Context is missing eth2 network config")?;

    client_config.eth1.deposit_contract_address = format!("{:?}", spec.deposit_contract_address);
    client_config.eth1.deposit_contract_deploy_block =
        eth2_network_config.deposit_contract_deploy_block;
    client_config.eth1.lowest_cached_block_number =
        client_config.eth1.deposit_contract_deploy_block;
    client_config.eth1.follow_distance = spec.eth1_follow_distance;
    client_config.eth1.node_far_behind_seconds =
        max(5, spec.eth1_follow_distance / 2) * spec.seconds_per_eth1_block;
    client_config.eth1.network_id = spec.deposit_network_id.into();
    client_config.eth1.chain_id = spec.deposit_chain_id.into();
    client_config.eth1.set_block_cache_truncation::<E>(spec);

    info!(
        log,
        "Deposit contract";
        "deploy_block" => client_config.eth1.deposit_contract_deploy_block,
        "address" => &client_config.eth1.deposit_contract_address
    );

    // Only append network config bootnodes if discovery is not disabled
    if !client_config.network.disable_discovery {
        if let Some(boot_nodes) = &eth2_network_config.boot_enr {
            client_config
                .network
                .boot_nodes_enr
                .extend_from_slice(boot_nodes)
        }
    }

    client_config.genesis = if let Some(genesis_state_bytes) =
        eth2_network_config.genesis_state_bytes.clone()
    {
        // Set up weak subjectivity sync, or start from the hardcoded genesis state.
        if let (Some(initial_state_path), Some(initial_block_path)) = (
            beacon_config.checkpoint_state.as_ref(),
            beacon_config.checkpoint_block.as_ref(),
        ) {
            let read = |path: &PathBuf| {
                use std::fs::File;
                use std::io::Read;
                File::open(path)
                    .and_then(|mut f| {
                        let mut buffer = vec![];
                        f.read_to_end(&mut buffer)?;
                        Ok(buffer)
                    })
                    .map_err(|e| format!("Unable to open {:?}: {:?}", path, e))
            };

            let anchor_state_bytes = read(initial_state_path)?;
            let anchor_block_bytes = read(initial_block_path)?;

            ClientGenesis::WeakSubjSszBytes {
                genesis_state_bytes,
                anchor_state_bytes,
                anchor_block_bytes,
            }
        } else if let Some(remote_bn_url) = beacon_config.checkpoint_sync_url.as_ref() {
            let url = SensitiveUrl::parse(remote_bn_url)
                .map_err(|e| format!("Invalid checkpoint sync URL: {:?}", e))?;

            ClientGenesis::CheckpointSyncUrl {
                genesis_state_bytes,
                url,
            }
        } else {
            // Note: re-serializing the genesis state is not so efficient, however it avoids adding
            // trait bounds to the `ClientGenesis` enum. This would have significant flow-on
            // effects.
            ClientGenesis::SszBytes {
                genesis_state_bytes,
            }
        }
    } else {
        if beacon_config.checkpoint_state.is_some() || beacon_config.checkpoint_sync_url.is_some() {
            return Err(
                "Checkpoint sync is not available for this network as no genesis state is known"
                    .to_string(),
            );
        }
        ClientGenesis::DepositContract
    };

    if beacon_config.reconstruct_historic_state {
        client_config.chain.reconstruct_historic_states = true;
    }

    let raw_graffiti = if let Some(graffiti) = beacon_config.graffiti.as_ref() {
        if graffiti.len() > GRAFFITI_BYTES_LEN {
            return Err(format!(
                "Your graffiti is too long! {} bytes maximum!",
                GRAFFITI_BYTES_LEN
            ));
        }

        graffiti.as_bytes()
    } else if beacon_config.private {
        b""
    } else {
        lighthouse_version::VERSION.as_bytes()
    };

    let trimmed_graffiti_len = cmp::min(raw_graffiti.len(), GRAFFITI_BYTES_LEN);
    client_config.graffiti.0[..trimmed_graffiti_len]
        .copy_from_slice(&raw_graffiti[..trimmed_graffiti_len]);

    if let Some(wss_checkpoint) = beacon_config.wss_checkpoint.as_ref() {
        let mut split = wss_checkpoint.split(':');
        let root_str = split
            .next()
            .ok_or("Improperly formatted weak subjectivity checkpoint")?;
        let epoch_str = split
            .next()
            .ok_or("Improperly formatted weak subjectivity checkpoint")?;

        if !root_str.starts_with("0x") {
            return Err(
                "Unable to parse weak subjectivity checkpoint root, must have 0x prefix"
                    .to_string(),
            );
        }

        if !root_str.chars().count() == 66 {
            return Err(
                "Unable to parse weak subjectivity checkpoint root, must have 32 bytes".to_string(),
            );
        }

        let root =
            Hash256::from_slice(&hex::decode(&root_str[2..]).map_err(|e| {
                format!("Unable to parse weak subjectivity checkpoint root: {:?}", e)
            })?);
        let epoch = Epoch::new(
            epoch_str
                .parse()
                .map_err(|_| "Invalid weak subjectivity checkpoint epoch".to_string())?,
        );

        client_config.chain.weak_subjectivity_checkpoint = Some(Checkpoint { epoch, root })
    }

    if let Some(max_skip_slots) = beacon_config.max_skip_slots.as_ref() {
        client_config.chain.import_max_skip_slots = match max_skip_slots.as_ref() {
            "none" => None,
            n => Some(
                n.parse()
                    .map_err(|_| "Invalid max-skip-slots".to_string())?,
            ),
        };
    }

    client_config.chain.max_network_size =
        lighthouse_network::gossip_max_size(spec.bellatrix_fork_epoch.is_some());

    if beacon_config.slasher {
        let slasher_dir = if let Some(slasher_dir) = beacon_config.slasher_dir.as_ref() {
            PathBuf::from(slasher_dir)
        } else {
            client_config.data_dir.join("slasher_db")
        };

        let mut slasher_config = slasher::Config::new(slasher_dir);

        if let Some(update_period) = beacon_config.slasher_update_period {
            slasher_config.update_period = update_period;
        }

        if let Some(slot_offset) = beacon_config.slasher_slot_offset {
            if slot_offset.is_finite() {
                slasher_config.slot_offset = slot_offset;
            } else {
                return Err(format!(
                    "invalid float for slasher-slot-offset: {}",
                    slot_offset
                ));
            }
        }

        if let Some(history_length) = beacon_config.slasher_history_length {
            slasher_config.history_length = history_length;
        }

        if let Some(max_db_size_gbs) = beacon_config.slasher_max_db_size {
            slasher_config.max_db_size_mbs = max_db_size_gbs * 1024;
        }

        if let Some(attestation_cache_size) = beacon_config.slasher_att_cache_size {
            slasher_config.attestation_root_cache_size = attestation_cache_size;
        }

        if let Some(chunk_size) = beacon_config.slasher_chunk_size {
            slasher_config.chunk_size = chunk_size;
        }

        if let Some(validator_chunk_size) = beacon_config.slasher_validator_chunk_size {
            slasher_config.validator_chunk_size = validator_chunk_size;
        }

        slasher_config.broadcast = beacon_config.slasher_broadcast;

        client_config.slasher = Some(slasher_config);
    }

    if beacon_config.validator_monitor_auto {
        client_config.validator_monitor_auto = true;
    }

    if let Some(pubkeys) = beacon_config.validator_monitor_pubkeys.clone() {
        let pubkeys = pubkeys
            .split(',')
            .map(PublicKeyBytes::from_str)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Invalid --validator-monitor-pubkeys value: {:?}", e))?;
        client_config
            .validator_monitor_pubkeys
            .extend_from_slice(&pubkeys);
    }

    if let Some(path) = beacon_config.validator_monitor_file.as_ref() {
        let string = fs::read(path)
            .map_err(|e| format!("Unable to read --validator-monitor-file: {}", e))
            .and_then(|bytes| {
                String::from_utf8(bytes)
                    .map_err(|e| format!("--validator-monitor-file is not utf8: {}", e))
            })?;
        let pubkeys = string
            .trim_end() // Remove trailing white space
            .split(',')
            .map(PublicKeyBytes::from_str)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Invalid --validator-monitor-file contents: {:?}", e))?;
        client_config
            .validator_monitor_pubkeys
            .extend_from_slice(&pubkeys);
    }

    if beacon_config.disable_lock_timeouts {
        client_config.chain.enable_lock_timeouts = false;
    }

    Ok(client_config)
}

/// Sets the network config from the command line arguments
pub fn set_network_config(
    config: &mut NetworkConfig,
    beacon_config: &BeaconNode,
    data_dir: &Path,
    log: &Logger,
    use_listening_port_as_enr_port_by_default: bool,
) -> Result<(), String> {
    set_network_config_shared::<BeaconNode>(
        config,
        beacon_config,
        data_dir,
        log,
        use_listening_port_as_enr_port_by_default,
    )?;

    if beacon_config.subscribe_all_subnets {
        config.subscribe_all_subnets = true;
    }

    if beacon_config.import_all_attestations {
        config.import_all_attestations = true;
    }

    if beacon_config.shutdown_after_sync {
        config.shutdown_after_sync = true;
    }

    config.target_peers = beacon_config.target_peers;

    if let Some(port) = beacon_config.discovery_port {
        config.discovery_port = port;
    }

    config.network_load = beacon_config.network_load;

    if let Some(libp2p_addresses_str) = beacon_config.libp2p_addresses.clone() {
        config.libp2p_nodes = libp2p_addresses_str
            .split(',')
            .map(|multiaddr| {
                multiaddr
                    .parse()
                    .map_err(|_| format!("Invalid Multiaddr: {}", multiaddr))
            })
            .collect::<Result<Vec<Multiaddr>, _>>()?;
    }

    if let Some(trusted_peers_str) = beacon_config.trusted_peers.clone() {
        config.trusted_peers = trusted_peers_str
            .split(',')
            .map(|peer_id| {
                peer_id
                    .parse()
                    .map_err(|_| format!("Invalid trusted peer id: {}", peer_id))
            })
            .collect::<Result<Vec<PeerIdSerialized>, _>>()?;
    }

    config.enr_tcp_port = beacon_config.enr_tcp_port;

    if beacon_config.enr_match {
        // set the enr address to localhost if the address is 0.0.0.0
        if config.listen_address == "0.0.0.0".parse::<IpAddr>().expect("valid ip addr") {
            config.enr_address = Some("127.0.0.1".parse::<IpAddr>().expect("valid ip addr"));
        } else {
            config.enr_address = Some(config.listen_address);
        }
        config.enr_udp_port = Some(config.discovery_port);
    }

    if beacon_config.disable_enr_auto_update {
        config.discv5_config.enr_update = false;
    }

    if beacon_config.disable_discovery {
        config.disable_discovery = true;
        warn!(log, "Discovery is disabled. New peers will not be found");
    }

    if beacon_config.disable_upnp {
        config.upnp_enabled = false;
    }

    if beacon_config.private {
        config.private = true;
    }

    if beacon_config.metrics {
        config.metrics_enabled = true;
    }

    Ok(())
}

// This method sets the network config from the command line arguments for all fields that are
// common to both the beacon node and boot node CLI config.
pub fn set_network_config_shared<T: NetworkConfigurable>(
    config: &mut NetworkConfig,
    cli_config: &T,
    data_dir: &Path,
    log: &Logger,
    use_listening_port_as_enr_port_by_default: bool,
) -> Result<(), String> {
    // If a network dir has been specified, override the `datadir` definition.
    if let Some(dir) = cli_config.get_network_dir() {
        config.network_dir = dir;
    } else {
        config.network_dir = data_dir.join(DEFAULT_NETWORK_DIR);
    };

    config.listen_address = cli_config.get_listen_address();
    config.libp2p_port = cli_config.get_port();
    config.discovery_port = cli_config.get_port();

    if let Some(boot_enr_str) = cli_config.get_boot_nodes() {
        let mut enrs: Vec<Enr> = vec![];
        let mut multiaddrs: Vec<Multiaddr> = vec![];
        for addr in boot_enr_str.split(',') {
            match addr.parse() {
                Ok(enr) => enrs.push(enr),
                Err(_) => {
                    // parsing as ENR failed, try as Multiaddr
                    let multi: Multiaddr = addr
                        .parse()
                        .map_err(|_| format!("Not valid as ENR nor Multiaddr: {}", addr))?;
                    if !multi.iter().any(|proto| matches!(proto, Protocol::Udp(_))) {
                        slog::error!(log, "Missing UDP in Multiaddr {}", multi.to_string());
                    }
                    if !multi.iter().any(|proto| matches!(proto, Protocol::P2p(_))) {
                        slog::error!(log, "Missing P2P in Multiaddr {}", multi.to_string());
                    }
                    multiaddrs.push(multi);
                }
            }
        }
        config.boot_nodes_enr = enrs;
        config.boot_nodes_multiaddr = multiaddrs;
    }

    config.enr_udp_port = cli_config.get_enr_udp_port();

    if let Some(enr_address) = cli_config.get_enr_address() {
        let resolved_addr = match enr_address.parse::<IpAddr>() {
            Ok(addr) => addr, // // Input is an IpAddr
            Err(_) => {
                let mut addr = enr_address.to_string();
                // Appending enr-port to the dns hostname to appease `to_socket_addrs()` parsing.
                // Since enr-update is disabled with a dns address, not setting the enr-udp-port
                // will make the node undiscoverable.
                if let Some(enr_udp_port) = config.enr_udp_port.or_else(|| {
                    if use_listening_port_as_enr_port_by_default {
                        Some(config.discovery_port)
                    } else {
                        None
                    }
                }) {
                    addr.push_str(&format!(":{}", enr_udp_port));
                } else {
                    return Err(
                        "enr-udp-port must be set for node to be discoverable with dns address"
                            .into(),
                    );
                }
                // `to_socket_addr()` does the dns resolution
                // Note: `to_socket_addrs()` is a blocking call
                let resolved_addr = if let Ok(mut resolved_addrs) = addr.to_socket_addrs() {
                    // Pick the first ip from the list of resolved addresses
                    resolved_addrs
                        .next()
                        .map(|a| a.ip())
                        .ok_or("Resolved dns addr contains no entries")?
                } else {
                    return Err(format!("Failed to parse enr-address: {}", enr_address));
                };
                config.discv5_config.enr_update = false;
                resolved_addr
            }
        };
        config.enr_address = Some(resolved_addr);
    }

    if cli_config.is_disable_packet_filter() {
        warn!(log, "Discv5 packet filter is disabled");
        config.discv5_config.enable_packet_filter = false;
    }

    Ok(())
}

/// Gets the datadir which should be used.
pub fn get_data_dir(config: &GlobalConfig) -> PathBuf {
    // Read the `--datadir` flag.
    //
    // If it's not present, try and find the home directory (`~`) and push the default data
    // directory and the testnet name onto it.

    config
        .datadir
        .as_ref()
        .map(|path| path.join(DEFAULT_BEACON_NODE_DIR))
        .or_else(|| {
            dirs::home_dir().map(|home| {
                home.join(DEFAULT_ROOT_DIR)
                    .join(directory::get_network_dir(config))
                    .join(DEFAULT_BEACON_NODE_DIR)
            })
        })
        .unwrap_or_else(|| PathBuf::from("."))
}

/// A bit of hack to find an unused port.
///
/// Does not guarantee that the given port is unused after the function exits, just that it was
/// unused before the function started (i.e., it does not reserve a port).
///
/// Used for passing unused ports to libp2 so that lighthouse won't have to update
/// its own ENR.
///
/// NOTE: It is possible that libp2p/discv5 is unable to bind to the
/// ports returned by this function as the OS has a buffer period where
/// it doesn't allow binding to the same port even after the socket is closed.
/// We might have to use SO_REUSEADDR socket option from `std::net2` crate in
/// that case.
pub fn unused_port(transport: &str) -> Result<u16, String> {
    let local_addr = match transport {
        "tcp" => {
            let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| {
                format!("Failed to create TCP listener to find unused port: {:?}", e)
            })?;
            listener.local_addr().map_err(|e| {
                format!(
                    "Failed to read TCP listener local_addr to find unused port: {:?}",
                    e
                )
            })?
        }
        "udp" => {
            let socket = UdpSocket::bind("127.0.0.1:0")
                .map_err(|e| format!("Failed to create UDP socket to find unused port: {:?}", e))?;
            socket.local_addr().map_err(|e| {
                format!(
                    "Failed to read UDP socket local_addr to find unused port: {:?}",
                    e
                )
            })?
        }
        _ => return Err("Invalid transport to find unused port".into()),
    };
    Ok(local_addr.port())
}
