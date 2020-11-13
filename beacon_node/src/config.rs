use beacon_chain::builder::PUBKEY_CACHE_FILENAME;
use clap::ArgMatches;
use clap_utils::BAD_TESTNET_DIR_MESSAGE;
use client::{ClientConfig, ClientGenesis};
use directory::{DEFAULT_BEACON_NODE_DIR, DEFAULT_NETWORK_DIR, DEFAULT_ROOT_DIR};
use eth2_libp2p::{multiaddr::Protocol, Enr, Multiaddr, NetworkConfig, PeerIdSerialized};
use eth2_testnet_config::Eth2TestnetConfig;
use slog::{info, warn, Logger};
use std::cmp;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;
use types::{ChainSpec, Checkpoint, Epoch, EthSpec, Hash256, GRAFFITI_BYTES_LEN};

/// Gets the fully-initialized global client.
///
/// The top-level `clap` arguments should be provided as `cli_args`.
///
/// The output of this function depends primarily upon the given `cli_args`, however it's behaviour
/// may be influenced by other external services like the contents of the file system or the
/// response of some remote server.
pub fn get_config<E: EthSpec>(
    cli_args: &ArgMatches,
    spec: &ChainSpec,
    log: Logger,
) -> Result<ClientConfig, String> {
    let mut client_config = ClientConfig::default();

    client_config.data_dir = get_data_dir(cli_args);

    // If necessary, remove any existing database and configuration
    if client_config.data_dir.exists() && cli_args.is_present("purge-db") {
        // Remove the chain_db.
        fs::remove_dir_all(
            client_config
                .get_db_path()
                .ok_or_else(|| "Failed to get db_path".to_string())?,
        )
        .map_err(|err| format!("Failed to remove chain_db: {}", err))?;

        // Remove the freezer db.
        fs::remove_dir_all(
            client_config
                .get_freezer_db_path()
                .ok_or_else(|| "Failed to get freezer db path".to_string())?,
        )
        .map_err(|err| format!("Failed to remove chain_db: {}", err))?;

        // Remove the pubkey cache file if it exists
        let pubkey_cache_file = client_config.data_dir.join(PUBKEY_CACHE_FILENAME);
        if pubkey_cache_file.exists() {
            fs::remove_file(&pubkey_cache_file)
                .map_err(|e| format!("Failed to remove {:?}: {:?}", pubkey_cache_file, e))?;
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
        cli_args,
        &client_config.data_dir,
        &log,
        false,
    )?;

    /*
     * Staking flag
     * Note: the config values set here can be overwritten by other more specific cli params
     */

    if cli_args.is_present("staking") {
        client_config.http_api.enabled = true;
        client_config.sync_eth1_chain = true;
    }

    /*
     * Http API server
     */

    if cli_args.is_present("http") {
        client_config.http_api.enabled = true;
    }

    if let Some(address) = cli_args.value_of("http-address") {
        client_config.http_api.listen_addr = address
            .parse::<Ipv4Addr>()
            .map_err(|_| "http-address is not a valid IPv4 address.")?;
    }

    if let Some(port) = cli_args.value_of("http-port") {
        client_config.http_api.listen_port = port
            .parse::<u16>()
            .map_err(|_| "http-port is not a valid u16.")?;
    }

    if let Some(allow_origin) = cli_args.value_of("http-allow-origin") {
        // Pre-validate the config value to give feedback to the user on node startup, instead of
        // as late as when the first API response is produced.
        hyper::header::HeaderValue::from_str(allow_origin)
            .map_err(|_| "Invalid allow-origin value")?;

        client_config.http_api.allow_origin = Some(allow_origin.to_string());
    }

    /*
     * Prometheus metrics HTTP server
     */

    if cli_args.is_present("metrics") {
        client_config.http_metrics.enabled = true;
    }

    if let Some(address) = cli_args.value_of("metrics-address") {
        client_config.http_metrics.listen_addr = address
            .parse::<Ipv4Addr>()
            .map_err(|_| "metrics-address is not a valid IPv4 address.")?;
    }

    if let Some(port) = cli_args.value_of("metrics-port") {
        client_config.http_metrics.listen_port = port
            .parse::<u16>()
            .map_err(|_| "metrics-port is not a valid u16.")?;
    }

    if let Some(allow_origin) = cli_args.value_of("metrics-allow-origin") {
        // Pre-validate the config value to give feedback to the user on node startup, instead of
        // as late as when the first API response is produced.
        hyper::header::HeaderValue::from_str(allow_origin)
            .map_err(|_| "Invalid allow-origin value")?;

        client_config.http_metrics.allow_origin = Some(allow_origin.to_string());
    }

    // Log a warning indicating an open HTTP server if it wasn't specified explicitly
    // (e.g. using the --staking flag).
    if cli_args.is_present("staking") {
        warn!(
            log,
            "Running HTTP server on port {}", client_config.http_api.listen_port
        );
    }

    /*
     * Websocket server
     */

    if cli_args.is_present("ws") {
        client_config.websocket_server.enabled = true;
    }

    if let Some(address) = cli_args.value_of("ws-address") {
        client_config.websocket_server.listen_address = address
            .parse::<Ipv4Addr>()
            .map_err(|_| "ws-address is not a valid IPv4 address.")?;
    }

    if let Some(port) = cli_args.value_of("ws-port") {
        client_config.websocket_server.port = port
            .parse::<u16>()
            .map_err(|_| "ws-port is not a valid u16.")?;
    }

    /*
     * Eth1
     */

    // When present, use an eth1 backend that generates deterministic junk.
    //
    // Useful for running testnets without the overhead of a deposit contract.
    if cli_args.is_present("dummy-eth1") {
        client_config.dummy_eth1_backend = true;
    }

    // When present, attempt to sync to an eth1 node.
    //
    // Required for block production.
    if cli_args.is_present("eth1") {
        client_config.sync_eth1_chain = true;
    }

    // Defines the URL to reach the eth1 node.
    if let Some(val) = cli_args.value_of("eth1-endpoint") {
        client_config.sync_eth1_chain = true;
        client_config.eth1.endpoint = val.to_string();
    }

    if let Some(freezer_dir) = cli_args.value_of("freezer-dir") {
        client_config.freezer_db_path = Some(PathBuf::from(freezer_dir));
    }

    if let Some(slots_per_restore_point) = cli_args.value_of("slots-per-restore-point") {
        client_config.store.slots_per_restore_point = slots_per_restore_point
            .parse()
            .map_err(|_| "slots-per-restore-point is not a valid integer".to_string())?;
    } else {
        client_config.store.slots_per_restore_point = std::cmp::min(
            E::slots_per_historical_root() as u64,
            store::config::DEFAULT_SLOTS_PER_RESTORE_POINT,
        );
    }

    if let Some(block_cache_size) = cli_args.value_of("block-cache-size") {
        client_config.store.block_cache_size = block_cache_size
            .parse()
            .map_err(|_| "block-cache-size is not a valid integer".to_string())?;
    }

    /*
     * Zero-ports
     *
     * Replaces previously set flags.
     * Libp2p and discovery ports are set explicitly by selecting
     * a random free port so that we aren't needlessly updating ENR
     * from lighthouse.
     * Discovery address is set to localhost by default.
     */
    if cli_args.is_present("zero-ports") {
        if client_config.network.enr_address == Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))) {
            client_config.network.enr_address = None
        }
        client_config.network.libp2p_port =
            unused_port("tcp").map_err(|e| format!("Failed to get port for libp2p: {}", e))?;
        client_config.network.discovery_port =
            unused_port("udp").map_err(|e| format!("Failed to get port for discovery: {}", e))?;
        client_config.http_api.listen_port = 0;
        client_config.http_metrics.listen_port = 0;
        client_config.websocket_server.port = 0;
    }

    /*
     * Load the eth2 testnet dir to obtain some additional config values.
     */
    let eth2_testnet_config = get_eth2_testnet_config(&cli_args)?;

    client_config.eth1.deposit_contract_address =
        format!("{:?}", eth2_testnet_config.deposit_contract_address()?);
    let spec_contract_address = format!("{:?}", spec.deposit_contract_address);
    if client_config.eth1.deposit_contract_address != spec_contract_address {
        return Err("Testnet contract address does not match spec".into());
    }

    client_config.eth1.deposit_contract_deploy_block =
        eth2_testnet_config.deposit_contract_deploy_block;
    client_config.eth1.lowest_cached_block_number =
        client_config.eth1.deposit_contract_deploy_block;
    client_config.eth1.follow_distance = spec.eth1_follow_distance;
    client_config.eth1.network_id = spec.deposit_network_id.into();

    if let Some(mut boot_nodes) = eth2_testnet_config.boot_enr {
        client_config.network.boot_nodes_enr.append(&mut boot_nodes)
    }

    if let Some(genesis_state_bytes) = eth2_testnet_config.genesis_state_bytes {
        // Note: re-serializing the genesis state is not so efficient, however it avoids adding
        // trait bounds to the `ClientGenesis` enum. This would have significant flow-on
        // effects.
        client_config.genesis = ClientGenesis::SszBytes {
            genesis_state_bytes,
        };
    } else {
        client_config.genesis = ClientGenesis::DepositContract;
    }

    let raw_graffiti = if let Some(graffiti) = cli_args.value_of("graffiti") {
        if graffiti.len() > GRAFFITI_BYTES_LEN {
            return Err(format!(
                "Your graffiti is too long! {} bytes maximum!",
                GRAFFITI_BYTES_LEN
            ));
        }

        graffiti.as_bytes()
    } else {
        lighthouse_version::VERSION.as_bytes()
    };

    let trimmed_graffiti_len = cmp::min(raw_graffiti.len(), GRAFFITI_BYTES_LEN);
    client_config.graffiti.0[..trimmed_graffiti_len]
        .copy_from_slice(&raw_graffiti[..trimmed_graffiti_len]);

    if let Some(wss_checkpoint) = cli_args.value_of("wss-checkpoint") {
        let mut split = wss_checkpoint.split(':');
        let root_str = split
            .next()
            .ok_or_else(|| "Improperly formatted weak subjectivity checkpoint".to_string())?;
        let epoch_str = split
            .next()
            .ok_or_else(|| "Improperly formatted weak subjectivity checkpoint".to_string())?;

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

    if let Some(max_skip_slots) = cli_args.value_of("max-skip-slots") {
        client_config.chain.import_max_skip_slots = match max_skip_slots {
            "none" => None,
            n => Some(
                n.parse()
                    .map_err(|_| "Invalid max-skip-slots".to_string())?,
            ),
        };
    }

    Ok(client_config)
}

/// Sets the network config from the command line arguments
pub fn set_network_config(
    config: &mut NetworkConfig,
    cli_args: &ArgMatches,
    data_dir: &PathBuf,
    log: &Logger,
    use_listening_port_as_enr_port_by_default: bool,
) -> Result<(), String> {
    // If a network dir has been specified, override the `datadir` definition.
    if let Some(dir) = cli_args.value_of("network-dir") {
        config.network_dir = PathBuf::from(dir);
    } else {
        config.network_dir = data_dir.join(DEFAULT_NETWORK_DIR);
    };

    if cli_args.is_present("subscribe-all-subnets") {
        config.subscribe_all_subnets = true;
    }

    if let Some(listen_address_str) = cli_args.value_of("listen-address") {
        let listen_address = listen_address_str
            .parse()
            .map_err(|_| format!("Invalid listen address: {:?}", listen_address_str))?;
        config.listen_address = listen_address;
    }

    if let Some(target_peers_str) = cli_args.value_of("target-peers") {
        config.target_peers = target_peers_str
            .parse::<usize>()
            .map_err(|_| format!("Invalid number of target peers: {}", target_peers_str))?;
    }

    if let Some(port_str) = cli_args.value_of("port") {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| format!("Invalid port: {}", port_str))?;
        config.libp2p_port = port;
        config.discovery_port = port;
    }

    if let Some(port_str) = cli_args.value_of("discovery-port") {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| format!("Invalid port: {}", port_str))?;
        config.discovery_port = port;
    }

    if let Some(boot_enr_str) = cli_args.value_of("boot-nodes") {
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

    if let Some(libp2p_addresses_str) = cli_args.value_of("libp2p-addresses") {
        config.libp2p_nodes = libp2p_addresses_str
            .split(',')
            .map(|multiaddr| {
                multiaddr
                    .parse()
                    .map_err(|_| format!("Invalid Multiaddr: {}", multiaddr))
            })
            .collect::<Result<Vec<Multiaddr>, _>>()?;
    }

    if let Some(trusted_peers_str) = cli_args.value_of("trusted-peers") {
        config.trusted_peers = trusted_peers_str
            .split(',')
            .map(|peer_id| {
                peer_id
                    .parse()
                    .map_err(|_| format!("Invalid trusted peer id: {}", peer_id))
            })
            .collect::<Result<Vec<PeerIdSerialized>, _>>()?;
    }

    if let Some(enr_udp_port_str) = cli_args.value_of("enr-udp-port") {
        config.enr_udp_port = Some(
            enr_udp_port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid discovery port: {}", enr_udp_port_str))?,
        );
    }

    if let Some(enr_tcp_port_str) = cli_args.value_of("enr-tcp-port") {
        config.enr_tcp_port = Some(
            enr_tcp_port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid ENR TCP port: {}", enr_tcp_port_str))?,
        );
    }

    if cli_args.is_present("enr-match") {
        // set the enr address to localhost if the address is 0.0.0.0
        if config.listen_address == "0.0.0.0".parse::<IpAddr>().expect("valid ip addr") {
            config.enr_address = Some("127.0.0.1".parse::<IpAddr>().expect("valid ip addr"));
        } else {
            config.enr_address = Some(config.listen_address);
        }
        config.enr_udp_port = Some(config.discovery_port);
    }

    if let Some(enr_address) = cli_args.value_of("enr-address") {
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
                    addr.push_str(&format!(":{}", enr_udp_port.to_string()));
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
                        .ok_or_else(|| "Resolved dns addr contains no entries".to_string())?
                } else {
                    return Err(format!("Failed to parse enr-address: {}", enr_address));
                };
                config.discv5_config.enr_update = false;
                resolved_addr
            }
        };
        config.enr_address = Some(resolved_addr);
    }

    if cli_args.is_present("disable-enr-auto-update") {
        config.discv5_config.enr_update = false;
    }

    if cli_args.is_present("disable-discovery") {
        config.disable_discovery = true;
        warn!(log, "Discovery is disabled. New peers will not be found");
    }

    if cli_args.is_present("disable-upnp") {
        config.upnp_enabled = false;
    }

    Ok(())
}

/// Gets the datadir which should be used.
pub fn get_data_dir(cli_args: &ArgMatches) -> PathBuf {
    // Read the `--datadir` flag.
    //
    // If it's not present, try and find the home directory (`~`) and push the default data
    // directory and the testnet name onto it.

    cli_args
        .value_of("datadir")
        .map(|path| PathBuf::from(path).join(DEFAULT_BEACON_NODE_DIR))
        .or_else(|| {
            dirs::home_dir().map(|home| {
                home.join(DEFAULT_ROOT_DIR)
                    .join(directory::get_testnet_name(cli_args))
                    .join(DEFAULT_BEACON_NODE_DIR)
            })
        })
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Try to parse the eth2 testnet config from the `testnet`, `testnet-dir` flags in that order.
/// Returns the default hardcoded testnet if neither flags are set.
pub fn get_eth2_testnet_config(cli_args: &ArgMatches) -> Result<Eth2TestnetConfig, String> {
    let optional_testnet_config = if cli_args.is_present("testnet") {
        clap_utils::parse_hardcoded_network(cli_args, "testnet")?
    } else if cli_args.is_present("testnet-dir") {
        clap_utils::parse_testnet_dir(cli_args, "testnet-dir")?
    } else {
        Eth2TestnetConfig::hard_coded_default()?
    };
    optional_testnet_config.ok_or_else(|| BAD_TESTNET_DIR_MESSAGE.to_string())
}

/// A bit of hack to find an unused port.
///
/// Does not guarantee that the given port is unused after the function exists, just that it was
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
