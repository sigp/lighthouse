use beacon_chain::builder::PUBKEY_CACHE_FILENAME;
use clap::ArgMatches;
use clap_utils::BAD_TESTNET_DIR_MESSAGE;
use client::{config::DEFAULT_DATADIR, ClientConfig, ClientGenesis};
use eth2_libp2p::{multiaddr::Protocol, Enr, Multiaddr};
use eth2_testnet_config::Eth2TestnetConfig;
use slog::{crit, info, Logger};
use ssz::Encode;
use std::cmp;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;
use types::{ChainSpec, EthSpec, GRAFFITI_BYTES_LEN};

pub const BEACON_NODE_DIR: &str = "beacon";
pub const NETWORK_DIR: &str = "network";

/// Gets the fully-initialized global client.
///
/// The top-level `clap` arguments should be provided as `cli_args`.
///
/// The output of this function depends primarily upon the given `cli_args`, however it's behaviour
/// may be influenced by other external services like the contents of the file system or the
/// response of some remote server.
#[allow(clippy::cognitive_complexity)]
pub fn get_config<E: EthSpec>(
    cli_args: &ArgMatches,
    spec_constants: &str,
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

    client_config.spec_constants = spec_constants.into();

    /*
     * Networking
     */
    // If a network dir has been specified, override the `datadir` definition.
    if let Some(dir) = cli_args.value_of("network-dir") {
        client_config.network.network_dir = PathBuf::from(dir);
    } else {
        client_config.network.network_dir = client_config.data_dir.join(NETWORK_DIR);
    };

    if let Some(listen_address_str) = cli_args.value_of("listen-address") {
        let listen_address = listen_address_str
            .parse()
            .map_err(|_| format!("Invalid listen address: {:?}", listen_address_str))?;
        client_config.network.listen_address = listen_address;
    }

    if let Some(target_peers_str) = cli_args.value_of("target-peers") {
        client_config.network.target_peers = target_peers_str
            .parse::<usize>()
            .map_err(|_| format!("Invalid number of target peers: {}", target_peers_str))?;
    }

    if let Some(port_str) = cli_args.value_of("port") {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| format!("Invalid port: {}", port_str))?;
        client_config.network.libp2p_port = port;
        client_config.network.discovery_port = port;
    }

    if let Some(port_str) = cli_args.value_of("discovery-port") {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| format!("Invalid port: {}", port_str))?;
        client_config.network.discovery_port = port;
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
        client_config.network.boot_nodes_enr = enrs;
        client_config.network.boot_nodes_multiaddr = multiaddrs;
    }

    if let Some(libp2p_addresses_str) = cli_args.value_of("libp2p-addresses") {
        client_config.network.libp2p_nodes = libp2p_addresses_str
            .split(',')
            .map(|multiaddr| {
                multiaddr
                    .parse()
                    .map_err(|_| format!("Invalid Multiaddr: {}", multiaddr))
            })
            .collect::<Result<Vec<Multiaddr>, _>>()?;
    }

    if let Some(enr_udp_port_str) = cli_args.value_of("enr-udp-port") {
        client_config.network.enr_udp_port = Some(
            enr_udp_port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid discovery port: {}", enr_udp_port_str))?,
        );
    }

    if let Some(enr_tcp_port_str) = cli_args.value_of("enr-tcp-port") {
        client_config.network.enr_tcp_port = Some(
            enr_tcp_port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid ENR TCP port: {}", enr_tcp_port_str))?,
        );
    }

    if cli_args.is_present("enr-match") {
        // set the enr address to localhost if the address is 0.0.0.0
        if client_config.network.listen_address
            == "0.0.0.0".parse::<IpAddr>().expect("valid ip addr")
        {
            client_config.network.enr_address =
                Some("127.0.0.1".parse::<IpAddr>().expect("valid ip addr"));
        } else {
            client_config.network.enr_address = Some(client_config.network.listen_address);
        }
        client_config.network.enr_udp_port = Some(client_config.network.discovery_port);
    }

    if let Some(enr_address) = cli_args.value_of("enr-address") {
        let resolved_addr = match enr_address.parse::<IpAddr>() {
            Ok(addr) => addr, // // Input is an IpAddr
            Err(_) => {
                let mut addr = enr_address.to_string();
                // Appending enr-port to the dns hostname to appease `to_socket_addrs()` parsing.
                // Since enr-update is disabled with a dns address, not setting the enr-udp-port
                // will make the node undiscoverable.
                if let Some(enr_udp_port) = client_config.network.enr_udp_port {
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
                client_config.network.discv5_config.enr_update = false;
                resolved_addr
            }
        };
        client_config.network.enr_address = Some(resolved_addr);
    }

    if cli_args.is_present("disable_enr_auto_update") {
        client_config.network.discv5_config.enr_update = false;
    }

    if cli_args.is_present("disable-discovery") {
        client_config.network.disable_discovery = true;
        slog::warn!(log, "Discovery is disabled. New peers will not be found");
    }

    /*
     * Http server
     */

    if cli_args.is_present("http") {
        client_config.rest_api.enabled = true;
    }

    if let Some(address) = cli_args.value_of("http-address") {
        client_config.rest_api.listen_address = address
            .parse::<Ipv4Addr>()
            .map_err(|_| "http-address is not a valid IPv4 address.")?;
    }

    if let Some(port) = cli_args.value_of("http-port") {
        client_config.rest_api.port = port
            .parse::<u16>()
            .map_err(|_| "http-port is not a valid u16.")?;
    }

    if let Some(allow_origin) = cli_args.value_of("http-allow-origin") {
        // Pre-validate the config value to give feedback to the user on node startup, instead of
        // as late as when the first API response is produced.
        hyper::header::HeaderValue::from_str(allow_origin)
            .map_err(|_| "Invalid allow-origin value")?;

        client_config.rest_api.allow_origin = allow_origin.to_string();
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

    if spec_constants != client_config.spec_constants {
        crit!(log, "Specification constants do not match.";
              "client_config" => client_config.spec_constants,
              "eth2_config" => spec_constants
        );
        return Err("Specification constant mismatch".into());
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
        client_config.rest_api.port = 0;
        client_config.websocket_server.port = 0;
    }

    /*
     * Load the eth2 testnet dir to obtain some additional config values.
     */
    let eth2_testnet_config: Eth2TestnetConfig<E> = get_eth2_testnet_config(&cli_args)?;

    client_config.eth1.deposit_contract_address =
        format!("{:?}", eth2_testnet_config.deposit_contract_address()?);
    client_config.eth1.deposit_contract_deploy_block =
        eth2_testnet_config.deposit_contract_deploy_block;
    client_config.eth1.lowest_cached_block_number =
        client_config.eth1.deposit_contract_deploy_block;
    client_config.eth1.follow_distance = spec.eth1_follow_distance;

    if let Some(mut boot_nodes) = eth2_testnet_config.boot_enr {
        client_config.network.boot_nodes_enr.append(&mut boot_nodes)
    }

    if let Some(genesis_state) = eth2_testnet_config.genesis_state {
        // Note: re-serializing the genesis state is not so efficient, however it avoids adding
        // trait bounds to the `ClientGenesis` enum. This would have significant flow-on
        // effects.
        client_config.genesis = ClientGenesis::SszBytes {
            genesis_state_bytes: genesis_state.as_ssz_bytes(),
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
    client_config.graffiti[..trimmed_graffiti_len]
        .copy_from_slice(&raw_graffiti[..trimmed_graffiti_len]);

    Ok(client_config)
}

/// Gets the datadir which should be used.
pub fn get_data_dir(cli_args: &ArgMatches) -> PathBuf {
    // Read the `--datadir` flag.
    //
    // If it's not present, try and find the home directory (`~`) and push the default data
    // directory onto it.
    cli_args
        .value_of("datadir")
        .map(|path| PathBuf::from(path).join(BEACON_NODE_DIR))
        .or_else(|| dirs::home_dir().map(|home| home.join(DEFAULT_DATADIR).join(BEACON_NODE_DIR)))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Try to parse the eth2 testnet config from the `testnet`, `testnet-dir` flags in that order.
/// Returns the default hardcoded testnet if neither flags are set.
pub fn get_eth2_testnet_config<E: EthSpec>(
    cli_args: &ArgMatches,
) -> Result<Eth2TestnetConfig<E>, String> {
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
