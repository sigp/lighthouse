use beacon_chain::builder::PUBKEY_CACHE_FILENAME;
use clap::ArgMatches;
use client::{config::DEFAULT_DATADIR, ClientConfig, ClientGenesis};
use eth2_libp2p::{Enr, Multiaddr};
use eth2_testnet_config::Eth2TestnetConfig;
use slog::{crit, info, warn, Logger};
use ssz::Encode;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::net::{IpAddr, Ipv4Addr};
use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;
use types::EthSpec;

pub const CLIENT_CONFIG_FILENAME: &str = "beacon-node.toml";
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
                .ok_or("Failed to get db_path".to_string())?,
        )
        .map_err(|err| format!("Failed to remove chain_db: {}", err))?;

        // Remove the freezer db.
        fs::remove_dir_all(
            client_config
                .get_freezer_db_path()
                .ok_or("Failed to get freezer db path".to_string())?,
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
    info!(log, "Data directory initialised"; "datadir" => format!("{}",log_dir.into_os_string().into_string().expect("Datadir should be a valid os string")));

    // Load the client config, if it exists .
    let config_file_path = client_config.data_dir.join(CLIENT_CONFIG_FILENAME);
    let config_file_existed = config_file_path.exists();
    if config_file_existed {
        client_config = read_from_file(config_file_path.clone())
            .map_err(|e| format!("Unable to parse {:?} file: {:?}", config_file_path, e))?
            .ok_or_else(|| format!("{:?} file does not exist", config_file_path))?;
    } else {
        client_config.spec_constants = spec_constants.into();
    }

    client_config.testnet_dir = get_testnet_dir(cli_args);

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

    if let Some(max_peers_str) = cli_args.value_of("maxpeers") {
        client_config.network.max_peers = max_peers_str
            .parse::<usize>()
            .map_err(|_| format!("Invalid number of max peers: {}", max_peers_str))?;
    }

    if let Some(port_str) = cli_args.value_of("port") {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| format!("Invalid port: {}", port_str))?;
        client_config.network.libp2p_port = port;
        client_config.network.discovery_port = port;
        dbg!(&client_config.network.discovery_port);
    }

    if let Some(port_str) = cli_args.value_of("discovery-port") {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| format!("Invalid port: {}", port_str))?;
        client_config.network.discovery_port = port;
    }

    if let Some(boot_enr_str) = cli_args.value_of("boot-nodes") {
        client_config.network.boot_nodes = boot_enr_str
            .split(',')
            .map(|enr| enr.parse().map_err(|_| format!("Invalid ENR: {}", enr)))
            .collect::<Result<Vec<Enr>, _>>()?;
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

    if let Some(enr_address_str) = cli_args.value_of("enr-address") {
        client_config.network.enr_address = Some(
            enr_address_str
                .parse()
                .map_err(|_| format!("Invalid discovery address: {:?}", enr_address_str))?,
        )
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

    if cli_args.is_present("disable_enr_auto_update") {
        client_config.network.discv5_config.enr_update = false;
    }

    if let Some(p2p_priv_key) = cli_args.value_of("p2p-priv-key") {
        client_config.network.secret_key_hex = Some(p2p_priv_key.to_string());
    }

    // Define a percentage of messages that should be propogated, useful for simulating bad network
    // conditions.
    //
    // WARNING: setting this to anything less than 100 will cause bad behaviour.
    if let Some(propagation_percentage_string) = cli_args.value_of("random-propagation") {
        let percentage = propagation_percentage_string
            .parse::<u8>()
            .map_err(|_| "Unable to parse the propagation percentage".to_string())?;
        if percentage > 100 {
            return Err("Propagation percentage greater than 100".to_string());
        }
        client_config.network.propagation_percentage = Some(percentage);
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

    if let Some(state_cache_size) = cli_args.value_of("state-cache-size") {
        client_config.store.state_cache_size = state_cache_size
            .parse()
            .map_err(|_| "block-cache-size is not a valid integer".to_string())?;
    }

    if spec_constants != client_config.spec_constants {
        crit!(log, "Specification constants do not match.";
              "client_config" => client_config.spec_constants.to_string(),
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
    let eth2_testnet_config: Eth2TestnetConfig<E> =
        get_eth2_testnet_config(&client_config.testnet_dir)?;

    client_config.eth1.deposit_contract_address =
        format!("{:?}", eth2_testnet_config.deposit_contract_address()?);
    client_config.eth1.deposit_contract_deploy_block =
        eth2_testnet_config.deposit_contract_deploy_block;
    client_config.eth1.lowest_cached_block_number =
        client_config.eth1.deposit_contract_deploy_block;

    if let Some(mut boot_nodes) = eth2_testnet_config.boot_enr {
        client_config.network.boot_nodes.append(&mut boot_nodes)
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

    if !config_file_existed {
        write_to_file(config_file_path, &client_config)?;
    }

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

/// Gets the testnet dir which should be used.
pub fn get_testnet_dir(cli_args: &ArgMatches) -> Option<PathBuf> {
    // Read the `--testnet-dir` flag.
    if let Some(val) = cli_args.value_of("testnet-dir") {
        Some(PathBuf::from(val))
    } else {
        None
    }
}

/// If `testnet_dir` is `Some`, returns the `Eth2TestnetConfig` at that path or returns an error.
/// If it is `None`, returns the "hard coded" config.
pub fn get_eth2_testnet_config<E: EthSpec>(
    testnet_dir: &Option<PathBuf>,
) -> Result<Eth2TestnetConfig<E>, String> {
    Ok(if let Some(testnet_dir) = testnet_dir {
        Eth2TestnetConfig::load(testnet_dir.clone())
            .map_err(|e| format!("Unable to open testnet dir at {:?}: {}", testnet_dir, e))?
    } else {
        Eth2TestnetConfig::hard_coded().map_err(|e| {
            format!(
                "The hard-coded testnet directory was invalid. \
                 This happens when Lighthouse is migrating between spec versions. \
                 Error : {}",
                e
            )
        })?
    })
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

/// Write a configuration to file.
pub fn write_to_file<T>(path: PathBuf, config: &T) -> Result<(), String>
where
    T: Default + serde::de::DeserializeOwned + serde::Serialize,
{
    if let Ok(mut file) = File::create(path.clone()) {
        let toml_encoded = toml::to_string(&config).map_err(|e| {
            format!(
                "Failed to write configuration to {:?}. Error: {:?}",
                path, e
            )
        })?;
        file.write_all(toml_encoded.as_bytes())
            .unwrap_or_else(|_| panic!("Unable to write to {:?}", path));
    }

    Ok(())
}

/// Loads a `ClientConfig` from file. If unable to load from file, generates a default
/// configuration and saves that as a sample file.
pub fn read_from_file<T>(path: PathBuf) -> Result<Option<T>, String>
where
    T: Default + serde::de::DeserializeOwned + serde::Serialize,
{
    if let Ok(mut file) = File::open(path.clone()) {
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| format!("Unable to read {:?}. Error: {:?}", path, e))?;

        let config = toml::from_str(&contents)
            .map_err(|e| format!("Unable to parse {:?}: {:?}", path, e))?;

        Ok(Some(config))
    } else {
        Ok(None)
    }
}
