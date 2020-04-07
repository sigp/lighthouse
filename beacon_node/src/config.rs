use clap::ArgMatches;
use client::{config::DEFAULT_DATADIR, ClientConfig, ClientGenesis, Eth2Config};
use eth2_config::{read_from_file, write_to_file};
use eth2_libp2p::{Enr, Multiaddr};
use eth2_testnet_config::Eth2TestnetConfig;
use genesis::recent_genesis_time;
use rand::{distributions::Alphanumeric, Rng};
use slog::{crit, info, Logger};
use ssz::Encode;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;
use types::EthSpec;

pub const CLIENT_CONFIG_FILENAME: &str = "beacon-node.toml";
pub const ETH2_CONFIG_FILENAME: &str = "eth2-spec.toml";
pub const BEACON_NODE_DIR: &str = "beacon";
pub const NETWORK_DIR: &str = "network";

type Result<T> = std::result::Result<T, String>;
type Config = (ClientConfig, Eth2Config, Logger);

/// Gets the fully-initialized global client and eth2 configuration objects.
///
/// The top-level `clap` arguments should be provided as `cli_args`.
///
/// The output of this function depends primarily upon the given `cli_args`, however it's behaviour
/// may be influenced by other external services like the contents of the file system or the
/// response of some remote server.
#[allow(clippy::cognitive_complexity)]
pub fn get_configs<E: EthSpec>(
    cli_args: &ArgMatches,
    mut eth2_config: Eth2Config,
    core_log: Logger,
) -> Result<Config> {
    let log = core_log.clone();

    let mut client_config = ClientConfig::default();

    client_config.spec_constants = eth2_config.spec_constants.clone();

    // Read the `--datadir` flag.
    //
    // If it's not present, try and find the home directory (`~`) and push the default data
    // directory onto it.
    client_config.data_dir = cli_args
        .value_of("datadir")
        .map(|path| PathBuf::from(path).join(BEACON_NODE_DIR))
        .or_else(|| dirs::home_dir().map(|home| home.join(DEFAULT_DATADIR).join(BEACON_NODE_DIR)))
        .unwrap_or_else(|| PathBuf::from("."));

    // Load the client config, if it exists .
    let path = client_config.data_dir.join(CLIENT_CONFIG_FILENAME);
    if path.exists() {
        client_config = read_from_file(path.clone())
            .map_err(|e| format!("Unable to parse {:?} file: {:?}", path, e))?
            .ok_or_else(|| format!("{:?} file does not exist", path))?;
    }

    // Load the eth2 config, if it exists .
    let path = client_config.data_dir.join(ETH2_CONFIG_FILENAME);
    if path.exists() {
        let loaded_eth2_config: Eth2Config = read_from_file(path.clone())
            .map_err(|e| format!("Unable to parse {:?} file: {:?}", path, e))?
            .ok_or_else(|| format!("{:?} file does not exist", path))?;

        // The loaded spec must be using the same spec constants (e.g., minimal, mainnet) as the
        // client expects.
        if loaded_eth2_config.spec_constants == client_config.spec_constants {
            eth2_config = loaded_eth2_config
        } else {
            return Err(
                format!(
                    "Eth2 config loaded from disk does not match client spec version. Got {} expected {}",
                    &loaded_eth2_config.spec_constants,
                    &client_config.spec_constants
                )
            );
        }
    }

    // Read the `--testnet-dir` flag.
    if let Some(val) = cli_args.value_of("testnet-dir") {
        client_config.testnet_dir = Some(PathBuf::from(val));
    }

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
            .collect::<Result<Vec<Enr>>>()?;
    }

    if let Some(libp2p_addresses_str) = cli_args.value_of("libp2p-addresses") {
        client_config.network.libp2p_nodes = libp2p_addresses_str
            .split(',')
            .map(|multiaddr| {
                multiaddr
                    .parse()
                    .map_err(|_| format!("Invalid Multiaddr: {}", multiaddr))
            })
            .collect::<Result<Vec<Multiaddr>>>()?;
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
        client_config.network.enr_address = Some(client_config.network.listen_address);
        client_config.network.enr_udp_port = Some(client_config.network.discovery_port);
    }

    if cli_args.is_present("disable_enr_auto_update") {
        client_config.network.discv5_config.enr_update = false;
    }

    if let Some(p2p_priv_key) = cli_args.value_of("p2p-priv-key") {
        client_config.network.secret_key_hex = Some(p2p_priv_key.to_string());
    }

    /*
     * Chain specification
     */
    if let Some(disabled_forks_str) = cli_args.value_of("disabled-forks") {
        client_config.disabled_forks = disabled_forks_str
            .split(',')
            .map(|fork_name| {
                fork_name
                    .parse()
                    .map_err(|_| format!("Invalid fork name: {}", fork_name))
            })
            .collect::<Result<Vec<String>>>()?;
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
        client_config.eth1.endpoint = val.to_string();
    }

    match cli_args.subcommand() {
        ("testnet", Some(sub_cmd_args)) => {
            process_testnet_subcommand(&mut client_config, &mut eth2_config, sub_cmd_args)?
        }
        // No sub-command assumes a resume operation.
        _ => {
            // If no primary subcommand was given, start the beacon chain from an existing
            // database.
            client_config.genesis = ClientGenesis::Resume;

            // Whilst there is no large testnet or mainnet force the user to specify how they want
            // to start a new chain (e.g., from a genesis YAML file, another node, etc).
            if !client_config.data_dir.exists() {
                info!(
                    log,
                    "Starting from an empty database";
                    "data_dir" => format!("{:?}", client_config.data_dir)
                );
                init_new_client::<E>(&mut client_config, &mut eth2_config)?
            } else {
                info!(
                    log,
                    "Resuming from existing datadir";
                    "data_dir" => format!("{:?}", client_config.data_dir)
                );
                // If the `testnet` command was not provided, attempt to load an existing datadir and
                // continue with an existing chain.
                load_from_datadir(&mut client_config)?
            }
        }
    };

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

    if eth2_config.spec_constants != client_config.spec_constants {
        crit!(log, "Specification constants do not match.";
              "client_config" => client_config.spec_constants.to_string(),
              "eth2_config" => eth2_config.spec_constants
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

    Ok((client_config, eth2_config, log))
}

/// Load from an existing database.
fn load_from_datadir(client_config: &mut ClientConfig) -> Result<()> {
    // Check to ensure the datadir exists.
    //
    // For now we return an error. In the future we may decide to boot a default (e.g.,
    // public testnet or mainnet).
    if !client_config.get_data_dir().map_or(false, |d| d.exists()) {
        return Err(
            "No datadir found. Either create a new testnet or specify a different `--datadir`."
                .into(),
        );
    }

    // If there is a path to a database in the config, ensure it exists.
    if !client_config
        .get_db_path()
        .map_or(false, |path| path.exists())
    {
        return Err(
            "No database found in datadir. Please make sure the directory provided is valid, or specify a different `--datadir`."
                .into(),
        );
    }

    client_config.genesis = ClientGenesis::Resume;

    Ok(())
}

/// Create a new client with the default configuration.
fn init_new_client<E: EthSpec>(
    client_config: &mut ClientConfig,
    eth2_config: &mut Eth2Config,
) -> Result<()> {
    let eth2_testnet_config: Eth2TestnetConfig<E> =
        if let Some(testnet_dir) = &client_config.testnet_dir {
            Eth2TestnetConfig::load(testnet_dir.clone())
                .map_err(|e| format!("Unable to open testnet dir at {:?}: {}", testnet_dir, e))?
        } else {
            Eth2TestnetConfig::hard_coded()
                .map_err(|e| format!("Unable to load hard-coded testnet dir: {}", e))?
        };

    eth2_config.spec = eth2_testnet_config
        .yaml_config
        .as_ref()
        .ok_or_else(|| "The testnet directory must contain a spec config".to_string())?
        .apply_to_chain_spec::<E>(&eth2_config.spec)
        .ok_or_else(|| {
            format!(
                "The loaded config is not compatible with the {} spec",
                &eth2_config.spec_constants
            )
        })?;

    let spec = &mut eth2_config.spec;

    client_config.eth1.deposit_contract_address =
        format!("{:?}", eth2_testnet_config.deposit_contract_address()?);
    client_config.eth1.deposit_contract_deploy_block =
        eth2_testnet_config.deposit_contract_deploy_block;

    client_config.eth1.follow_distance = spec.eth1_follow_distance / 2;
    client_config.eth1.lowest_cached_block_number = client_config
        .eth1
        .deposit_contract_deploy_block
        .saturating_sub(client_config.eth1.follow_distance * 2);

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

    create_new_datadir(&client_config, &eth2_config)?;

    Ok(())
}

/// Writes the configs in `self` to `self.data_dir`.
///
/// Returns an error if `self.data_dir` already exists.
pub fn create_new_datadir(client_config: &ClientConfig, eth2_config: &Eth2Config) -> Result<()> {
    if client_config.data_dir.exists() {
        return Err(format!(
            "Data dir already exists at {:?}",
            client_config.data_dir
        ));
    }

    // Create `datadir` and any non-existing parent directories.
    fs::create_dir_all(&client_config.data_dir)
        .map_err(|e| format!("Failed to create data dir: {}", e))?;

    macro_rules! write_to_file {
        ($file: ident, $variable: ident) => {
            let file = client_config.data_dir.join($file);
            if file.exists() {
                return Err(format!("Datadir is not clean, {} exists.", $file));
            } else {
                // Write the onfig to a TOML file in the datadir.
                write_to_file(client_config.data_dir.join($file), $variable)
                    .map_err(|e| format!("Unable to write {} file: {:?}", $file, e))?;
            }
        };
    }

    write_to_file!(CLIENT_CONFIG_FILENAME, client_config);
    write_to_file!(ETH2_CONFIG_FILENAME, eth2_config);

    Ok(())
}

/// Process the `testnet` CLI subcommand arguments, updating the `builder`.
fn process_testnet_subcommand(
    client_config: &mut ClientConfig,
    eth2_config: &mut Eth2Config,
    cli_args: &ArgMatches,
) -> Result<()> {
    // Specifies that a random datadir should be used.
    if cli_args.is_present("random-datadir") {
        client_config
            .data_dir
            .push(format!("random_{}", random_string(6)));
        client_config.network.network_dir = client_config.data_dir.join("network");
    }

    // Deletes the existing datadir.
    if cli_args.is_present("force") && client_config.data_dir.exists() {
        fs::remove_dir_all(&client_config.data_dir)
            .map_err(|e| format!("Unable to delete existing datadir: {:?}", e))?;
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

    // Modify the `SECONDS_PER_SLOT` "constant".
    if let Some(slot_time) = cli_args.value_of("slot-time") {
        let slot_time = slot_time
            .parse::<u64>()
            .map_err(|e| format!("Unable to parse slot-time: {:?}", e))?;

        eth2_config.spec.milliseconds_per_slot = slot_time;
    }

    // Start matching on the second subcommand (e.g., `testnet bootstrap ...`).
    match cli_args.subcommand() {
        ("recent", Some(cli_args)) => {
            let validator_count = cli_args
                .value_of("validator_count")
                .ok_or_else(|| "No validator_count specified")?
                .parse::<usize>()
                .map_err(|e| format!("Unable to parse validator_count: {:?}", e))?;

            let minutes = cli_args
                .value_of("minutes")
                .ok_or_else(|| "No recent genesis minutes supplied")?
                .parse::<u64>()
                .map_err(|e| format!("Unable to parse minutes: {:?}", e))?;

            client_config.dummy_eth1_backend = true;

            client_config.genesis = ClientGenesis::Interop {
                validator_count,
                genesis_time: recent_genesis_time(minutes),
            };
        }
        ("quick", Some(cli_args)) => {
            let validator_count = cli_args
                .value_of("validator_count")
                .ok_or_else(|| "No validator_count specified")?
                .parse::<usize>()
                .map_err(|e| format!("Unable to parse validator_count: {:?}", e))?;

            let genesis_time = cli_args
                .value_of("genesis_time")
                .ok_or_else(|| "No genesis time supplied")?
                .parse::<u64>()
                .map_err(|e| format!("Unable to parse genesis time: {:?}", e))?;

            client_config.dummy_eth1_backend = true;

            client_config.genesis = ClientGenesis::Interop {
                validator_count,
                genesis_time,
            };
        }
        ("file", Some(cli_args)) => {
            let path = cli_args
                .value_of("file")
                .ok_or_else(|| "No filename specified")?
                .parse::<PathBuf>()
                .map_err(|e| format!("Unable to parse filename: {:?}", e))?;

            let format = cli_args
                .value_of("format")
                .ok_or_else(|| "No file format specified")?;

            let start_method = match format {
                "ssz" => ClientGenesis::SszFile { path },
                other => return Err(format!("Unknown genesis file format: {}", other)),
            };

            client_config.genesis = start_method;
        }
        ("prysm", Some(_)) => {
            let mut spec = &mut eth2_config.spec;

            spec.min_deposit_amount = 100;
            spec.max_effective_balance = 3_200_000_000;
            spec.ejection_balance = 1_600_000_000;
            spec.effective_balance_increment = 100_000_000;
            spec.min_genesis_time = 0;
            spec.genesis_fork_version = [0, 0, 0, 2];

            client_config.eth1.deposit_contract_address =
                "0x802dF6aAaCe28B2EEb1656bb18dF430dDC42cc2e".to_string();
            client_config.eth1.deposit_contract_deploy_block = 1_487_270;
            client_config.eth1.follow_distance = 16;
            client_config.dummy_eth1_backend = false;

            client_config.genesis = ClientGenesis::DepositContract;
        }
        (cmd, Some(_)) => {
            return Err(format!(
                "Invalid valid method specified: {}. See 'testnet --help'.",
                cmd
            ))
        }
        _ => return Err("No testnet method specified. See 'testnet --help'.".into()),
    };

    create_new_datadir(&client_config, &eth2_config)?;

    Ok(())
}

fn random_string(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .collect::<String>()
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
pub fn unused_port(transport: &str) -> Result<u16> {
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
