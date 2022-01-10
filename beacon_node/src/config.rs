use clap::ArgMatches;
use clap_utils::flags::DISABLE_MALLOC_TUNING_FLAG;
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
    cli_args: &ArgMatches,
    context: &RuntimeContext<E>,
) -> Result<ClientConfig, String> {
    let spec = &context.eth2_config.spec;
    let log = context.log();

    let mut client_config = ClientConfig {
        data_dir: get_data_dir(cli_args),
        ..Default::default()
    };

    // If necessary, remove any existing database and configuration
    if client_config.data_dir.exists() && cli_args.is_present("purge-db") {
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
        cli_args,
        &client_config.data_dir,
        log,
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

    if cli_args.is_present("http-disable-legacy-spec") {
        client_config.http_api.serve_legacy_spec = false;
    }

    if cli_args.is_present("http-enable-tls") {
        client_config.http_api.tls_config = Some(TlsConfig {
            cert: cli_args
                .value_of("http-tls-cert")
                .ok_or("--http-tls-cert was not provided.")?
                .parse::<PathBuf>()
                .map_err(|_| "http-tls-cert is not a valid path name.")?,
            key: cli_args
                .value_of("http-tls-key")
                .ok_or("--http-tls-key was not provided.")?
                .parse::<PathBuf>()
                .map_err(|_| "http-tls-key is not a valid path name.")?,
        });
    }

    if cli_args.is_present("http-allow-sync-stalled") {
        client_config.http_api.allow_sync_stalled = true;
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

    /*
     * Explorer metrics
     */
    if let Some(monitoring_endpoint) = cli_args.value_of("monitoring-endpoint") {
        client_config.monitoring_api = Some(monitoring_api::Config {
            db_path: None,
            freezer_db_path: None,
            monitoring_endpoint: monitoring_endpoint.to_string(),
        });
    }

    // Log a warning indicating an open HTTP server if it wasn't specified explicitly
    // (e.g. using the --staking flag).
    if cli_args.is_present("staking") {
        warn!(
            log,
            "Running HTTP server on port {}", client_config.http_api.listen_port
        );
    }

    // Do not scrape for malloc metrics if we've disabled tuning malloc as it may cause panics.
    if cli_args.is_present(DISABLE_MALLOC_TUNING_FLAG) {
        client_config.http_metrics.allocator_metrics_enabled = false;
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
    if let Some(endpoint) = cli_args.value_of("eth1-endpoint") {
        warn!(
            log,
            "The --eth1-endpoint flag is deprecated";
            "msg" => "please use --eth1-endpoints instead"
        );
        client_config.sync_eth1_chain = true;
        client_config.eth1.endpoints = vec![SensitiveUrl::parse(endpoint)
            .map_err(|e| format!("eth1-endpoint was an invalid URL: {:?}", e))?];
    } else if let Some(endpoints) = cli_args.value_of("eth1-endpoints") {
        client_config.sync_eth1_chain = true;
        client_config.eth1.endpoints = endpoints
            .split(',')
            .map(SensitiveUrl::parse)
            .collect::<Result<_, _>>()
            .map_err(|e| format!("eth1-endpoints contains an invalid URL {:?}", e))?;
    }

    if let Some(val) = cli_args.value_of("eth1-blocks-per-log-query") {
        client_config.eth1.blocks_per_log_query = val
            .parse()
            .map_err(|_| "eth1-blocks-per-log-query is not a valid integer".to_string())?;
    }

    if cli_args.is_present("eth1-purge-cache") {
        client_config.eth1.purge_cache = true;
    }

    if let Some(endpoints) = cli_args.value_of("execution-endpoints") {
        client_config.sync_eth1_chain = true;
        client_config.execution_endpoints = endpoints
            .split(',')
            .map(SensitiveUrl::parse)
            .collect::<Result<_, _>>()
            .map(Some)
            .map_err(|e| format!("execution-endpoints contains an invalid URL {:?}", e))?;
    } else if cli_args.is_present("merge") {
        client_config.execution_endpoints = Some(client_config.eth1.endpoints.clone());
    }

    client_config.suggested_fee_recipient = Some(
        clap_utils::parse_optional(cli_args, "fee-recipient")?
            // TODO(merge): remove this default value. It's just there to make life easy during
            // early testnets.
            .unwrap_or_else(|| Address::from(DEFAULT_SUGGESTED_FEE_RECIPIENT)),
    );

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

    client_config.store.compact_on_init = cli_args.is_present("compact-db");
    if let Some(compact_on_prune) = cli_args.value_of("auto-compact-db") {
        client_config.store.compact_on_prune = compact_on_prune
            .parse()
            .map_err(|_| "auto-compact-db takes a boolean".to_string())?;
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
            cli_args.value_of("checkpoint-state"),
            cli_args.value_of("checkpoint-block"),
        ) {
            let read = |path: &str| {
                use std::fs::File;
                use std::io::Read;
                File::open(Path::new(path))
                    .and_then(|mut f| {
                        let mut buffer = vec![];
                        f.read_to_end(&mut buffer)?;
                        Ok(buffer)
                    })
                    .map_err(|e| format!("Unable to open {}: {:?}", path, e))
            };

            let anchor_state_bytes = read(initial_state_path)?;
            let anchor_block_bytes = read(initial_block_path)?;

            ClientGenesis::WeakSubjSszBytes {
                genesis_state_bytes,
                anchor_state_bytes,
                anchor_block_bytes,
            }
        } else if let Some(remote_bn_url) = cli_args.value_of("checkpoint-sync-url") {
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
        if cli_args.is_present("checkpoint-state") || cli_args.is_present("checkpoint-sync-url") {
            return Err(
                "Checkpoint sync is not available for this network as no genesis state is known"
                    .to_string(),
            );
        }
        ClientGenesis::DepositContract
    };

    if cli_args.is_present("reconstruct-historic-states") {
        client_config.chain.reconstruct_historic_states = true;
    }

    let raw_graffiti = if let Some(graffiti) = cli_args.value_of("graffiti") {
        if graffiti.len() > GRAFFITI_BYTES_LEN {
            return Err(format!(
                "Your graffiti is too long! {} bytes maximum!",
                GRAFFITI_BYTES_LEN
            ));
        }

        graffiti.as_bytes()
    } else if cli_args.is_present("private") {
        b""
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

    if let Some(max_skip_slots) = cli_args.value_of("max-skip-slots") {
        client_config.chain.import_max_skip_slots = match max_skip_slots {
            "none" => None,
            n => Some(
                n.parse()
                    .map_err(|_| "Invalid max-skip-slots".to_string())?,
            ),
        };
    }

    client_config.chain.max_network_size =
        lighthouse_network::gossip_max_size(spec.merge_fork_epoch.is_some());

    if cli_args.is_present("slasher") {
        let slasher_dir = if let Some(slasher_dir) = cli_args.value_of("slasher-dir") {
            PathBuf::from(slasher_dir)
        } else {
            client_config.data_dir.join("slasher_db")
        };

        let mut slasher_config = slasher::Config::new(slasher_dir);

        if let Some(update_period) = clap_utils::parse_optional(cli_args, "slasher-update-period")?
        {
            slasher_config.update_period = update_period;
        }

        if let Some(slot_offset) =
            clap_utils::parse_optional::<f64>(cli_args, "slasher-slot-offset")?
        {
            if slot_offset.is_finite() {
                slasher_config.slot_offset = slot_offset;
            } else {
                return Err(format!(
                    "invalid float for slasher-slot-offset: {}",
                    slot_offset
                ));
            }
        }

        if let Some(history_length) =
            clap_utils::parse_optional(cli_args, "slasher-history-length")?
        {
            slasher_config.history_length = history_length;
        }

        if let Some(max_db_size_gbs) =
            clap_utils::parse_optional::<usize>(cli_args, "slasher-max-db-size")?
        {
            slasher_config.max_db_size_mbs = max_db_size_gbs * 1024;
        }

        if let Some(attestation_cache_size) =
            clap_utils::parse_optional(cli_args, "slasher-att-cache-size")?
        {
            slasher_config.attestation_root_cache_size = attestation_cache_size;
        }

        if let Some(chunk_size) = clap_utils::parse_optional(cli_args, "slasher-chunk-size")? {
            slasher_config.chunk_size = chunk_size;
        }

        if let Some(validator_chunk_size) =
            clap_utils::parse_optional(cli_args, "slasher-validator-chunk-size")?
        {
            slasher_config.validator_chunk_size = validator_chunk_size;
        }

        slasher_config.broadcast = cli_args.is_present("slasher-broadcast");

        client_config.slasher = Some(slasher_config);
    }

    if cli_args.is_present("validator-monitor-auto") {
        client_config.validator_monitor_auto = true;
    }

    if let Some(pubkeys) = cli_args.value_of("validator-monitor-pubkeys") {
        let pubkeys = pubkeys
            .split(',')
            .map(PublicKeyBytes::from_str)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Invalid --validator-monitor-pubkeys value: {:?}", e))?;
        client_config
            .validator_monitor_pubkeys
            .extend_from_slice(&pubkeys);
    }

    if let Some(path) = cli_args.value_of("validator-monitor-file") {
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

    if cli_args.is_present("disable-lock-timeouts") {
        client_config.chain.enable_lock_timeouts = false;
    }

    Ok(client_config)
}

/// Sets the network config from the command line arguments
pub fn set_network_config(
    config: &mut NetworkConfig,
    cli_args: &ArgMatches,
    data_dir: &Path,
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

    if cli_args.is_present("import-all-attestations") {
        config.import_all_attestations = true;
    }

    if cli_args.is_present("shutdown-after-sync") {
        config.shutdown_after_sync = true;
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

    if cli_args.is_present("disable-enr-auto-update") {
        config.discv5_config.enr_update = false;
    }

    if cli_args.is_present("disable-packet-filter") {
        warn!(log, "Discv5 packet filter is disabled");
        config.discv5_config.enable_packet_filter = false;
    }

    if cli_args.is_present("disable-discovery") {
        config.disable_discovery = true;
        warn!(log, "Discovery is disabled. New peers will not be found");
    }

    if cli_args.is_present("disable-upnp") {
        config.upnp_enabled = false;
    }

    if cli_args.is_present("private") {
        config.private = true;
    }

    if cli_args.is_present("metrics") {
        config.metrics_enabled = true;
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
                    .join(directory::get_network_dir(cli_args))
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
