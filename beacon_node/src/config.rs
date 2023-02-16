use beacon_chain::chain_config::{
    ReOrgThreshold, DEFAULT_PREPARE_PAYLOAD_LOOKAHEAD_FACTOR,
    DEFAULT_RE_ORG_MAX_EPOCHS_SINCE_FINALIZATION, DEFAULT_RE_ORG_THRESHOLD,
};
use beacon_chain::TrustedSetup;
use clap::ArgMatches;
use clap_utils::flags::DISABLE_MALLOC_TUNING_FLAG;
use client::{ClientConfig, ClientGenesis};
use directory::{DEFAULT_BEACON_NODE_DIR, DEFAULT_NETWORK_DIR, DEFAULT_ROOT_DIR};
use environment::RuntimeContext;
use execution_layer::DEFAULT_JWT_FILE;
use genesis::Eth1Endpoint;
use http_api::TlsConfig;
use lighthouse_network::{multiaddr::Protocol, Enr, Multiaddr, NetworkConfig, PeerIdSerialized};
use sensitive_url::SensitiveUrl;
use slog::{info, warn, Logger};
use std::cmp;
use std::cmp::max;
use std::fmt::Debug;
use std::fmt::Write;
use std::fs;
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use types::{Checkpoint, Epoch, EthSpec, Hash256, PublicKeyBytes, GRAFFITI_BYTES_LEN};
use unused_port::{unused_tcp_port, unused_udp_port};

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

    let mut client_config = ClientConfig::default();

    // Update the client's data directory
    client_config.set_data_dir(get_data_dir(cli_args));

    // If necessary, remove any existing database and configuration
    if client_config.data_dir().exists() && cli_args.is_present("purge-db") {
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
    fs::create_dir_all(client_config.data_dir())
        .map_err(|e| format!("Failed to create data dir: {}", e))?;

    // logs the chosen data directory
    let mut log_dir = client_config.data_dir().clone();
    // remove /beacon from the end
    log_dir.pop();
    info!(log, "Data directory initialised"; "datadir" => log_dir.into_os_string().into_string().expect("Datadir should be a valid os string"));

    /*
     * Networking
     */

    let data_dir_ref = client_config.data_dir().clone();

    set_network_config(
        &mut client_config.network,
        cli_args,
        &data_dir_ref,
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
            .parse::<IpAddr>()
            .map_err(|_| "http-address is not a valid IP address.")?;
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
        warn!(
            log,
            "The flag --http-disable-legacy-spec is deprecated and will be removed"
        );
    }

    if let Some(fork_name) = clap_utils::parse_optional(cli_args, "http-spec-fork")? {
        client_config.http_api.spec_fork_name = Some(fork_name);
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
            .parse::<IpAddr>()
            .map_err(|_| "metrics-address is not a valid IP address.")?;
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
        let update_period_secs =
            clap_utils::parse_optional(cli_args, "monitoring-endpoint-period")?;

        client_config.monitoring_api = Some(monitoring_api::Config {
            db_path: None,
            freezer_db_path: None,
            update_period_secs,
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

        let endpoint = SensitiveUrl::parse(endpoint)
            .map_err(|e| format!("eth1-endpoint was an invalid URL: {:?}", e))?;
        client_config.eth1.endpoint = Eth1Endpoint::NoAuth(endpoint);
    } else if let Some(endpoint) = cli_args.value_of("eth1-endpoints") {
        client_config.sync_eth1_chain = true;
        let endpoint = SensitiveUrl::parse(endpoint)
            .map_err(|e| format!("eth1-endpoints contains an invalid URL {:?}", e))?;
        client_config.eth1.endpoint = Eth1Endpoint::NoAuth(endpoint);
    }

    if let Some(val) = cli_args.value_of("eth1-blocks-per-log-query") {
        client_config.eth1.blocks_per_log_query = val
            .parse()
            .map_err(|_| "eth1-blocks-per-log-query is not a valid integer".to_string())?;
    }

    if cli_args.is_present("eth1-purge-cache") {
        client_config.eth1.purge_cache = true;
    }

    if let Some(follow_distance) =
        clap_utils::parse_optional(cli_args, "eth1-cache-follow-distance")?
    {
        client_config.eth1.cache_follow_distance = Some(follow_distance);
    }

    if cli_args.is_present("merge") {
        if cli_args.is_present("execution-endpoint") {
            warn!(
                log,
                "The --merge flag is deprecated";
                "info" => "the --execution-endpoint flag automatically enables this feature"
            )
        } else {
            return Err("The --merge flag is deprecated. \
                Supply a value to --execution-endpoint instead."
                .into());
        }
    }

    if let Some(endpoints) = cli_args.value_of("execution-endpoint") {
        let mut el_config = execution_layer::Config::default();

        // Always follow the deposit contract when there is an execution endpoint.
        //
        // This is wasteful for non-staking nodes as they have no need to process deposit contract
        // logs and build an "eth1" cache. The alternative is to explicitly require the `--eth1` or
        // `--staking` flags, however that poses a risk to stakers since they cannot produce blocks
        // without "eth1".
        //
        // The waste for non-staking nodes is relatively small so we err on the side of safety for
        // stakers. The merge is already complicated enough.
        client_config.sync_eth1_chain = true;

        // Parse a single execution endpoint, logging warnings if multiple endpoints are supplied.
        let execution_endpoint =
            parse_only_one_value(endpoints, SensitiveUrl::parse, "--execution-endpoint", log)?;

        // JWTs are required if `--execution-endpoint` is supplied. They can be either passed via
        // file_path or directly as string.

        let secret_file: PathBuf;
        // Parse a single JWT secret from a given file_path, logging warnings if multiple are supplied.
        if let Some(secret_files) = cli_args.value_of("execution-jwt") {
            secret_file =
                parse_only_one_value(secret_files, PathBuf::from_str, "--execution-jwt", log)?;

        // Check if the JWT secret key is passed directly via cli flag and persist it to the default
        // file location.
        } else if let Some(jwt_secret_key) = cli_args.value_of("execution-jwt-secret-key") {
            use std::fs::File;
            use std::io::Write;
            secret_file = client_config.data_dir().join(DEFAULT_JWT_FILE);
            let mut jwt_secret_key_file = File::create(secret_file.clone())
                .map_err(|e| format!("Error while creating jwt_secret_key file: {:?}", e))?;
            jwt_secret_key_file
                .write_all(jwt_secret_key.as_bytes())
                .map_err(|e| {
                    format!(
                        "Error occured while writing to jwt_secret_key file: {:?}",
                        e
                    )
                })?;
        } else {
            return Err("Error! Please set either --execution-jwt file_path or --execution-jwt-secret-key directly via cli when using --execution-endpoint".to_string());
        }

        // Parse and set the payload builder, if any.
        if let Some(endpoint) = cli_args.value_of("builder") {
            let payload_builder =
                parse_only_one_value(endpoint, SensitiveUrl::parse, "--builder", log)?;
            el_config.builder_url = Some(payload_builder);
        }

        // Set config values from parse values.
        el_config.secret_files = vec![secret_file.clone()];
        el_config.execution_endpoints = vec![execution_endpoint.clone()];
        el_config.suggested_fee_recipient =
            clap_utils::parse_optional(cli_args, "suggested-fee-recipient")?;
        el_config.jwt_id = clap_utils::parse_optional(cli_args, "execution-jwt-id")?;
        el_config.jwt_version = clap_utils::parse_optional(cli_args, "execution-jwt-version")?;
        el_config.default_datadir = client_config.data_dir().clone();
        el_config.builder_profit_threshold =
            clap_utils::parse_required(cli_args, "builder-profit-threshold")?;
        let execution_timeout_multiplier =
            clap_utils::parse_required(cli_args, "execution-timeout-multiplier")?;
        el_config.execution_timeout_multiplier = Some(execution_timeout_multiplier);

        // If `--execution-endpoint` is provided, we should ignore any `--eth1-endpoints` values and
        // use `--execution-endpoint` instead. Also, log a deprecation warning.
        if cli_args.is_present("eth1-endpoints") || cli_args.is_present("eth1-endpoint") {
            warn!(
                log,
                "Ignoring --eth1-endpoints flag";
                "info" => "the value for --execution-endpoint will be used instead. \
                    --eth1-endpoints has been deprecated for post-merge configurations"
            );
        }
        client_config.eth1.endpoint = Eth1Endpoint::Auth {
            endpoint: execution_endpoint,
            jwt_path: secret_file,
            jwt_id: el_config.jwt_id.clone(),
            jwt_version: el_config.jwt_version.clone(),
        };

        // Store the EL config in the client config.
        client_config.execution_layer = Some(el_config);
    }

    // 4844 params
    client_config.trusted_setup = context
        .eth2_network_config
        .as_ref()
        .and_then(|config| config.kzg_trusted_setup.clone());

    // Override default trusted setup file if required
    // TODO: consider removing this when we get closer to launch
    if let Some(trusted_setup_file_path) = cli_args.value_of("trusted-setup-file-override") {
        let file = std::fs::File::open(trusted_setup_file_path)
            .map_err(|e| format!("Failed to open trusted setup file: {}", e))?;
        let trusted_setup: TrustedSetup = serde_json::from_reader(file)
            .map_err(|e| format!("Unable to read trusted setup file: {}", e))?;
        client_config.trusted_setup = Some(trusted_setup);
    }

    if let Some(freezer_dir) = cli_args.value_of("freezer-dir") {
        client_config.freezer_db_path = Some(PathBuf::from(freezer_dir));
    }

    if let Some(blobs_db_dir) = cli_args.value_of("blobs-dir") {
        client_config.blobs_db_path = Some(PathBuf::from(blobs_db_dir));
    }

    let (sprp, sprp_explicit) = get_slots_per_restore_point::<E>(cli_args)?;
    client_config.store.slots_per_restore_point = sprp;
    client_config.store.slots_per_restore_point_set_explicitly = sprp_explicit;

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

    if let Some(prune_payloads) = clap_utils::parse_optional(cli_args, "prune-payloads")? {
        client_config.store.prune_payloads = prune_payloads;
    }

    if let Some(prune_blobs) = clap_utils::parse_optional(cli_args, "prune-blobs")? {
        client_config.store.prune_blobs = prune_blobs;
    }

    if let Some(epochs_per_blob_prune) =
        clap_utils::parse_optional(cli_args, "epochs-per-blob-prune")?
    {
        client_config.store.epochs_per_blob_prune = epochs_per_blob_prune;
    }

    if let Some(blob_prune_margin_epochs) =
        clap_utils::parse_optional(cli_args, "blob-prune-margin-epochs")?
    {
        client_config.store.blob_prune_margin_epochs = blob_prune_margin_epochs;
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
            unused_tcp_port().map_err(|e| format!("Failed to get port for libp2p: {}", e))?;
        client_config.network.discovery_port =
            unused_udp_port().map_err(|e| format!("Failed to get port for discovery: {}", e))?;
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
    client_config.chain.checkpoint_sync_url_timeout =
        clap_utils::parse_required::<u64>(cli_args, "checkpoint-sync-url-timeout")?;

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
        lighthouse_network::gossip_max_size(spec.bellatrix_fork_epoch.is_some());

    if cli_args.is_present("slasher") {
        let slasher_dir = if let Some(slasher_dir) = cli_args.value_of("slasher-dir") {
            PathBuf::from(slasher_dir)
        } else {
            client_config.data_dir().join("slasher_db")
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

        if let Some(backend) = clap_utils::parse_optional(cli_args, "slasher-backend")? {
            slasher_config.backend = backend;
        }

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

    if let Some(count) =
        clap_utils::parse_optional(cli_args, "validator-monitor-individual-tracking-threshold")?
    {
        client_config.validator_monitor_individual_tracking_threshold = count;
    }

    if cli_args.is_present("disable-lock-timeouts") {
        client_config.chain.enable_lock_timeouts = false;
    }

    if cli_args.is_present("disable-proposer-reorgs") {
        client_config.chain.re_org_threshold = None;
    } else {
        client_config.chain.re_org_threshold = Some(
            clap_utils::parse_optional(cli_args, "proposer-reorg-threshold")?
                .map(ReOrgThreshold)
                .unwrap_or(DEFAULT_RE_ORG_THRESHOLD),
        );
        client_config.chain.re_org_max_epochs_since_finalization =
            clap_utils::parse_optional(cli_args, "proposer-reorg-epochs-since-finalization")?
                .unwrap_or(DEFAULT_RE_ORG_MAX_EPOCHS_SINCE_FINALIZATION);
    }

    // Note: This overrides any previous flags that enable this option.
    if cli_args.is_present("disable-deposit-contract-sync") {
        client_config.sync_eth1_chain = false;
    }

    client_config.chain.prepare_payload_lookahead =
        clap_utils::parse_optional(cli_args, "prepare-payload-lookahead")?
            .map(Duration::from_millis)
            .unwrap_or_else(|| {
                Duration::from_secs(spec.seconds_per_slot)
                    / DEFAULT_PREPARE_PAYLOAD_LOOKAHEAD_FACTOR
            });

    if let Some(timeout) =
        clap_utils::parse_optional(cli_args, "fork-choice-before-proposal-timeout")?
    {
        client_config.chain.fork_choice_before_proposal_timeout_ms = timeout;
    }

    client_config.chain.count_unrealized =
        clap_utils::parse_required(cli_args, "count-unrealized")?;
    client_config.chain.count_unrealized_full =
        clap_utils::parse_required::<bool>(cli_args, "count-unrealized-full")?.into();

    client_config.chain.always_reset_payload_statuses =
        cli_args.is_present("reset-payload-statuses");

    client_config.chain.paranoid_block_proposal = cli_args.is_present("paranoid-block-proposal");

    /*
     * Builder fallback configs.
     */
    client_config.chain.builder_fallback_skips =
        clap_utils::parse_required(cli_args, "builder-fallback-skips")?;
    client_config.chain.builder_fallback_skips_per_epoch =
        clap_utils::parse_required(cli_args, "builder-fallback-skips-per-epoch")?;
    client_config
        .chain
        .builder_fallback_epochs_since_finalization =
        clap_utils::parse_required(cli_args, "builder-fallback-epochs-since-finalization")?;
    client_config.chain.builder_fallback_disable_checks =
        cli_args.is_present("builder-fallback-disable-checks");

    // Graphical user interface config.
    if cli_args.is_present("gui") {
        client_config.http_api.enabled = true;
        client_config.validator_monitor_auto = true;
    }

    // Optimistic finalized sync.
    client_config.chain.optimistic_finalized_sync =
        !cli_args.is_present("disable-optimistic-finalized-sync");

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

    if let Some(value) = cli_args.value_of("network-load") {
        let network_load = value
            .parse::<u8>()
            .map_err(|_| format!("Invalid integer: {}", value))?;
        config.network_load = network_load;
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
        // set the enr address to localhost if the address is unspecified
        if config.listen_address == IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
            config.enr_address = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        } else if config.listen_address == IpAddr::V6(Ipv6Addr::UNSPECIFIED) {
            config.enr_address = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
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
                if let Some(enr_udp_port) =
                    config
                        .enr_udp_port
                        .or(if use_listening_port_as_enr_port_by_default {
                            Some(config.discovery_port)
                        } else {
                            None
                        })
                {
                    write!(addr, ":{}", enr_udp_port)
                        .map_err(|e| format!("Failed to write enr address {}", e))?;
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

    if cli_args.is_present("enable-private-discovery") {
        config.discv5_config.table_filter = |_| true;
    }

    // Light client server config.
    config.enable_light_client_server = cli_args.is_present("light-client-server");

    // This flag can be used both with or without a value. Try to parse it first with a value, if
    // no value is defined but the flag is present, use the default params.
    config.outbound_rate_limiter_config = clap_utils::parse_optional(cli_args, "self-limiter")?;
    if cli_args.is_present("self-limiter") && config.outbound_rate_limiter_config.is_none() {
        config.outbound_rate_limiter_config = Some(Default::default());
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

/// Get the `slots_per_restore_point` value to use for the database.
///
/// Return `(sprp, set_explicitly)` where `set_explicitly` is `true` if the user provided the value.
pub fn get_slots_per_restore_point<E: EthSpec>(
    cli_args: &ArgMatches,
) -> Result<(u64, bool), String> {
    if let Some(slots_per_restore_point) =
        clap_utils::parse_optional(cli_args, "slots-per-restore-point")?
    {
        Ok((slots_per_restore_point, true))
    } else {
        let default = std::cmp::min(
            E::slots_per_historical_root() as u64,
            store::config::DEFAULT_SLOTS_PER_RESTORE_POINT,
        );
        Ok((default, false))
    }
}

/// Parses the `cli_value` as a comma-separated string of values to be parsed with `parser`.
///
/// If there is more than one value, log a warning. If there are no values, return an error.
pub fn parse_only_one_value<F, T, E>(
    cli_value: &str,
    parser: F,
    flag_name: &str,
    log: &Logger,
) -> Result<T, String>
where
    F: Fn(&str) -> Result<T, E>,
    E: Debug,
{
    let values = cli_value
        .split(',')
        .map(parser)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{} contains an invalid value {:?}", flag_name, e))?;

    if values.len() > 1 {
        warn!(
            log,
            "Multiple values provided";
            "info" => "multiple values are deprecated, only the first value will be used",
            "count" => values.len(),
            "flag" => flag_name
        );
    }

    values
        .into_iter()
        .next()
        .ok_or(format!("Must provide at least one value to {}", flag_name))
}
