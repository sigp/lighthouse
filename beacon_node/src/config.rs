use beacon_chain::chain_config::{
    DisallowedReOrgOffsets, ReOrgThreshold, DEFAULT_PREPARE_PAYLOAD_LOOKAHEAD_FACTOR,
    DEFAULT_RE_ORG_MAX_EPOCHS_SINCE_FINALIZATION, DEFAULT_RE_ORG_THRESHOLD,
};
use clap::ArgMatches;
use clap_utils::flags::DISABLE_MALLOC_TUNING_FLAG;
use clap_utils::parse_required;
use client::{ClientConfig, ClientGenesis};
use directory::{DEFAULT_BEACON_NODE_DIR, DEFAULT_NETWORK_DIR, DEFAULT_ROOT_DIR};
use environment::RuntimeContext;
use execution_layer::DEFAULT_JWT_FILE;
use genesis::Eth1Endpoint;
use http_api::TlsConfig;
use lighthouse_network::ListenAddress;
use lighthouse_network::{multiaddr::Protocol, Enr, Multiaddr, NetworkConfig, PeerIdSerialized};
use sensitive_url::SensitiveUrl;
use slog::{info, warn, Logger};
use std::cmp;
use std::cmp::max;
use std::fmt::Debug;
use std::fs;
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use types::{Checkpoint, Epoch, EthSpec, Hash256, PublicKeyBytes, GRAFFITI_BYTES_LEN};

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

    set_network_config(&mut client_config.network, cli_args, &data_dir_ref, log)?;

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

    client_config.http_api.sse_capacity_multiplier =
        parse_required(cli_args, "http-sse-capacity-multiplier")?;

    client_config.http_api.enable_beacon_processor =
        parse_required(cli_args, "http-enable-beacon-processor")?;

    client_config.http_api.duplicate_block_status_code =
        parse_required(cli_args, "http-duplicate-block-status")?;

    if let Some(cache_size) = clap_utils::parse_optional(cli_args, "shuffling-cache-size")? {
        client_config.chain.shuffling_cache_size = cache_size;
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

            el_config.builder_user_agent =
                clap_utils::parse_optional(cli_args, "builder-user-agent")?;
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
        el_config.always_prefer_builder_payload =
            cli_args.is_present("always-prefer-builder-payload");

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

    if let Some(freezer_dir) = cli_args.value_of("freezer-dir") {
        client_config.freezer_db_path = Some(PathBuf::from(freezer_dir));
    }

    let (sprp, sprp_explicit) = get_slots_per_restore_point::<E>(cli_args)?;
    client_config.store.slots_per_restore_point = sprp;
    client_config.store.slots_per_restore_point_set_explicitly = sprp_explicit;

    if let Some(block_cache_size) = cli_args.value_of("block-cache-size") {
        client_config.store.block_cache_size = block_cache_size
            .parse()
            .map_err(|_| "block-cache-size is not a valid integer".to_string())?;
    }

    if let Some(historic_state_cache_size) = cli_args.value_of("historic-state-cache-size") {
        client_config.store.historic_state_cache_size = historic_state_cache_size
            .parse()
            .map_err(|_| "historic-state-cache-size is not a valid integer".to_string())?;
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

    if let Some(epochs_per_migration) =
        clap_utils::parse_optional(cli_args, "epochs-per-migration")?
    {
        client_config.chain.epochs_per_migration = epochs_per_migration;
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

    client_config.genesis_state_url_timeout =
        clap_utils::parse_required(cli_args, "genesis-state-url-timeout")
            .map(Duration::from_secs)?;

    let genesis_state_url_opt =
        clap_utils::parse_optional::<String>(cli_args, "genesis-state-url")?;
    let checkpoint_sync_url_opt =
        clap_utils::parse_optional::<String>(cli_args, "checkpoint-sync-url")?;

    // If the `--genesis-state-url` is defined, use that to download the
    // genesis state bytes. If it's not defined, try `--checkpoint-sync-url`.
    client_config.genesis_state_url = if let Some(genesis_state_url) = genesis_state_url_opt {
        Some(genesis_state_url)
    } else if let Some(checkpoint_sync_url) = checkpoint_sync_url_opt {
        // If the checkpoint sync URL is going to be used to download the
        // genesis state, adopt the timeout from the checkpoint sync URL too.
        client_config.genesis_state_url_timeout =
            Duration::from_secs(client_config.chain.checkpoint_sync_url_timeout);
        Some(checkpoint_sync_url)
    } else {
        None
    };

    client_config.genesis = if eth2_network_config.genesis_state_is_known() {
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
                anchor_state_bytes,
                anchor_block_bytes,
            }
        } else if let Some(remote_bn_url) = cli_args.value_of("checkpoint-sync-url") {
            let url = SensitiveUrl::parse(remote_bn_url)
                .map_err(|e| format!("Invalid checkpoint sync URL: {:?}", e))?;

            ClientGenesis::CheckpointSyncUrl { url }
        } else {
            ClientGenesis::GenesisState
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
        client_config.chain.genesis_backfill = true;
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

    client_config.chain.max_network_size = lighthouse_network::gossip_max_size(
        spec.bellatrix_fork_epoch.is_some(),
        spec.gossip_max_size as usize,
    );

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

        if let Some(broadcast) = clap_utils::parse_optional(cli_args, "slasher-broadcast")? {
            slasher_config.broadcast = broadcast;
        }

        if let Some(backend) = clap_utils::parse_optional(cli_args, "slasher-backend")? {
            slasher_config.backend = backend;
        }

        client_config.slasher = Some(slasher_config);
    }

    if cli_args.is_present("validator-monitor-auto") {
        client_config.validator_monitor.auto_register = true;
    }

    if let Some(pubkeys) = cli_args.value_of("validator-monitor-pubkeys") {
        let pubkeys = pubkeys
            .split(',')
            .map(PublicKeyBytes::from_str)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Invalid --validator-monitor-pubkeys value: {:?}", e))?;
        client_config
            .validator_monitor
            .validators
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
            .validator_monitor
            .validators
            .extend_from_slice(&pubkeys);
    }

    if let Some(count) =
        clap_utils::parse_optional(cli_args, "validator-monitor-individual-tracking-threshold")?
    {
        client_config
            .validator_monitor
            .individual_tracking_threshold = count;
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
        client_config.chain.re_org_cutoff_millis =
            clap_utils::parse_optional(cli_args, "proposer-reorg-cutoff")?;

        if let Some(disallowed_offsets_str) =
            clap_utils::parse_optional::<String>(cli_args, "proposer-reorg-disallowed-offsets")?
        {
            let disallowed_offsets = disallowed_offsets_str
                .split(',')
                .map(|s| {
                    s.parse()
                        .map_err(|e| format!("invalid disallowed-offsets: {e:?}"))
                })
                .collect::<Result<Vec<u64>, _>>()?;
            client_config.chain.re_org_disallowed_offsets =
                DisallowedReOrgOffsets::new::<E>(disallowed_offsets)
                    .map_err(|e| format!("invalid disallowed-offsets: {e:?}"))?;
        }
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

    client_config.chain.always_prepare_payload = cli_args.is_present("always-prepare-payload");

    if let Some(timeout) =
        clap_utils::parse_optional(cli_args, "fork-choice-before-proposal-timeout")?
    {
        client_config.chain.fork_choice_before_proposal_timeout_ms = timeout;
    }

    if !clap_utils::parse_required::<bool>(cli_args, "count-unrealized")? {
        warn!(
            log,
            "The flag --count-unrealized is deprecated and will be removed";
            "info" => "any use of the flag will have no effect"
        );
    }

    if clap_utils::parse_required::<bool>(cli_args, "count-unrealized-full")? {
        warn!(
            log,
            "The flag --count-unrealized-full is deprecated and will be removed";
            "info" => "setting it to `true` has no effect"
        );
    }

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
        client_config.validator_monitor.auto_register = true;
    }

    // Optimistic finalized sync.
    client_config.chain.optimistic_finalized_sync =
        !cli_args.is_present("disable-optimistic-finalized-sync");

    if cli_args.is_present("genesis-backfill") {
        client_config.chain.genesis_backfill = true;
    }

    // Backfill sync rate-limiting
    client_config.beacon_processor.enable_backfill_rate_limiting =
        !cli_args.is_present("disable-backfill-rate-limiting");

    if let Some(path) = clap_utils::parse_optional(cli_args, "invalid-gossip-verified-blocks-path")?
    {
        client_config.network.invalid_block_storage = Some(path);
    }

    if let Some(progressive_balances_mode) =
        clap_utils::parse_optional(cli_args, "progressive-balances")?
    {
        client_config.chain.progressive_balances_mode = progressive_balances_mode;
    }

    if let Some(max_workers) = clap_utils::parse_optional(cli_args, "beacon-processor-max-workers")?
    {
        client_config.beacon_processor.max_workers = max_workers;
    }

    if client_config.beacon_processor.max_workers == 0 {
        return Err("--beacon-processor-max-workers must be a non-zero value".to_string());
    }

    client_config.beacon_processor.max_work_event_queue_len =
        clap_utils::parse_required(cli_args, "beacon-processor-work-queue-len")?;
    client_config.beacon_processor.max_scheduled_work_queue_len =
        clap_utils::parse_required(cli_args, "beacon-processor-reprocess-queue-len")?;
    client_config
        .beacon_processor
        .max_gossip_attestation_batch_size =
        clap_utils::parse_required(cli_args, "beacon-processor-attestation-batch-size")?;
    client_config
        .beacon_processor
        .max_gossip_aggregate_batch_size =
        clap_utils::parse_required(cli_args, "beacon-processor-aggregate-batch-size")?;

    Ok(client_config)
}

/// Gets the listening_addresses for lighthouse based on the cli options.
pub fn parse_listening_addresses(
    cli_args: &ArgMatches,
    log: &Logger,
) -> Result<ListenAddress, String> {
    let listen_addresses_str = cli_args
        .values_of("listen-address")
        .expect("--listen_addresses has a default value");

    let use_zero_ports = cli_args.is_present("zero-ports");

    // parse the possible ips
    let mut maybe_ipv4 = None;
    let mut maybe_ipv6 = None;
    for addr_str in listen_addresses_str {
        let addr = addr_str.parse::<IpAddr>().map_err(|parse_error| {
            format!("Failed to parse listen-address ({addr_str}) as an Ip address: {parse_error}")
        })?;

        match addr {
            IpAddr::V4(v4_addr) => match &maybe_ipv4 {
                Some(first_ipv4_addr) => {
                    return Err(format!(
                                "When setting the --listen-address option twice, use an IpV4 address and an Ipv6 address. \
                                Got two IpV4 addresses {first_ipv4_addr} and {v4_addr}"
                            ));
                }
                None => maybe_ipv4 = Some(v4_addr),
            },
            IpAddr::V6(v6_addr) => match &maybe_ipv6 {
                Some(first_ipv6_addr) => {
                    return Err(format!(
                                "When setting the --listen-address option twice, use an IpV4 address and an Ipv6 address. \
                                Got two IpV6 addresses {first_ipv6_addr} and {v6_addr}"
                            ));
                }
                None => maybe_ipv6 = Some(v6_addr),
            },
        }
    }

    // parse the possible tcp ports
    let port = cli_args
        .value_of("port")
        .expect("--port has a default value")
        .parse::<u16>()
        .map_err(|parse_error| format!("Failed to parse --port as an integer: {parse_error}"))?;
    let port6 = cli_args
        .value_of("port6")
        .map(str::parse::<u16>)
        .transpose()
        .map_err(|parse_error| format!("Failed to parse --port6 as an integer: {parse_error}"))?
        .unwrap_or(9090);

    // parse the possible udp ports
    let maybe_udp_port = cli_args
        .value_of("discovery-port")
        .map(str::parse::<u16>)
        .transpose()
        .map_err(|parse_error| {
            format!("Failed to parse --discovery-port as an integer: {parse_error}")
        })?;
    let maybe_udp6_port = cli_args
        .value_of("discovery-port6")
        .map(str::parse::<u16>)
        .transpose()
        .map_err(|parse_error| {
            format!("Failed to parse --discovery-port6 as an integer: {parse_error}")
        })?;

    // Now put everything together
    let listening_addresses = match (maybe_ipv4, maybe_ipv6) {
        (None, None) => {
            // This should never happen unless clap is broken
            return Err("No listening addresses provided".into());
        }
        (None, Some(ipv6)) => {
            // A single ipv6 address was provided. Set the ports

            if cli_args.is_present("port6") {
                warn!(log, "When listening only over IpV6, use the --port flag. The value of --port6 will be ignored.")
            }
            // use zero ports if required. If not, use the given port.
            let tcp_port = use_zero_ports
                .then(unused_port::unused_tcp6_port)
                .transpose()?
                .unwrap_or(port);

            if maybe_udp6_port.is_some() {
                warn!(log, "When listening only over IpV6, use the --discovery-port flag. The value of --discovery-port6 will be ignored.")
            }
            // use zero ports if required. If not, use the specific udp port. If none given, use
            // the tcp port.
            let udp_port = use_zero_ports
                .then(unused_port::unused_udp6_port)
                .transpose()?
                .or(maybe_udp_port)
                .unwrap_or(port);

            ListenAddress::V6(lighthouse_network::ListenAddr {
                addr: ipv6,
                udp_port,
                tcp_port,
            })
        }
        (Some(ipv4), None) => {
            // A single ipv4 address was provided. Set the ports

            // use zero ports if required. If not, use the given port.
            let tcp_port = use_zero_ports
                .then(unused_port::unused_tcp4_port)
                .transpose()?
                .unwrap_or(port);
            // use zero ports if required. If not, use the specific udp port. If none given, use
            // the tcp port.
            let udp_port = use_zero_ports
                .then(unused_port::unused_udp4_port)
                .transpose()?
                .or(maybe_udp_port)
                .unwrap_or(port);
            ListenAddress::V4(lighthouse_network::ListenAddr {
                addr: ipv4,
                udp_port,
                tcp_port,
            })
        }
        (Some(ipv4), Some(ipv6)) => {
            let ipv4_tcp_port = use_zero_ports
                .then(unused_port::unused_tcp4_port)
                .transpose()?
                .unwrap_or(port);
            let ipv4_udp_port = use_zero_ports
                .then(unused_port::unused_udp4_port)
                .transpose()?
                .or(maybe_udp_port)
                .unwrap_or(ipv4_tcp_port);

            // Defaults to 9090 when required
            let ipv6_tcp_port = use_zero_ports
                .then(unused_port::unused_tcp6_port)
                .transpose()?
                .unwrap_or(port6);
            let ipv6_udp_port = use_zero_ports
                .then(unused_port::unused_udp6_port)
                .transpose()?
                .or(maybe_udp6_port)
                .unwrap_or(ipv6_tcp_port);
            ListenAddress::DualStack(
                lighthouse_network::ListenAddr {
                    addr: ipv4,
                    udp_port: ipv4_udp_port,
                    tcp_port: ipv4_tcp_port,
                },
                lighthouse_network::ListenAddr {
                    addr: ipv6,
                    udp_port: ipv6_udp_port,
                    tcp_port: ipv6_tcp_port,
                },
            )
        }
    };

    Ok(listening_addresses)
}

/// Sets the network config from the command line arguments.
pub fn set_network_config(
    config: &mut NetworkConfig,
    cli_args: &ArgMatches,
    data_dir: &Path,
    log: &Logger,
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

    config.set_listening_addr(parse_listening_addresses(cli_args, log)?);

    // A custom target-peers command will overwrite the --proposer-only default.
    if let Some(target_peers_str) = cli_args.value_of("target-peers") {
        config.target_peers = target_peers_str
            .parse::<usize>()
            .map_err(|_| format!("Invalid number of target peers: {}", target_peers_str))?;
    } else {
        config.target_peers = 80; // default value
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

    if cli_args.is_present("disable-peer-scoring") {
        config.disable_peer_scoring = true;
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
        if config.trusted_peers.len() >= config.target_peers {
            slog::warn!(log, "More trusted peers than the target peer limit. This will prevent efficient peer selection criteria."; "target_peers" => config.target_peers, "trusted_peers" => config.trusted_peers.len());
        }
    }

    if let Some(enr_udp_port_str) = cli_args.value_of("enr-udp-port") {
        config.enr_udp4_port = Some(
            enr_udp_port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid discovery port: {}", enr_udp_port_str))?,
        );
    }

    if let Some(enr_tcp_port_str) = cli_args.value_of("enr-tcp-port") {
        config.enr_tcp4_port = Some(
            enr_tcp_port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid ENR TCP port: {}", enr_tcp_port_str))?,
        );
    }

    if let Some(enr_udp_port_str) = cli_args.value_of("enr-udp6-port") {
        config.enr_udp6_port = Some(
            enr_udp_port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid discovery port: {}", enr_udp_port_str))?,
        );
    }

    if let Some(enr_tcp_port_str) = cli_args.value_of("enr-tcp6-port") {
        config.enr_tcp6_port = Some(
            enr_tcp_port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid ENR TCP port: {}", enr_tcp_port_str))?,
        );
    }

    if cli_args.is_present("enr-match") {
        // Match the Ip and UDP port in the enr.

        // set the enr address to localhost if the address is unspecified
        if let Some(ipv4_addr) = config.listen_addrs().v4().cloned() {
            let ipv4_enr_addr = if ipv4_addr.addr == Ipv4Addr::UNSPECIFIED {
                Ipv4Addr::LOCALHOST
            } else {
                ipv4_addr.addr
            };
            config.enr_address.0 = Some(ipv4_enr_addr);
            config.enr_udp4_port = Some(ipv4_addr.udp_port);
        }

        if let Some(ipv6_addr) = config.listen_addrs().v6().cloned() {
            let ipv6_enr_addr = if ipv6_addr.addr == Ipv6Addr::UNSPECIFIED {
                Ipv6Addr::LOCALHOST
            } else {
                ipv6_addr.addr
            };
            config.enr_address.1 = Some(ipv6_enr_addr);
            config.enr_udp6_port = Some(ipv6_addr.udp_port);
        }
    }

    if let Some(enr_addresses) = cli_args.values_of("enr-address") {
        let mut enr_ip4 = None;
        let mut enr_ip6 = None;
        let mut resolved_enr_ip4 = None;
        let mut resolved_enr_ip6 = None;

        for addr in enr_addresses {
            match addr.parse::<IpAddr>() {
                Ok(IpAddr::V4(v4_addr)) => {
                    if let Some(used) = enr_ip4.as_ref() {
                        warn!(log, "More than one Ipv4 ENR address provided"; "used" => %used, "ignored" => %v4_addr)
                    } else {
                        enr_ip4 = Some(v4_addr)
                    }
                }
                Ok(IpAddr::V6(v6_addr)) => {
                    if let Some(used) = enr_ip6.as_ref() {
                        warn!(log, "More than one Ipv6 ENR address provided"; "used" => %used, "ignored" => %v6_addr)
                    } else {
                        enr_ip6 = Some(v6_addr)
                    }
                }
                Err(_) => {
                    // Try to resolve the address

                    // NOTE: From checking the `to_socket_addrs` code I don't think the port
                    // actually matters. Just use the udp port.

                    let port = match config.listen_addrs() {
                        ListenAddress::V4(v4_addr) => v4_addr.udp_port,
                        ListenAddress::V6(v6_addr) => v6_addr.udp_port,
                        ListenAddress::DualStack(v4_addr, _v6_addr) => {
                            // NOTE: slight preference for ipv4 that I don't think is of importance.
                            v4_addr.udp_port
                        }
                    };

                    let addr_str = format!("{addr}:{port}");
                    match addr_str.to_socket_addrs() {
                        Err(_e) => {
                            return Err(format!("Failed to parse or resolve address {addr}."))
                        }
                        Ok(resolved_addresses) => {
                            for socket_addr in resolved_addresses {
                                // Use the first ipv4 and first ipv6 addresses present.

                                // NOTE: this means that if two dns addresses are provided, we
                                // might end up using the ipv4 and ipv6 resolved addresses of just
                                // the first.
                                match socket_addr.ip() {
                                    IpAddr::V4(v4_addr) => {
                                        if resolved_enr_ip4.is_none() {
                                            resolved_enr_ip4 = Some(v4_addr)
                                        }
                                    }
                                    IpAddr::V6(v6_addr) => {
                                        if resolved_enr_ip6.is_none() {
                                            resolved_enr_ip6 = Some(v6_addr)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // The ENR addresses given as ips should take preference over any resolved address
        let used_host_resolution = resolved_enr_ip4.is_some() || resolved_enr_ip6.is_some();
        let ip4 = enr_ip4.or(resolved_enr_ip4);
        let ip6 = enr_ip6.or(resolved_enr_ip6);
        config.enr_address = (ip4, ip6);
        if used_host_resolution {
            config.discv5_config.enr_update = false;
        }
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

    // The self limiter is disabled by default.
    // This flag can be used both with or without a value. Try to parse it first with a value, if
    // no value is defined but the flag is present, use the default params.
    config.outbound_rate_limiter_config = clap_utils::parse_optional(cli_args, "self-limiter")?;
    if cli_args.is_present("self-limiter") && config.outbound_rate_limiter_config.is_none() {
        config.outbound_rate_limiter_config = Some(Default::default());
    }

    // Proposer-only mode overrides a number of previous configuration parameters.
    // Specifically, we avoid subscribing to long-lived subnets and wish to maintain a minimal set
    // of peers.
    if cli_args.is_present("proposer-only") {
        config.subscribe_all_subnets = false;

        if cli_args.value_of("target-peers").is_none() {
            // If a custom value is not set, change the default to 15
            config.target_peers = 15;
        }
        config.proposer_only = true;
        warn!(log, "Proposer-only mode enabled"; "info"=> "Do not connect a validator client to this node unless via the --proposer-nodes flag");
    }
    // The inbound rate limiter is enabled by default unless `disabled` is passed to the
    // `inbound-rate-limiter` flag. Any other value should be parsed as a configuration string.
    config.inbound_rate_limiter_config = match cli_args.value_of("inbound-rate-limiter") {
        None => {
            // Enabled by default, with default values
            Some(Default::default())
        }
        Some("disabled") => {
            // Explicitly disabled
            None
        }
        Some(config_str) => {
            // Enabled with a custom configuration
            Some(config_str.parse()?)
        }
    };
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
