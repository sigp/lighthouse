use beacon_chain::chain_config::{
    DisallowedReOrgOffsets, ReOrgThreshold, DEFAULT_PREPARE_PAYLOAD_LOOKAHEAD_FACTOR,
};
use beacon_chain::TrustedSetup;
use clap_utils::GlobalConfig;
use client::{ClientConfig, ClientGenesis};
use directory::{DEFAULT_BEACON_NODE_DIR, DEFAULT_NETWORK_DIR, DEFAULT_ROOT_DIR};
use environment::RuntimeContext;
use execution_layer::DEFAULT_JWT_FILE;
use genesis::Eth1Endpoint;
use http_api::TlsConfig;
use lighthouse_network::rpc::config::{InboundRateLimiterConfig, OutboundRateLimiterConfig};
use lighthouse_network::ListenAddress;
use lighthouse_network::{multiaddr::Protocol, Enr, Multiaddr, NetworkConfig};
use sensitive_url::SensitiveUrl;
use slog::{info, warn, Logger};
use std::cmp;
use std::cmp::max;
use std::fs;
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use types::ForkName;
use types::{Checkpoint, Epoch, EthSpec, Hash256, PublicKeyBytes, GRAFFITI_BYTES_LEN};

use crate::cli::BeaconNode;
use crate::NetworkConfigurable;

/// Gets the fully-initialized global client.
///
/// The top-level `clap` arguments should be provided as `beacon_node`.
///
/// The output of this function depends primarily upon the given `beacon_node`, however it's behaviour
/// may be influenced by other external services like the contents of the file system or the
/// response of some remote server.
pub fn get_config<E: EthSpec>(
    beacon_config: &BeaconNode,
    global_config: &GlobalConfig,
    context: &RuntimeContext<E>,
) -> Result<ClientConfig, String> {
    let spec = &context.eth2_config.spec;
    let log = context.log();

    let mut client_config = ClientConfig::default();

    // Update the client's data directory
    client_config.set_data_dir(get_data_dir(global_config));

    // If necessary, remove any existing database and configuration
    if client_config.data_dir().exists() && beacon_config.purge_db {
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

        // Remove the blobs db.
        let blobs_db = client_config.get_blobs_db_path();
        if blobs_db.exists() {
            fs::remove_dir_all(blobs_db)
                .map_err(|err| format!("Failed to remove blobs_db: {}", err))?;
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
        beacon_config,
        &data_dir_ref,
        log,
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

    if beacon_config.enable_http() {
        client_config.http_api.enabled = true;

        client_config.http_api.listen_addr = IpAddr::V4(beacon_config.http_address);
        client_config.http_api.listen_port = beacon_config.http_port;

        if let Some(allow_origin) = beacon_config.http_allow_origin.as_ref() {
            // Pre-validate the config value to give feedback to the user on node startup, instead of
            // as late as when the first API response is produced.
            hyper::header::HeaderValue::from_str(allow_origin)
                .map_err(|_| "Invalid allow-origin value")?;

            client_config.http_api.allow_origin = Some(allow_origin.to_string());
        }

        if let Some(fork_name_str) = beacon_config.http_spec_fork.as_ref() {
            client_config.http_api.spec_fork_name = Some(ForkName::from_str(fork_name_str)?);
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

        client_config.http_api.allow_sync_stalled = beacon_config.http_allow_sync_stalled;
        client_config.http_api.sse_capacity_multiplier = beacon_config.http_sse_capacity_multiplier;
        client_config.http_api.enable_beacon_processor = beacon_config.http_enable_beacon_processor;

        client_config.http_api.duplicate_block_status_code = beacon_config
            .http_duplicate_block_status
            .to_string()
            .parse()
            .map_err(|e| format!("Failed to parse duplicate block status code. {}", e))?;

        client_config.http_api.enable_light_client_server = beacon_config.light_client_server;
    }

    if let Some(cache_size) = beacon_config.shuffling_cache_size {
        client_config.chain.shuffling_cache_size = cache_size;
    }

    /*
     * Prometheus metrics HTTP server
     */

    client_config.http_metrics.enabled = beacon_config.metrics;
    client_config.http_metrics.listen_addr = IpAddr::V4(beacon_config.metrics_address);
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
        let update_period_secs = beacon_config.monitoring_endpoint_period;

        client_config.monitoring_api = Some(monitoring_api::Config {
            db_path: None,
            freezer_db_path: None,
            update_period_secs: Some(update_period_secs),
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
    client_config.http_metrics.allocator_metrics_enabled = !global_config.disable_malloc_tuning;

    /*
     * Eth1
     */

    // When present, use an eth1 backend that generates deterministic junk.
    //
    // Useful for running testnets without the overhead of a deposit contract.
    client_config.dummy_eth1_backend = beacon_config.dummy_eth1;

    // When present, attempt to sync to an eth1 node.
    //
    // Required for block production.
    client_config.sync_eth1_chain = beacon_config.eth1;
    client_config.eth1.blocks_per_log_query = beacon_config.eth1_blocks_per_log_query;

    client_config.eth1.purge_cache = beacon_config.eth1_purge_cache;
    client_config.eth1.cache_follow_distance = beacon_config.eth1_cache_follow_distance;

    if let Some(endpoint) = beacon_config.execution_endpoint.as_ref() {
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
        let execution_endpoint = SensitiveUrl::from_str(endpoint)
            .map_err(|e| format!("Failed to parse execution endpoint url, {}", e))?;

        // JWTs are required if `--execution-endpoint` is supplied. They can be either passed via
        // file_path or directly as string.

        let secret_file: PathBuf;
        // Parse a single JWT secret from a given file_path
        if let Some(execution_jwt) = beacon_config.execution_jwt.as_ref() {
            secret_file = execution_jwt.clone();
        // Check if the JWT secret key is passed directly via cli flag and persist it to the default
        // file location.
        } else if let Some(jwt_secret_key) = beacon_config.execution_jwt_secret_key.as_ref() {
            use std::fs::File;
            use std::io::Write;
            secret_file = client_config.data_dir().join(DEFAULT_JWT_FILE);
            let mut jwt_secret_key_file = File::create(secret_file.clone())
                .map_err(|e| format!("Error while creating jwt_secret_key file: {:?}", e))?;
            jwt_secret_key_file
                .write_all(jwt_secret_key.as_bytes())
                .map_err(|e| {
                    format!(
                        "Error occurred while writing to jwt_secret_key file: {:?}",
                        e
                    )
                })?;
        } else {
            return Err("Error! Please set either --execution-jwt file_path or --execution-jwt-secret-key directly via cli when using --execution-endpoint".to_string());
        }

        // Parse and set the payload builder, if any.
        if let Some(endpoint) = beacon_config.builder.as_ref() {
            let payload_builder = SensitiveUrl::from_str(endpoint)
                .map_err(|e| format!("Failed to parse payload builder, {}", e))?;
            el_config.builder_url = Some(payload_builder);

            el_config.builder_user_agent = beacon_config.builder_user_agent.clone();
        }

        if beacon_config.builder_profit_threshold.is_some() {
            warn!(
                log,
                "Ignoring --builder-profit-threshold";
                "info" => "this flag is deprecated and will be removed"
            );
        }
        if beacon_config.always_prefer_builder_payload {
            warn!(
                log,
                "Ignoring --always-prefer-builder-payload";
                "info" => "this flag is deprecated and will be removed"
            );
        }

        // Set config values from parse values.
        el_config.secret_files = vec![secret_file.clone()];
        el_config.execution_endpoints = vec![execution_endpoint.clone()];
        el_config.suggested_fee_recipient = beacon_config.suggested_fee_recipient;
        el_config.jwt_id = beacon_config.execution_jwt_id.clone();
        el_config.jwt_version = beacon_config.execution_jwt_version.clone();
        el_config.default_datadir = client_config.data_dir().clone();
        el_config.execution_timeout_multiplier = Some(beacon_config.execution_timeout_multiplier);

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
        .and_then(|config| config.kzg_trusted_setup.as_ref())
        .map(|trusted_setup_bytes| serde_json::from_slice(trusted_setup_bytes))
        .transpose()
        .map_err(|e| format!("Unable to read trusted setup file: {}", e))?;

    // Override default trusted setup file if required
    if let Some(trusted_setup_file_path) = beacon_config.trusted_setup_file_override.as_ref() {
        let file = std::fs::File::open(trusted_setup_file_path)
            .map_err(|e| format!("Failed to open trusted setup file: {}", e))?;
        let trusted_setup: TrustedSetup = serde_json::from_reader(file)
            .map_err(|e| format!("Unable to read trusted setup file: {}", e))?;
        client_config.trusted_setup = Some(trusted_setup);
    }

    if let Some(freezer_dir) = beacon_config.freezer_dir.as_ref() {
        client_config.freezer_db_path = Some(PathBuf::from(freezer_dir));
    }

    if let Some(blobs_db_dir) = beacon_config.blobs_dir.as_ref() {
        client_config.blobs_db_path = Some(PathBuf::from(blobs_db_dir));
    }

    let (sprp, sprp_explicit) =
        get_slots_per_restore_point::<E>(beacon_config.slots_per_restore_point)?;
    client_config.store.slots_per_restore_point = sprp;
    client_config.store.slots_per_restore_point_set_explicitly = sprp_explicit;
    client_config.store.block_cache_size = beacon_config.block_cache_size;
    client_config.store.historic_state_cache_size = beacon_config.historic_state_cache_size;
    client_config.store.compact_on_init = beacon_config.compact_db;
    client_config.store.compact_on_prune = beacon_config.auto_compact_db;
    client_config.store.prune_payloads = beacon_config.prune_payloads;
    client_config.chain.epochs_per_migration = beacon_config.epochs_per_migration;
    client_config.store.prune_blobs = beacon_config.prune_blobs;
    client_config.store.epochs_per_blob_prune = beacon_config.epochs_per_blob_prune;
    client_config.store.blob_prune_margin_epochs = beacon_config.blob_prune_margin_epochs;

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

    client_config.chain.checkpoint_sync_url_timeout = beacon_config.checkpoint_sync_url_timeout;
    client_config.genesis_state_url_timeout =
        Duration::from_secs(global_config.genesis_state_url_timeout);
    let genesis_state_url_opt = global_config.genesis_state_url.clone();
    let checkpoint_sync_url_opt = beacon_config.checkpoint_sync_url.clone();

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

    client_config.allow_insecure_genesis_sync = beacon_config.allow_insecure_genesis_sync;

    client_config.genesis = if eth2_network_config.genesis_state_is_known() {
        // Set up weak subjectivity sync, or start from the hardcoded genesis state.
        if let (Some(initial_state_path), Some(initial_block_path), maybe_initial_blobs_path) = (
            beacon_config.checkpoint_state.as_ref(),
            beacon_config.checkpoint_block.as_ref(),
            beacon_config.checkpoint_blobs.as_ref(),
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

            ClientGenesis::WeakSubjSszBytes {
                anchor_state_bytes: read(initial_state_path)?,
                anchor_block_bytes: read(initial_block_path)?,
                anchor_blobs_bytes: maybe_initial_blobs_path
                    .map(|path| read(path))
                    .transpose()?,
            }
        } else if let Some(remote_bn_url) = beacon_config.checkpoint_sync_url.as_ref() {
            let url = SensitiveUrl::from_str(remote_bn_url)
                .map_err(|e| format!("Invalid checkpoint sync URL: {:?}", e))?;

            ClientGenesis::CheckpointSyncUrl { url }
        } else {
            ClientGenesis::GenesisState
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

    if beacon_config.reconstruct_historic_states {
        client_config.chain.reconstruct_historic_states = true;
        client_config.chain.genesis_backfill = true;
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

    client_config.chain.import_max_skip_slots = beacon_config.max_skip_slots;

    client_config.chain.max_network_size = lighthouse_network::gossip_max_size(
        spec.bellatrix_fork_epoch.is_some(),
        spec.gossip_max_size as usize,
    );

    if beacon_config.slasher {
        let slasher_dir = if let Some(slasher_dir) = beacon_config.slasher_dir.as_ref() {
            PathBuf::from(slasher_dir)
        } else {
            client_config.data_dir().join("slasher_db")
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
        slasher_config.backend = beacon_config.slasher_backend;
        client_config.slasher = Some(slasher_config);
    }

    client_config.validator_monitor.auto_register = beacon_config.validator_monitor_auto;

    if let Some(pubkeys) = beacon_config.validator_monitor_pubkeys.as_ref() {
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
            .validator_monitor
            .validators
            .extend_from_slice(&pubkeys);
    }

    client_config
        .validator_monitor
        .individual_tracking_threshold =
        beacon_config.validator_monitor_individual_tracking_threshold;

    client_config.chain.enable_lock_timeouts = !beacon_config.disable_lock_timeouts;

    if beacon_config.disable_proposer_reorgs {
        client_config.chain.re_org_threshold = None;
    } else {
        client_config.chain.re_org_threshold =
            Some(ReOrgThreshold(beacon_config.proposer_reorg_threshold));
        client_config.chain.re_org_max_epochs_since_finalization =
            beacon_config.proposer_reorg_epochs_since_finalization;

        client_config.chain.re_org_cutoff_millis = beacon_config.proposer_reorg_cutoff;

        if let Some(disallowed_offsets) = beacon_config.proposer_reorg_disallowed_offsets.as_ref() {
            client_config.chain.re_org_disallowed_offsets =
                DisallowedReOrgOffsets::new::<E>(disallowed_offsets.clone())
                    .map_err(|e| format!("invalid disallowed-offsets: {e:?}"))?;
        }
    }

    // Note: This overrides any previous flags that enable this option.
    client_config.sync_eth1_chain = !beacon_config.disable_deposit_contract_sync;

    client_config.chain.prepare_payload_lookahead = beacon_config
        .prepare_payload_lookahead
        .map(Duration::from_secs)
        .unwrap_or_else(|| {
            Duration::from_secs(spec.seconds_per_slot) / DEFAULT_PREPARE_PAYLOAD_LOOKAHEAD_FACTOR
        });

    client_config.chain.always_prepare_payload = beacon_config.always_prepare_payload;
    client_config.chain.fork_choice_before_proposal_timeout_ms =
        beacon_config.fork_choice_before_proposal_timeout;
    client_config.chain.always_reset_payload_statuses = beacon_config.reset_payload_statuses;
    client_config.chain.paranoid_block_proposal = beacon_config.paranoid_block_proposal;

    /*
     * Builder fallback configs.
     */
    client_config.chain.builder_fallback_skips = beacon_config.builder_fallback_skips;
    client_config.chain.builder_fallback_skips_per_epoch =
        beacon_config.builder_fallback_skips_per_epoch;

    client_config
        .chain
        .builder_fallback_epochs_since_finalization =
        beacon_config.builder_fallback_epochs_since_finalization;

    client_config.chain.builder_fallback_disable_checks =
        beacon_config.builder_fallback_disable_checks;

    // Graphical user interface config.
    if beacon_config.gui {
        client_config.http_api.enabled = true;
        client_config.validator_monitor.auto_register = true;
    }

    // Optimistic finalized sync.
    client_config.chain.optimistic_finalized_sync =
        !beacon_config.disable_optimistic_finalized_sync;

    client_config.chain.genesis_backfill = beacon_config.genesis_backfill;

    // Backfill sync rate-limiting
    client_config.beacon_processor.enable_backfill_rate_limiting =
        !beacon_config.disable_backfill_rate_limiting;

    client_config.network.invalid_block_storage =
        beacon_config.invalid_gossip_verified_blocks_path.clone();

    if let Some(progressive_balances_mode) = beacon_config.progressive_balances {
        client_config.chain.progressive_balances_mode = progressive_balances_mode;
    }

    if let Some(max_workers) = beacon_config.beacon_processor_max_workers {
        client_config.beacon_processor.max_workers = max_workers;
    }

    if client_config.beacon_processor.max_workers == 0 {
        return Err("--beacon-processor-max-workers must be a non-zero value".to_string());
    }

    client_config.beacon_processor.max_work_event_queue_len =
        beacon_config.beacon_processor_work_queue_len;
    client_config.beacon_processor.max_scheduled_work_queue_len =
        beacon_config.beacon_processor_reprocess_queue_len;
    client_config
        .beacon_processor
        .max_gossip_attestation_batch_size = beacon_config.beacon_processor_attestation_batch_size;
    client_config
        .beacon_processor
        .max_gossip_aggregate_batch_size = beacon_config.beacon_processor_aggregate_batch_size;

    Ok(client_config)
}

/// Gets the listening_addresses for lighthouse based on the cli options.
pub fn parse_listening_addresses<T: NetworkConfigurable>(
    config: &T,
    log: &Logger,
) -> Result<ListenAddress, String> {
    let use_zero_ports = config.is_zero_ports();

    // parse the possible ips
    let mut maybe_ipv4 = None;
    let mut maybe_ipv6 = None;
    for addr in config.get_listen_addresses() {
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

    let port = config.get_port();
    let port6 = config.get_port6();
    let maybe_disc_port = config.get_disc_port();
    let maybe_disc6_port = config.get_disc6_port();
    let maybe_quic_port = config.get_quic_port();
    let maybe_quic6_port = config.get_quic6_port();

    // Now put everything together
    let listening_addresses = match (maybe_ipv4, maybe_ipv6) {
        (None, None) => {
            // This should never happen unless clap is broken
            return Err("No listening addresses provided".into());
        }
        (None, Some(ipv6)) => {
            // A single ipv6 address was provided. Set the ports
            warn!(log, "When listening only over IPv6, use the --port flag. The value of --port6 will be ignored.")
            // use zero ports if required. If not, use the given port.
            let tcp_port = use_zero_ports
                .then(unused_port::unused_tcp6_port)
                .transpose()?
                .unwrap_or(port);

            if maybe_disc6_port.is_some() {
                warn!(log, "When listening only over IPv6, use the --discovery-port flag. The value of --discovery-port6 will be ignored.")
            }

            if maybe_quic6_port.is_some() {
                warn!(log, "When listening only over IPv6, use the --quic-port flag. The value of --quic-port6 will be ignored.")
            }

            // use zero ports if required. If not, use the specific udp port. If none given, use
            // the tcp port.
            let disc_port = use_zero_ports
                .then(unused_port::unused_udp6_port)
                .transpose()?
                .or(maybe_disc_port)
                .unwrap_or(tcp_port);

            let quic_port = use_zero_ports
                .then(unused_port::unused_udp6_port)
                .transpose()?
                .or(maybe_quic_port)
                .unwrap_or(if tcp_port == 0 { 0 } else { tcp_port + 1 });

            ListenAddress::V6(lighthouse_network::ListenAddr {
                addr: ipv6,
                quic_port,
                disc_port,
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
            // use zero ports if required. If not, use the specific discovery port. If none given, use
            // the tcp port.
            let disc_port = use_zero_ports
                .then(unused_port::unused_udp4_port)
                .transpose()?
                .or(maybe_disc_port)
                .unwrap_or(tcp_port);
            // use zero ports if required. If not, use the specific quic port. If none given, use
            // the tcp port + 1.
            let quic_port = use_zero_ports
                .then(unused_port::unused_udp4_port)
                .transpose()?
                .or(maybe_quic_port)
                .unwrap_or(if tcp_port == 0 { 0 } else { tcp_port + 1 });

            ListenAddress::V4(lighthouse_network::ListenAddr {
                addr: ipv4,
                disc_port,
                quic_port,
                tcp_port,
            })
        }
        (Some(ipv4), Some(ipv6)) => {
            let ipv4_tcp_port = use_zero_ports
                .then(unused_port::unused_tcp4_port)
                .transpose()?
                .unwrap_or(port);
            let ipv4_disc_port = use_zero_ports
                .then(unused_port::unused_udp4_port)
                .transpose()?
                .or(maybe_disc_port)
                .unwrap_or(ipv4_tcp_port);
            let ipv4_quic_port = use_zero_ports
                .then(unused_port::unused_udp4_port)
                .transpose()?
                .or(maybe_quic_port)
                .unwrap_or(if ipv4_tcp_port == 0 {
                    0
                } else {
                    ipv4_tcp_port + 1
                });

            // Defaults to 9090 when required
            let ipv6_tcp_port = use_zero_ports
                .then(unused_port::unused_tcp6_port)
                .transpose()?
                .unwrap_or(port6);
            let ipv6_disc_port = use_zero_ports
                .then(unused_port::unused_udp6_port)
                .transpose()?
                .or(maybe_disc6_port)
                .unwrap_or(ipv6_tcp_port);
            let ipv6_quic_port = use_zero_ports
                .then(unused_port::unused_udp6_port)
                .transpose()?
                .or(maybe_quic6_port)
                .unwrap_or(if ipv6_tcp_port == 0 {
                    0
                } else {
                    ipv6_tcp_port + 1
                });

            ListenAddress::DualStack(
                lighthouse_network::ListenAddr {
                    addr: ipv4,
                    disc_port: ipv4_disc_port,
                    quic_port: ipv4_quic_port,
                    tcp_port: ipv4_tcp_port,
                },
                lighthouse_network::ListenAddr {
                    addr: ipv6,
                    disc_port: ipv6_disc_port,
                    quic_port: ipv6_quic_port,
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
    beacon_node: &BeaconNode,
    data_dir: &Path,
    log: &Logger,
) -> Result<(), String> {
    // If a network dir has been specified, override the `datadir` definition.
    if let Some(dir) = beacon_node.network_dir.as_ref() {
        config.network_dir = dir.clone();
    } else {
        config.network_dir = data_dir.join(DEFAULT_NETWORK_DIR);
    };

    config.subscribe_all_subnets = beacon_node.subscribe_all_subnets;
    config.import_all_attestations = beacon_node.import_all_attestations;
    config.shutdown_after_sync = beacon_node.shutdown_after_sync;

    config.set_listening_addr(parse_listening_addresses(beacon_node, log)?);

    // A custom target-peers command will overwrite the --proposer-only default.
    if let Some(target_peers) = beacon_node.target_peers {
        config.target_peers = target_peers;
    }

    config.network_load = beacon_node.network_load;

    if let Some(boot_node_enrs) = beacon_node.boot_nodes.as_ref() {
        let mut enrs: Vec<Enr> = vec![];
        let mut multiaddrs: Vec<Multiaddr> = vec![];
        for addr in boot_node_enrs {
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

    if let Some(libp2p_addresses) = beacon_node.libp2p_addresses.as_ref() {
        config.libp2p_nodes = libp2p_addresses.clone();
    }

    config.disable_peer_scoring = beacon_node.disable_peer_scoring;

    if let Some(trusted_peers) = beacon_node.trusted_peers.as_ref() {
        config.trusted_peers = trusted_peers.clone();

        if config.trusted_peers.len() >= config.target_peers {
            slog::warn!(log, "More trusted peers than the target peer limit. This will prevent efficient peer selection criteria."; "target_peers" => config.target_peers, "trusted_peers" => config.trusted_peers.len());
        }
    }

    config.enr_udp4_port = beacon_node.enr_udp_port;
    config.enr_quic4_port = beacon_node.enr_quic_port;
    config.enr_tcp4_port = beacon_node.enr_tcp_port;

    config.enr_udp6_port = beacon_node.enr_udp6_port;
    config.enr_quic6_port = beacon_node.enr_quic6_port;
    config.enr_tcp6_port = beacon_node.enr_tcp6_port;

    if beacon_node.enr_match {
        // Match the IP and UDP port in the ENR.

        if let Some(ipv4_addr) = config.listen_addrs().v4().cloned() {
            // ensure the port is valid to be advertised
            let disc_port = ipv4_addr
                .disc_port
                .try_into()
                .map_err(|_| "enr-match can only be used with non-zero listening ports")?;

            // Set the ENR address to localhost if the address is unspecified.
            let ipv4_enr_addr = if ipv4_addr.addr == Ipv4Addr::UNSPECIFIED {
                Ipv4Addr::LOCALHOST
            } else {
                ipv4_addr.addr
            };
            config.enr_address.0 = Some(ipv4_enr_addr);
            config.enr_udp4_port = Some(disc_port);
        }

        if let Some(ipv6_addr) = config.listen_addrs().v6().cloned() {
            // ensure the port is valid to be advertised
            let disc_port = ipv6_addr
                .disc_port
                .try_into()
                .map_err(|_| "enr-match can only be used with non-zero listening ports")?;

            // Set the ENR address to localhost if the address is unspecified.
            let ipv6_enr_addr = if ipv6_addr.addr == Ipv6Addr::UNSPECIFIED {
                Ipv6Addr::LOCALHOST
            } else {
                ipv6_addr.addr
            };
            config.enr_address.1 = Some(ipv6_enr_addr);
            config.enr_udp6_port = Some(disc_port);
        }
    }

    if let Some(enr_addresses) = beacon_node.enr_addresses.as_ref() {
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
                        ListenAddress::V4(v4_addr) => v4_addr.disc_port,
                        ListenAddress::V6(v6_addr) => v6_addr.disc_port,
                        ListenAddress::DualStack(v4_addr, _v6_addr) => {
                            // NOTE: slight preference for ipv4 that I don't think is of importance.
                            v4_addr.disc_port
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

    config.discv5_config.enr_update = !beacon_node.disable_enr_auto_update;
    config.discv5_config.enable_packet_filter = !beacon_node.disable_packet_filter;
    config.disable_discovery = beacon_node.disable_discovery;
    config.disable_quic_support = beacon_node.disable_quic;
    config.upnp_enabled = !beacon_node.disable_upnp;
    config.private = beacon_node.private;
    config.metrics_enabled = beacon_node.metrics;

    if beacon_node.enable_private_discovery {
        config.discv5_config.table_filter = |_| true;
    }

    // Light client server config.
    config.enable_light_client_server = beacon_node.light_client_server;

    // The self limiter is disabled by default.
    // This flag can be used both with or without a value. Try to parse it first with a value, if
    // no value is defined but the flag is present, use the default params.

    if let Some(self_limiter) = beacon_node.self_limiter.as_ref() {
        config.outbound_rate_limiter_config =
            Some(OutboundRateLimiterConfig::from_str(self_limiter)?);
    }

    if beacon_node.self_limiter.is_some() && config.outbound_rate_limiter_config.is_none() {
        config.outbound_rate_limiter_config = Some(Default::default());
    }

    // Proposer-only mode overrides a number of previous configuration parameters.
    // Specifically, we avoid subscribing to long-lived subnets and wish to maintain a minimal set
    // of peers.
    if beacon_node.proposer_only {
        config.subscribe_all_subnets = false;

        if beacon_node.target_peers.is_none() {
            // If a custom value is not set, change the default to 15
            config.target_peers = 15;
        }
        config.proposer_only = true;
        warn!(log, "Proposer-only mode enabled"; "info"=> "Do not connect a validator client to this node unless via the --proposer-nodes flag");
    }

    // The inbound rate limiter is enabled by default unless `disabled` is passed to the
    // `inbound-rate-limiter` flag. Any other value should be parsed as a configuration string.

    if let Some(inbound_rate_limiter) = beacon_node.inbound_rate_limiter.as_ref() {
        if inbound_rate_limiter == &String::from("default") {
            config.inbound_rate_limiter_config = None;
        } else {
            config.inbound_rate_limiter_config =
                Some(InboundRateLimiterConfig::from_str(inbound_rate_limiter)?);
        }
    } else {
        config.inbound_rate_limiter_config = Some(Default::default());
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
) -> Result<(), String> {
    // If a network dir has been specified, override the `datadir` definition.
    if let Some(dir) = cli_config.get_network_dir() {
        config.network_dir = dir;
    } else {
        config.network_dir = data_dir.join(DEFAULT_NETWORK_DIR);
    };

    config.set_listening_addr(parse_listening_addresses(cli_config, log)?);

    if let Some(boot_enrs) = cli_config.get_boot_nodes() {
        let mut enrs: Vec<Enr> = vec![];
        let mut multiaddrs: Vec<Multiaddr> = vec![];
        for addr in boot_enrs {
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
    };

    config.enr_udp4_port = cli_config.get_enr_udp_port();

    if let Some(enr_addresses) = cli_config.get_enr_addresses() {
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
                        ListenAddress::V4(v4_addr) => v4_addr.disc_port,
                        ListenAddress::V6(v6_addr) => v6_addr.disc_port,
                        ListenAddress::DualStack(v4_addr, _v6_addr) => {
                            // NOTE: slight preference for ipv4 that I don't think is of importance.
                            v4_addr.disc_port
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

/// Get the `slots_per_restore_point` value to use for the database.
///
/// Return `(sprp, set_explicitly)` where `set_explicitly` is `true` if the user provided the value.
pub fn get_slots_per_restore_point<E: EthSpec>(
    maybe_slots_per_restore_point: Option<u64>,
) -> Result<(u64, bool), String> {
    if let Some(slots_per_restore_point) = maybe_slots_per_restore_point {
        Ok((slots_per_restore_point, true))
    } else {
        let default = std::cmp::min(
            E::slots_per_historical_root() as u64,
            store::config::DEFAULT_SLOTS_PER_RESTORE_POINT,
        );
        Ok((default, false))
    }
}
