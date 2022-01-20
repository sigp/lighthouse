//! CLI flags used across the Lighthouse code base can be located here.
//!
//! These flags are grouped according to which subcommands they are used in, in order to allow us to
//! validate which flags are available to which subcommands when loading config from a file.

/// This macro constructs a constant for each given `(identifier, value)` tuple, and a constant
/// group containing all of those.
macro_rules! generate_flag_constants {
    ($group_name:ident, $(($key:ident, $value:expr)),+) => {
        $(pub const $key: &str = $value;)+
        pub const $group_name: &[&'static str] = &[
            $($value,)*
        ];
    }
}

// Top level / Global
generate_flag_constants!(
    GLOBAL_FLAGS,
    (CONFIG_FILE_FLAG, "config-file"),
    (SPEC_FLAG, "spec"),
    (ENV_LOG_FLAG, "env_log"),
    (LOGFILE_FLAG, "logfile"),
    (LOGFILE_DEBUG_LEVEL_FLAG, "logfile-debug-level"),
    (LOGFILE_MAX_SIZE_FLAG, "logfile-max-size"),
    (LOGFILE_MAX_NUMBER_FLAG, "logfile-max-number"),
    (LOGFILE_COMPRESS_FLAG, "logfile-compress"),
    (LOG_FORMAT_FLAG, "log-format"),
    (DEBUG_LEVEL_FLAG, "debug-level"),
    (DATADIR_FLAG, "datadir"),
    (TESTNET_DIR_FLAG, "testnet-dir"),
    (NETWORK_FLAG, "network"),
    (DUMP_CONFIG_FLAG, "dump-config"),
    (IMMEDIATE_SHUTDOWN_FLAG, "immediate-shutdown"),
    (DISABLE_MALLOC_TUNING_FLAG, "disable-malloc-tuning"),
    (
        TERMINAL_TOTAL_DIFFICULTY_OVERRIDE_FLAG,
        "terminal-total-difficulty-override"
    ),
    (
        TERMINAL_BLOCK_HASH_OVERRIDE_FLAG,
        "terminal-block-hash-override"
    ),
    (
        TERMINAL_BLOCK_HASH_EPOCH_OVERRIDE_FLAG,
        "terminal-block-hash-epoch-override"
    )
);

// Beacon node
generate_flag_constants!(
    BEACON_NODE_FLAGS,
    (FREEZER_DIR_FLAG, "freezer-dir"),
    (SUBSCRIBE_ALL_SUBNETS_FLAG, "subscribe-all-subnets"),
    (IMPORT_ALL_ATTESTATIONS_FLAG, "import-all-attestations"),
    (SHUTDOWN_AFTER_SYNC_FLAG, "shutdown-after-sync"),
    (ZERO_PORTS_FLAG, "zero-ports"),
    (DISCOVERY_PORT_FLAG, "discovery-port"),
    (TARGET_PEERS_FLAG, "target-peers"),
    (DISABLE_UPNP_FLAG, "disable-upnp"),
    (PRIVATE_FLAG, "private"),
    (ENR_TCP_PORT_FLAG, "enr-tcp-port"),
    (ENR_MATCH_FLAG, "enr-match"),
    (DISABLE_ENR_AUTO_UPDATE_FLAG, "disable-enr-auto-update"),
    (LIBP2P_ADDRESSES_FLAG, "libp2p-addresses"),
    (DISABLE_DISCOVERY_FLAG, "disable-discovery"),
    (TRUSTED_PEERS_FLAG, "trusted-peers"),
    (HTTP_DISABLE_LEGACY_SPEC_FLAG, "http-disable-legacy-spec"),
    (HTTP_ENABLE_TLS_FLAG, "http-enable-tls"),
    (HTTP_TLS_CERT_FLAG, "http-tls-cert"),
    (HTTP_TLS_KEY_FLAG, "http-tls-key"),
    (HTTP_ALLOW_SYNC_STALLED_FLAG, "http-allow-sync-stalled"),
    (STAKING_FLAG, "staking"),
    (ETH1_FLAG, "eth1"),
    (DUMMY_ETH1_FLAG, "dummy-eth1"),
    (ETH1_ENDPOINT_FLAG, "eth1-endpoint"),
    (ETH1_ENDPOINTS_FLAG, "eth1-endpoints"),
    (ETH1_PURGE_CACHE_FLAG, "eth1-purge-cache"),
    (ETH1_BLOCKS_PER_LOG_QUERY_FLAG, "eth1-blocks-per-log-query"),
    (SLOTS_PER_RESTORE_POINT_FLAG, "slots-per-restore-point"),
    (BLOCK_CACHE_SIZE_FLAG, "block-cache-size"),
    (MERGE_FLAG, "merge"),
    (EXECUTION_ENDPOINTS_FLAG, "execution-endpoints"),
    (FEE_RECIPIENT_FLAG, "fee-recipient"),
    (PURGE_DB_FLAG, "purge-db"),
    (COMPACT_DB_FLAG, "compact-db"),
    (AUTO_COMPACT_DB_FLAG, "auto-compact-db"),
    (MAX_SKIP_SLOTS_FLAG, "max-skip-slots"),
    (SLASHER_FLAG, "slasher"),
    (SLASHER_DIR_FLAG, "slasher-dir"),
    (SLASHER_UPDATE_PERIOD_FLAG, "slasher-update-period"),
    (SLASHER_SLOT_OFFSET_FLAG, "slasher-slot-offset"),
    (SLASHER_HISTORY_LENGTH_FLAG, "slasher-history-length"),
    (SLASHER_MAX_DB_SIZE_FLAG, "slasher-max-db-size"),
    (SLASHER_ATT_CACHE_SIZE_FLAG, "slasher-att-cache-size"),
    (SLASHER_CHUNK_SIZE_FLAG, "slasher-chunk-size"),
    (
        SLASHER_VALIDATOR_CHUNK_SIZE_FLAG,
        "slasher-validator-chunk-size"
    ),
    (SLASHER_BROADCAST_FLAG, "slasher-broadcast"),
    (WSS_CHECKPOINT_FLAG, "wss-checkpoint"),
    (CHECKPOINT_STATE_FLAG, "checkpoint-state"),
    (CHECKPOINT_BLOCK_FLAG, "checkpoint-block"),
    (CHECKPOINT_SYNC_URL_FLAG, "checkpoint-sync-url"),
    (
        RECONSTRUCT_HISTORIC_STATE_FLAG,
        "reconstruct-historic-states"
    ),
    (VALIDATOR_MONITOR_AUTO_FLAG, "validator-monitor-auto"),
    (VALIDATOR_MONITOR_PUBKEYS_FLAG, "validator-monitor-pubkeys"),
    (VALIDATOR_MONITOR_FILE_FLAG, "validator-monitor-file"),
    (DISABLE_LOCK_TIMEOUTS_FLAG, "disable-lock-timeouts")
);

// Validator client
generate_flag_constants!(
    VALIDATOR_FLAGS,
    (BEACON_NODE_FLAG, "beacon-node"),
    (BEACON_NODES_FLAG, "beacon-nodes"),
    (SERVER_FLAG, "server"),
    (VALIDATORS_DIR_FLAG, "validators-dir"),
    (SECRETS_DIR_FLAG, "secrets-dir"),
    (DELETE_LOCKFILES_FLAG, "delete-lockfiles"),
    (INIT_SLASHING_PROTECTION_FLAG, "init-slashing-protection"),
    (DISABLE_AUTO_DISCOVER_FLAG, "disable-auto-discover"),
    (ALLOW_UNSYNCED_FLAG, "allow-unsynced"),
    (USE_LONG_TIMEOUTS_FLAG, "use-long-timeouts"),
    (BEACON_NODES_TLS_CERTS_FLAG, "beacon-nodes-tls-certs"),
    (GRAFFITI_FILE_FLAG, "graffiti-file"),
    (
        UNENCRYPTED_HTTP_TRANSPORT_FLAG,
        "unencrypted-http-transport"
    ),
    (
        ENABLE_DOPPELGANGER_PROTECTION_FLAG,
        "enable-doppelganger-protection"
    )
);

// Boot node
generate_flag_constants!(
    BOOT_NODE_FLAGS,
    (ENABLE_ENR_AUTO_UPDATE_FLAG, "enable-enr-auto-update")
);

// Beacon/Validator Common
generate_flag_constants!(
    BEACON_VALIDATOR_FLAGS,
    (HTTP_FLAG, "http"),
    (HTTP_ADDRESS_FLAG, "http-address"),
    (HTTP_PORT_FLAG, "http-port"),
    (HTTP_ALLOW_ORIGIN_FLAG, "http-allow-origin"),
    (METRICS_FLAG, "metrics"),
    (METRICS_ADDRESS_FLAG, "metrics-address"),
    (METRICS_PORT_FLAG, "metrics-port"),
    (METRICS_ALLOW_ORIGIN_FLAG, "metrics-allow-origin"),
    (MONITORING_ENDPOINT_FLAG, "monitoring-endpoint"),
    (GRAFFITI_FLAG, "graffiti")
);

// Beacon/Boot node Common
generate_flag_constants!(
    BEACON_BOOT_NODE_FLAGS,
    (ENR_ADDRESS_FLAG, "enr-address"),
    (PORT_FLAG, "port"),
    (LISTEN_ADDRESS_FLAG, "listen-address"),
    (BOOT_NODES_FLAG, "boot-nodes"),
    (NETWORK_LOAD_FLAG, "network-load"),
    (ENR_UDP_PORT_FLAG, "enr-udp-port"),
    (DISABLE_PACKET_FILTER_FLAG, "disable-packet-filter"),
    (NETWORK_DIR_FLAG, "network-dir")
);
