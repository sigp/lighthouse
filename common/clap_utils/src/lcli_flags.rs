use crate::generate_flag_constants;
use lazy_static::lazy_static;

// lcli flags
generate_flag_constants!(
    LCLI_FLAGS,
    (SPEC_FLAG, "spec"),
    (TESTNET_DIR_FLAG, "testnet-dir"),
    (PRE_STATE_FLAG, "pre-state"),
    (SLOTS_FLAG, "slots"),
    (OUTPUT_FLAG, "output"),
    (BLOCK_FLAG, "block"),
    (FORMAT_FLAG, "format"),
    (TYPE_FLAG, "type"),
    (SSZ_FILE_FLAG, "ssz-file"),
    (ETH1_HTTP_FLAG, "eth1-http"),
    (CONFIRMATIONS_FLAG, "confirmations"),
    (VALIDATOR_COUNT_FLAG, "validator-count"),
    (ETH1_ENDPOINT_FLAG, "eth1-endpoint"),
    (ETH1_ENDPOINTS_FLAG, "eth1-endpoints"),
    (GENESIS_TIME_FLAG, "genesis-time"),
    (GENESIS_FORK_VERSION_FLAG, "genesis-fork-version"),
    (SSZ_STATE_FLAG, "ssz-state"),
    (MNEMONIC_FLAG, "mnemonic"),
    (EXECUTION_BLOCK_HASH_FLAG, "execution-block-hash"),
    (BASE_FEE_PER_GAS_FLAG, "base-fee-per-gas"),
    (GAS_LIMIT_FLAG, "gas-limit"),
    (FILE_FLAG, "file"),
    (FORCE_FLAG, "force"),
    (INTEROP_GENESIS_STATE_FLAG, "interop-genesis-state"),
    (MIN_GENESIS_TIME_FLAG, "min-genesis-time"),
    (
        MIN_GENESIS_ACTIVE_VALIDATOR_COUNT_FLAG,
        "min-genesis-active-validator-count"
    ),
    (GENESIS_DELAY_FLAG, "genesis-delay"),
    (MIN_DEPOSIT_AMOUNT_FLAG, "min-deposit-amount"),
    (MAX_EFFECTIVE_BALANCE_FLAG, "max-effective-balance"),
    (
        EFFECTIVE_BALANCE_INCREMENT_FLAG,
        "effective-balance-increment"
    ),
    (EJECTION_BALANCE_FLAG, "ejection-balance"),
    (ETH1_FOLLOW_DISTANCE_FLAG, "eth1-follow-distance"),
    (SECONDS_PER_SLOT_FLAG, "seconds-per-slot"),
    (SECONDS_PER_ETH1_BLOCK_FLAG, "seconds-per-eth1-block"),
    (ETH1_ID_FLAG, "eth1-id"),
    (DEPOSIT_CONTRACT_ADDRESS_FLAG, "deposit-contract-address"),
    (
        DEPOSIT_CONTRACT_DEPLOY_BLOCK_FLAG,
        "deposit-contract-deploy-block"
    ),
    (ALTAIR_FORK_EPOCH_FLAG, "altair-fork-epoch"),
    (MERGE_FORK_EPOCH_FLAG, "merge-fork-epoch"),
    (ETH1_BLOCK_HASH_FLAG, "eth1-block-hash"),
    (EXECUTION_PAYLOAD_HEADER_FLAG, "execution-payload-header"),
    (BOOT_ADDRESS_FLAG, "boot-address"),
    (BOOT_DIR_FLAG, "boot-dir"),
    (DEPOSIT_AMOUNT_FLAG, "deposit-amount"),
    (DEPOSIT_DATA_FLAG, "deposit-data"),
    (IP_FLAG, "ip"),
    (UDP_PORT_FLAG, "udp-port"),
    (TCP_PORT_FLAG, "tcp-port"),
    (OUTPUT_DIR_FLAG, "output-dir"),
    (COUNT_FLAG, "count"),
    (BASE_DIR_FLAG, "base-dir"),
    (NODE_COUNT_FLAG, "node-count"),
    (ENDPOINT_FLAG, "endpoint"),
    (START_EPOCH_FLAG, "start-epoch"),
    (END_EPOCH_FLAG, "end-epoch"),
    (OFFLINE_WINDOW_FLAG, "offline-window")
);

// lcli subcommands
generate_flag_constants!(
    LCLI_SUBCOMMANDS,
    (SKIP_SLOTS_CMD, "skip-slots"),
    (TRANSITION_BLOCKS_CMD, "transition-blocks"),
    (PRETTY_SSZ_CMD, "pretty-ssz"),
    (DEPLOY_DEPOSIT_CONTRACT_CMD, "deploy-deposit-contract"),
    (ETH1_GENESIS_CMD, "eth1-genesis"),
    (INTEROP_GENESIS_CMD, "interop-genesis"),
    (CHANGE_GENESIS_TIME_CMD, "change-genesis-time"),
    (REPLACE_STATE_PUBKEYS_CMD, "replace-state-pubkeys"),
    (CREATE_PAYLOAD_HEADER_CMD, "create-payload-header"),
    (NEW_TESTNET_CMD, "new-testnet"),
    (CHECK_DEPOSIT_DATA_CMD, "check-deposit-data"),
    (GENERATE_BOOTNODE_ENR_CMD, "generate-bootnode-enr"),
    (INSECURE_VALIDATORS_CMD, "insecure-validators"),
    (ETL_BLOCK_EFFICIENCY_CMD, "etl-block-efficiency")
);
