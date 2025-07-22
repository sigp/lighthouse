-- create table if not exists store (
--     col text not null,
--     key bytea not null,
--     value bytea not null,
--     primary key (col, key)
-- );

CREATE TABLE beacon_meta (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE beacon_block (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE beacon_blob (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE beacon_data_column (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE beacon_state_hot_diff (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE beacon_state_hot_snapshot (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE beacon_state_snapshot (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE beacon_state_diff (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE beacon_state_hot_summary (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE beacon_cold_state_summary (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE executive_payload (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE beacon_chain (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE op_pool (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE fork_choice (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE pubkey_cache (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE beacon_state_roots (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE beacon_block_roots (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE beacon_randao_mixes (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE dht_enrs (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE custody_context (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE overflow_lru_cache (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE light_client_update (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE sync_committe_branch (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE sync_committe (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE dummy (
    key BYTEA PRIMARY KEY,
    value BYTEA NOT NULL
);