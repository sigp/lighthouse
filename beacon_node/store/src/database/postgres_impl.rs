use crate::{DBColumn, Error, AsyncKeyValueStore};
use sqlx::{PgPool, postgres::PgPoolOptions, Row};
use types::EthSpec;
use std::marker::PhantomData;
use async_trait::async_trait;

#[derive(Clone)]
pub struct PostgresDB<E: EthSpec> {
    db: PgPool,
    _phantom: PhantomData<E>
}

impl<E: EthSpec> PostgresDB<E> {
    pub async fn new(database_url: &str) -> Result<Self, Error> {
        let db = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .map_err(|e| Error::DBError { message: e.to_string() })?;

        Ok(Self {
            db,
            _phantom: PhantomData
        })
    }
}

#[async_trait]
impl<E: EthSpec> AsyncKeyValueStore<E> for PostgresDB<E> {
    async fn get_bytes(&self, column: DBColumn, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let table = get_table_name(column);
        let key = key.to_vec();

        let query = format!("SELECT value FROM {} WHERE key = $1", table);
        let row = sqlx::query(&query)
            .bind(key)
            .fetch_optional(&self.db)
            .await
            .map_err(|e| Error::DBError { message: e.to_string() })?;

        Ok(row.map(|r| r.get::<Vec<u8>, _>("value")))
    }

    async fn put_bytes(&self, column: DBColumn, key: &[u8], value: &[u8]) -> Result<(), Error> {
        let table = get_table_name(column);
        let key = key.to_vec();
        let value = value.to_vec();

        let query = format!(
            "INSERT INTO {} (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            table
        );

        sqlx::query(&query)
            .bind(key)
            .bind(value)
            .execute(&self.db)
            .await
            .map(|_| ())
            .map_err(|e| Error::DBError { message: e.to_string() })
    }

    async fn put_bytes_sync(&self, column: DBColumn, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.put_bytes(column, key, value).await
    }
}

pub fn get_table_name(column: DBColumn) -> &'static str {
    match column {
        DBColumn::BeaconMeta => "beacon_meta",
        DBColumn::BeaconBlock => "beacon_block",
        DBColumn::BeaconBlob => "beacon_blob",
        DBColumn::BeaconDataColumn => "beacon_data_column",
        DBColumn::BeaconState => "beacon_state",
        DBColumn::BeaconStateHotDiff => "beacon_state_hot_diff",
        DBColumn::BeaconStateHotSnapshot => "beacon_state_hot_snapshot",
        DBColumn::BeaconStateSnapshot => "beacon_state_snapshot",
        DBColumn::BeaconStateDiff => "beacon_state_diff",
        DBColumn::BeaconStateSummary => "beacon_state_summary",
        DBColumn::BeaconStateHotSummary => "beacon_state_hot_summary",
        DBColumn::BeaconColdStateSummary => "beacon_cold_state_summary",
        DBColumn::BeaconStateTemporary => "beacon_state_temporary",
        DBColumn::ExecPayload => "executive_payload",
        DBColumn::BeaconChain => "beacon_chain",
        DBColumn::OpPool => "op_pool",
        DBColumn::Eth1Cache => "eth1_cache",
        DBColumn::ForkChoice => "fork_choice",
        DBColumn::PubkeyCache => "pubkey_cache",
        DBColumn::BeaconRestorePoint => "beacon_restore_point",
        DBColumn::BeaconStateRoots => "beacon_state_roots",
        DBColumn::BeaconStateRootsChunked => "beacon_state_roots_chunked",
        DBColumn::BeaconBlockRoots => "beacon_block_roots",
        DBColumn::BeaconBlockRootsChunked => "beacon_block_roots_chunked",
        DBColumn::BeaconHistoricalRoots => "beacon_historical_roots",
        DBColumn::BeaconRandaoMixes => "beacon_randao_mixes",
        DBColumn::DhtEnrs => "dht_enrs",
        DBColumn::CustodyContext => "custody_context",
        DBColumn::OptimisticTransitionBlock => "optimistic_transition_block",
        DBColumn::BeaconHistoricalSummaries => "beacon_historical_summaries",
        DBColumn::OverflowLRUCache => "overflow_lru_cache",
        DBColumn::LightClientUpdate => "light_client_update",
        DBColumn::SyncCommitteeBranch => "sync_committe_branch",
        DBColumn::SyncCommittee => "sync_committe",
        DBColumn::Dummy => "dummy",
    }
}