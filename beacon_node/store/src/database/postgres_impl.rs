use crate::{DBColumn, Error};
use sqlx::{PgPool, postgres::PgPoolOptions, Row};
use types::EthSpec;
use std::{marker::PhantomData, time::Duration};

#[derive(Clone)]
pub struct PostgresDB<E: EthSpec> {
    db: PgPool,
    _phantom: PhantomData<E>
}

impl<E: EthSpec> PostgresDB<E> {
    pub async fn open(database_url: &str) -> Result<Self, Error> {
        let db = PgPoolOptions::new()
            .max_connections(100)
            .acquire_timeout(Duration::from_secs(10))
            .connect(database_url)
            .await
            .map_err(|e| Error::DBError { message: e.to_string() })?;

        println!("Using Postgres backend🎯!!!");
        
        Ok(Self {
            db,
            _phantom: PhantomData
        })
    }
        
    pub async fn get_bytes(&self, column: DBColumn, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
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

    pub async fn put_bytes(&self, column: DBColumn, key: &[u8], value: &[u8]) -> Result<(), Error> {
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

    pub async fn key_exists(&self, column: DBColumn, key: &[u8]) -> Result<bool, Error> {
        let table = get_table_name(column);
        let key = key.to_vec();

        let query = format!("SELECT EXISTS (SELECT 1 FROM {} WHERE key = $1)", table);
        let exists: (bool, ) = sqlx::query_as(&query)
            .bind(key)
            .fetch_one(&self.db)
            .await
            .map_err(|e| Error::DBError { message: e.to_string() })?;
        Ok(exists.0)
    }

    pub async fn key_delete(&self, column: DBColumn, key: &[u8]) -> Result<(), Error> {
        let table = get_table_name(column);
        let key = key.to_vec();
        let query = format!("DELETE FROM {} WHERE key = $1", table);

        sqlx::query(&query)
            .bind(key)
            .execute(&self.db)
            .await
            .map(|_| ())
            .map_err(|e| Error::DBError { message: e.to_string() })
    }

    // pub async fn do_atomically(){}

    pub async fn compact(&self) -> Result<(), Error> {
        // No-op for Postgres, but we can run VACUUM FULL
        sqlx::query("VACUUM FULL")
            .execute(&self.db)
            .await
            .map(|_| ())
            .map_err(|e| Error::DBError { message: e.to_string() })
    }

    pub async fn compact_column(&self, column: DBColumn) -> Result<(), Error> {
        let table = get_table_name(column);
        let query = format!("VACUUM FULL {}", table);
        sqlx::query(&query)
            .execute(&self.db)
            .await
            .map(|_| ())
            .map_err(|e| Error::DBError { message: e.to_string() })
    }

    pub async fn iter_column_keys_from(&self, column: DBColumn, start: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let table = get_table_name(column);
        let query = format!("SELECT key FROM {} WHERE key >= $1 ORDER BY key ASC", table);
        let rows = sqlx::query(&query)
            .bind(start.to_vec())
            .fetch_all(&self.db)
            .await
            .map_err(|e| Error::DBError { message: e.to_string() })?;
        Ok(rows.into_iter().map(|r| r.get::<Vec<u8>, _>("key")).collect())
    }

    pub async fn iter_column_keys(&self, column: DBColumn) -> Result<Vec<Vec<u8>>, Error> {
        let table = get_table_name(column);
        let query = format!("SELECT key FROM {} ORDER BY key ASC", table);
        let rows = sqlx::query(&query)
            .fetch_all(&self.db)
            .await
            .map_err(|e| Error::DBError { message: e.to_string() })?;
        Ok(rows.into_iter().map(|r| r.get::<Vec<u8>, _>("key")).collect())
    }

    pub async fn iter_column_from(&self, column: DBColumn, start: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Error> {
        let table = get_table_name(column);
        let query = format!("SELECT key, value FROM {} WHERE key >= $1 ORDER BY key ASC", table);
        let rows = sqlx::query(&query)
            .bind(start.to_vec())
            .fetch_all(&self.db)
            .await
            .map_err(|e| Error::DBError { message: e.to_string() })?;
        Ok(rows.into_iter().map(|r| (r.get("key"), r.get("value"))).collect())
    }

    pub async fn delete_batch(&self, column: DBColumn, keys: &[Vec<u8>]) -> Result<(), Error> {
        let table = get_table_name(column);
        let mut tx = self.db.begin().await
            .map_err(|e| Error::DBError { message: e.to_string() })?;
        let query = format!("DELETE FROM {} WHERE key = $1", table);
        for key in keys {
            sqlx::query(&query)
                .bind(key.clone())
                .execute(&mut *tx)
                .await
                .map_err(|e| Error::DBError { message: e.to_string() })?;
        }
        tx.commit().await
            .map_err(|e| Error::DBError { message: e.to_string() })
    }

    pub async fn delete_if<F>(&self, column: DBColumn, predicate: F) -> Result<(), Error>
    where
        F: Fn(&[u8], &[u8]) -> bool
    {
        let table = get_table_name(column);
        let rows = sqlx::query(&format!("SELECT key, value FROM {}", table))
            .fetch_all(&self.db)
            .await
            .map_err(|e| Error::DBError { message: e.to_string() })?;
        let mut tx = self.db.begin().await
            .map_err(|e| Error::DBError { message: e.to_string() })?;
        for row in rows {
            let key: Vec<u8> = row.get("key");
            let value: Vec<u8> = row.get("value");
            if predicate(&key, &value) {
                sqlx::query(&format!("DELETE FROM {} WHERE key = $1", table))
                    .bind(key)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| Error::DBError { message: e.to_string() })?;
            }
        }
        tx.commit().await
            .map_err(|e| Error::DBError { message: e.to_string() })
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