use log::{error, info};
use std::convert::TryInto;
use std::time::Duration;
use tokio::{runtime, task::JoinHandle};
use tokio_postgres::{config::Config as PostgresConfig, Client, NoTls, Row};
use types::{BeaconBlockHeader, Epoch, EthSpec, Hash256, Slot};

pub use config::Config;
pub use error::Error;
pub use tokio_postgres::Transaction;

mod config;
mod error;

pub struct Database {
    client: Client,
    _connection: JoinHandle<()>,
    _config: Config,
}

impl Database {
    pub async fn connect(config: Config) -> Result<Self, Error> {
        let (client, connection) = Self::postgres_config(&config).connect(NoTls).await?;
        let connection = runtime::Handle::current().spawn(async move {
            if let Err(e) = connection.await {
                error!("Connection error: {:?}", e);
            }
        });

        Ok(Self {
            client,
            _connection: connection,
            _config: config,
        })
    }

    /// Open an existing database at the given `path`, or create one if none exists.
    fn postgres_config(config: &Config) -> PostgresConfig {
        let mut postgres_config = PostgresConfig::new();
        postgres_config
            .user(&config.user)
            .password(config.password.clone())
            .dbname(&config.dbname)
            .host(&config.host)
            .port(config.port)
            .connect_timeout(Duration::from_millis(config.connect_timeout_millis));
        postgres_config
    }

    /// Create a slashing database at the given path.
    ///
    /// Error if a database (or any file) already exists at `path`.
    pub async fn create(config: Config) -> Result<Self, Error> {
        Self::create_database(&config).await?;

        let db = Self::connect(config).await?;

        db.client
            .execute(
                "CREATE TABLE validators (
                id integer PRIMARY KEY,
                validator_index integer NOT NULL,
                public_key char(98) NOT NULL
            )",
                &[],
            )
            .await?;

        db.client
            .execute(
                "CREATE TABLE beacon_blocks (
                root char(66) PRIMARY KEY,
                parent_root char(66) NOT NULL,
                slot integer NOT NULL
            )",
                &[],
            )
            .await?;

        db.client
            .execute(
                "CREATE TABLE canonical_slots (
                slot integer PRIMARY KEY,
                root char(66),
                beacon_block char(66) REFERENCES beacon_blocks(root)
            )",
                &[],
            )
            .await?;

        db.client
            .execute(
                "CREATE TABLE canonical_epochs (
                epoch integer PRIMARY KEY,
                root char(66),
                beacon_block char(66) REFERENCES beacon_blocks(root)
            )",
                &[],
            )
            .await?;

        Ok(db)
    }

    pub async fn create_database(config: &Config) -> Result<(), Error> {
        let mut config = config.clone();
        let new_dbname = std::mem::replace(&mut config.dbname, config.default_dbname.clone());
        let db = Self::connect(config.clone()).await?;

        if config.drop_dbname {
            info!("Dropping {} database", new_dbname);

            db.client
                .execute(&format!("DROP DATABASE IF EXISTS {};", new_dbname), &[])
                .await?;
        }

        info!("Creating {} database", new_dbname);

        db.client
            .execute(&format!("CREATE DATABASE {};", new_dbname), &[])
            .await?;
        Ok(())
    }

    pub async fn transaction<'a>(&'a mut self) -> Result<Transaction<'a>, Error> {
        self.client.transaction().await.map_err(Into::into)
    }

    pub async fn delete_canonical_roots_above<'a, T: EthSpec>(
        tx: &'a Transaction<'a>,
        slot: Slot,
    ) -> Result<(), Error> {
        let epoch = slot.epoch(T::slots_per_epoch());
        let epoch_end_slot = epoch.end_slot(T::slots_per_epoch());

        // Optionally remove the canonical epoch.
        if slot < epoch_end_slot {
            tx.execute(
                "DELETE FROM canonical_epochs
                    WHERE epoch > $1",
                &[&encode_epoch(epoch)?],
            )
            .await?;
        }

        tx.execute(
            "DELETE FROM canonical_slots
                WHERE slot > $1",
            &[&encode_slot(slot)?],
        )
        .await?;

        Ok(())
    }

    pub async fn insert_canonical_root<'a, T: EthSpec>(
        tx: &'a Transaction<'a>,
        slot: Slot,
        root: Hash256,
    ) -> Result<(), Error> {
        let root = encode_hash256(root);
        let epoch = slot.epoch(T::slots_per_epoch());
        let epoch_end_slot = epoch.end_slot(T::slots_per_epoch());

        // Optionally update the canonical epoch.
        if slot == epoch_end_slot {
            tx.execute(
                "INSERT INTO canonical_epochs (epoch, root)
                VALUES ($1, $2)",
                &[&encode_epoch(epoch)?, &root],
            )
            .await?;
        }

        tx.execute(
            "INSERT INTO canonical_slots (slot, root)
            VALUES ($1, $2)",
            &[&encode_slot(slot)?, &root],
        )
        .await
        .map_err(Into::into)
        .map(|_| ())
    }

    pub async fn get_root_at_canonical_slot<'a>(
        tx: &'a Transaction<'a>,
        slot: Slot,
    ) -> Result<Option<Hash256>, Error> {
        let row_opt = tx
            .query_opt(
                "SELECT root
                FROM canonical_slots
                WHERE slot = $1;",
                &[&encode_slot(slot)?],
            )
            .await?;

        if let Some(row) = row_opt {
            Ok(Some(row_to_root(&row, 0)?))
        } else {
            Ok(None)
        }
    }

    pub async fn lowest_canonical_slot<'a>(tx: &'a Transaction<'a>) -> Result<Option<Slot>, Error> {
        let row_opt = tx
            .query_opt(
                "SELECT MIN(slot)
                FROM canonical_slots",
                &[],
            )
            .await?;

        if let Some(row) = row_opt {
            if let Some(slot) = row.try_get::<_, Option<i32>>(0)? {
                let slot: u64 = slot.try_into().map_err(|_| Error::InvalidSlot)?;
                Ok(Some(slot.into()))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    pub async fn unknown_canonical_blocks<'a>(
        tx: &'a Transaction<'a>,
        count: i64,
    ) -> Result<Vec<Hash256>, Error> {
        let rows = tx
            .query(
                "SELECT root
                FROM canonical_slots
                WHERE beacon_block IS NULL
                ORDER BY slot DESC
                LIMIT $1",
                &[&count],
            )
            .await?;

        rows.into_iter()
            .map(|row| row_to_root(&row, 0))
            .collect::<Result<_, _>>()
    }

    pub async fn insert_canonical_header_if_not_exists<'a>(
        tx: &'a Transaction<'a>,
        header: &BeaconBlockHeader,
        header_root: Hash256,
    ) -> Result<(), Error> {
        let slot = encode_slot(header.slot)?;
        let header_root = encode_hash256(header_root);

        tx.execute(
            "INSERT INTO beacon_blocks (slot, root, parent_root)
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING",
            &[&slot, &header_root, &encode_hash256(header.parent_root)],
        )
        .await?;

        tx.execute(
            "UPDATE canonical_slots
            SET beacon_block = $1
            WHERE slot = $2",
            &[&header_root, &slot],
        )
        .await?;

        Ok(())
    }

    pub async fn get_beacon_block<'a>(
        tx: &'a Transaction<'a>,
        root: Hash256,
    ) -> Result<Option<WatchBeaconBlock>, Error> {
        let row = tx
            .query_opt(
                "SELECT (slot, root, parent_root)
                FROM beacon_blocks
                WHERE root = ",
                &[&encode_hash256(root)],
            )
            .await?;

        let block_opt = if let Some(row) = row {
            let block = WatchBeaconBlock {
                slot: row_to_slot(&row, 0)?,
                root: row_to_root(&row, 1)?,
                parent_root: row_to_root(&row, 2)?,
            };

            Some(block)
        } else {
            None
        };

        Ok(block_opt)
    }
}

struct WatchBeaconBlock {
    slot: Slot,
    root: Hash256,
    parent_root: Hash256,
}

fn row_to_root(row: &Row, index: usize) -> Result<Hash256, Error> {
    row.try_get::<_, String>(index)?
        .parse()
        .map_err(|_| Error::InvalidRoot)
}

fn row_to_slot(row: &Row, index: usize) -> Result<Slot, Error> {
    row.try_get::<_, i32>(index)
        .map_err(|_| Error::InvalidSlot)?
        .try_into()
        .map_err(|_| Error::InvalidSlot)
        .map(|slot: u64| slot.into())
}

fn encode_hash256(h: Hash256) -> String {
    format!("{:?}", h)
}

fn encode_epoch(e: Epoch) -> Result<i32, Error> {
    e.as_u64().try_into().map_err(|_| Error::InvalidSlot)
}

fn encode_slot(s: Slot) -> Result<i32, Error> {
    s.as_u64().try_into().map_err(|_| Error::InvalidSlot)
}
