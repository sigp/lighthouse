use crate::{config::Config, Error};
use log::{error, info};
use std::convert::TryInto;
use std::time::Duration;
use tokio::{runtime, task::JoinHandle};
use tokio_postgres::{config::Config as PostgresConfig, Client, NoTls};
use types::{Hash256, Slot};

pub use tokio_postgres::Transaction;

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
                id integer PRIMARY KEY,
                parent integer,
                root char(66) UNIQUE,
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
                beacon_block integer REFERENCES beacon_blocks(id)
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

    pub async fn delete_canonical_roots_above<'a>(
        tx: &'a Transaction<'a>,
        slot: Slot,
    ) -> Result<(), Error> {
        let slot: i32 = slot.as_u64().try_into().map_err(|_| Error::InvalidSlot)?;

        tx.execute(
            "DELETE FROM canonical_slots
                WHERE slot > $1",
            &[&slot],
        )
        .await?;

        Ok(())
    }

    pub async fn insert_canonical_slot<'a>(
        tx: &'a Transaction<'a>,
        slot: Slot,
        root: Hash256,
    ) -> Result<(), Error> {
        let slot: i32 = slot.as_u64().try_into().map_err(|_| Error::InvalidSlot)?;
        let root: String = format!("{:?}", root);

        tx.execute(
            "INSERT INTO canonical_slots (slot, root)
            VALUES ($1, $2)",
            &[&slot, &root],
        )
        .await
        .map_err(Into::into)
        .map(|_| ())
    }

    pub async fn get_root_at_canonical_slot<'a>(
        tx: &'a Transaction<'a>,
        slot: Slot,
    ) -> Result<Option<Hash256>, Error> {
        let slot: i32 = slot.as_u64().try_into().map_err(|_| Error::InvalidSlot)?;

        let row_opt = tx
            .query_opt(
                "SELECT root
                FROM canonical_slots
                WHERE slot = $1;",
                &[&slot],
            )
            .await?;

        if let Some(row) = row_opt {
            let root: Hash256 = row
                .try_get::<_, String>(0)?
                .parse()
                .map_err(|_| Error::InvalidRoot)?;

            Ok(Some(root))
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
}
