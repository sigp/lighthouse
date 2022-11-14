pub mod database;
pub mod server;
pub mod updater;

mod config;

use crate::database::WatchSlot;

use eth2::SensitiveUrl;
use reqwest::{Client, Response, Url};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use types::Slot;

pub use config::Config;
pub use database::{
    get_blockprint_by_root, get_blockprint_by_slot, get_highest_blockprint, get_lowest_blockprint,
    get_unknown_blockprint, get_validators_clients_at_slot, insert_batch_blockprint,
    list_consensus_clients, WatchBlockprint,
};
pub use server::blockprint_routes;

const TIMEOUT: Duration = Duration::from_secs(50);

#[derive(Debug)]
pub enum Error {
    Reqwest(reqwest::Error),
    Url(url::ParseError),
    BlockprintNotSynced,
    Other(String),
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Reqwest(e)
    }
}

impl From<url::ParseError> for Error {
    fn from(e: url::ParseError) -> Self {
        Error::Url(e)
    }
}

pub struct WatchBlockprintClient {
    pub client: Client,
    pub server: SensitiveUrl,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BlockprintSyncingResponse {
    pub greatest_block_slot: Slot,
    pub synced: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BlockprintResponse {
    pub proposer_index: i32,
    pub slot: Slot,
    pub best_guess_single: String,
}

impl WatchBlockprintClient {
    async fn get(&self, url: Url) -> Result<Response, Error> {
        let mut builder = self.client.get(url).timeout(TIMEOUT);
        if let Some(username) = &self.username {
            builder = builder.basic_auth(username, self.password.as_ref());
        }
        let response = builder.send().await.map_err(Error::Reqwest)?;

        if !response.status().is_success() {
            return Err(Error::Other(response.text().await?));
        }

        Ok(response)
    }

    // Returns the `greatest_block_slot` as reported by the Blockprint server.
    // Will error if the Blockprint server is not synced.
    #[allow(dead_code)]
    pub async fn ensure_synced(&self) -> Result<Slot, Error> {
        let url = self.server.full.join("sync/")?.join("status")?;

        let response = self.get(url).await?;

        let result = response.json::<BlockprintSyncingResponse>().await?;
        if !result.synced {
            return Err(Error::BlockprintNotSynced);
        }

        Ok(result.greatest_block_slot)
    }

    // Pulls the latest blockprint for all validators.
    #[allow(dead_code)]
    pub async fn blockprint_all_validators(
        &self,
        highest_validator: i32,
    ) -> Result<HashMap<i32, String>, Error> {
        let url = self
            .server
            .full
            .join("validator/")?
            .join("blocks/")?
            .join("latest")?;

        let response = self.get(url).await?;

        let mut result = response.json::<Vec<BlockprintResponse>>().await?;
        result.retain(|print| print.proposer_index <= highest_validator);

        let mut map: HashMap<i32, String> = HashMap::with_capacity(result.len());
        for print in result {
            map.insert(print.proposer_index, print.best_guess_single);
        }

        Ok(map)
    }

    // Construct a request to the Blockprint server for a range of slots between `start_slot` and
    // `end_slot`.
    pub async fn get_blockprint(
        &self,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<Vec<WatchBlockprint>, Error> {
        let url = self
            .server
            .full
            .join("blocks/")?
            .join(&format!("{start_slot}/{end_slot}"))?;

        let response = self.get(url).await?;

        let result = response
            .json::<Vec<BlockprintResponse>>()
            .await?
            .iter()
            .map(|response| WatchBlockprint {
                slot: WatchSlot::from_slot(response.slot),
                best_guess: response.best_guess_single.clone(),
            })
            .collect();
        Ok(result)
    }
}
