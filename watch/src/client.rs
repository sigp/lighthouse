use crate::block_packing::WatchBlockPacking;
use crate::block_rewards::WatchBlockRewards;
use crate::database::models::{
    WatchBeaconBlock, WatchCanonicalSlot, WatchProposerInfo, WatchValidator,
};
use crate::suboptimal_attestations::WatchAttestation;

use eth2::types::BlockId;
use reqwest::Client;
use serde::de::DeserializeOwned;
use types::Hash256;
use url::Url;

#[derive(Debug)]
pub enum Error {
    Reqwest(reqwest::Error),
    Url(url::ParseError),
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

pub struct WatchHttpClient {
    pub client: Client,
    pub server: Url,
}

impl WatchHttpClient {
    async fn get_opt<T: DeserializeOwned>(&self, url: Url) -> Result<Option<T>, Error> {
        let response = self.client.get(url).send().await?;

        if response.status() == 404 {
            Ok(None)
        } else {
            response
                .error_for_status()?
                .json()
                .await
                .map_err(Into::into)
        }
    }

    pub async fn get_beacon_blocks(
        &self,
        block_id: BlockId,
    ) -> Result<Option<WatchBeaconBlock>, Error> {
        let url = self
            .server
            .join("v1/")?
            .join("blocks/")?
            .join(&block_id.to_string())?;

        self.get_opt(url).await
    }

    pub async fn get_lowest_canonical_slot(&self) -> Result<Option<WatchCanonicalSlot>, Error> {
        let url = self.server.join("v1/")?.join("slots/")?.join("lowest")?;

        self.get_opt(url).await
    }

    pub async fn get_highest_canonical_slot(&self) -> Result<Option<WatchCanonicalSlot>, Error> {
        let url = self.server.join("v1/")?.join("slots/")?.join("highest")?;

        self.get_opt(url).await
    }

    pub async fn get_lowest_beacon_block(&self) -> Result<Option<WatchBeaconBlock>, Error> {
        let url = self.server.join("v1/")?.join("blocks/")?.join("lowest")?;

        self.get_opt(url).await
    }

    pub async fn get_highest_beacon_block(&self) -> Result<Option<WatchBeaconBlock>, Error> {
        let url = self.server.join("v1/")?.join("blocks/")?.join("highest")?;

        self.get_opt(url).await
    }

    pub async fn get_next_beacon_block(
        &self,
        parent: Hash256,
    ) -> Result<Option<WatchBeaconBlock>, Error> {
        let url = self
            .server
            .join("v1/")?
            .join("blocks/")?
            .join(&format!("{parent:?}/"))?
            .join("next")?;

        self.get_opt(url).await
    }

    pub async fn get_validator_by_index(
        &self,
        index: i32,
    ) -> Result<Option<WatchValidator>, Error> {
        let url = self
            .server
            .join("v1/")?
            .join("validators/")?
            .join(&format!("{index}"))?;

        self.get_opt(url).await
    }

    pub async fn get_proposer_info(
        &self,
        block_id: BlockId,
    ) -> Result<Option<WatchProposerInfo>, Error> {
        let url = self
            .server
            .join("v1/")?
            .join("blocks/")?
            .join(&format!("{block_id}/"))?
            .join("proposer")?;

        self.get_opt(url).await
    }

    pub async fn get_block_reward(
        &self,
        block_id: BlockId,
    ) -> Result<Option<WatchBlockRewards>, Error> {
        let url = self
            .server
            .join("v1/")?
            .join("blocks/")?
            .join(&format!("{block_id}/"))?
            .join("rewards")?;

        self.get_opt(url).await
    }

    pub async fn get_block_packing(
        &self,
        block_id: BlockId,
    ) -> Result<Option<WatchBlockPacking>, Error> {
        let url = self
            .server
            .join("v1/")?
            .join("blocks/")?
            .join(&format!("{block_id}/"))?
            .join("packing")?;

        self.get_opt(url).await
    }

    pub async fn get_all_validators(&self) -> Result<Option<Vec<WatchValidator>>, Error> {
        let url = self.server.join("v1/")?.join("validators/")?.join("all")?;

        self.get_opt(url).await
    }

    pub async fn get_attestations(
        &self,
        epoch: i32,
    ) -> Result<Option<Vec<WatchAttestation>>, Error> {
        let url = self
            .server
            .join("v1/")?
            .join("validators/")?
            .join("all/")?
            .join("attestation/")?
            .join(&format!("{epoch}"))?;

        self.get_opt(url).await
    }
}
