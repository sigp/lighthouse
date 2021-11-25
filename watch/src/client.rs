use crate::database::WatchBeaconBlock;
use eth2::types::BlockId;
use reqwest::Client;
use serde::de::DeserializeOwned;
use types::Slot;
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
            .join("beacon_blocks/")?
            .join(&block_id.to_string())?;

        self.get_opt(url).await
    }

    pub async fn get_lowest_canonical_slot(&self) -> Result<Option<Slot>, Error> {
        let url = self
            .server
            .join("v1/")?
            .join("canonical_slots/")?
            .join("lowest")?;

        self.get_opt(url).await
    }
}
