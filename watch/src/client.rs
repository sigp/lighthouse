use crate::database::WatchBeaconBlock;
use eth2::types::BlockId;
use reqwest::Client;
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
    pub async fn get_beacon_blocks(&self, block_id: BlockId) -> Result<WatchBeaconBlock, Error> {
        let url = self
            .server
            .join("v1/")?
            .join("beacon_blocks/")?
            .join(&block_id.to_string())?;

        self.client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }
}
