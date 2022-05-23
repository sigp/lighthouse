use eth2::ok_or_error;
use eth2::types::builder_bid::SignedBuilderBid;
use eth2::types::{
    BlindedPayload, EthSpec, ExecPayload, ExecutionBlockHash, ExecutionPayload,
    ForkVersionedResponse, PublicKeyBytes, SignedBeaconBlock, SignedValidatorRegistrationData,
    Slot,
};
pub use eth2::Error;
use reqwest::{IntoUrl, Response};
use sensitive_url::SensitiveUrl;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::format;
use std::time::Duration;

#[derive(Clone)]
pub struct BuilderHttpClient {
    client: reqwest::Client,
    server: SensitiveUrl,
}

impl BuilderHttpClient {
    pub fn new(server: SensitiveUrl) -> Result<Self, Error> {
        Ok(Self {
            client: reqwest::Client::new(),
            server,
        })
    }

    async fn get<T: DeserializeOwned, U: IntoUrl>(&self, url: U) -> Result<T, Error> {
        self.get_response(url)
            .await?
            .json()
            .await
            .map_err(Error::Reqwest)
    }

    /// Perform a HTTP GET request, returning the `Response` for further processing.
    async fn get_response<U: IntoUrl>(&self, url: U) -> Result<Response, Error> {
        let response = self.client.get(url).send().await.map_err(Error::Reqwest)?;
        ok_or_error(response).await
    }

    /// Perform a HTTP POST request with a custom timeout.
    async fn post_with_timeout<T: Serialize, U: IntoUrl>(
        &self,
        url: U,
        body: &T,
        timeout: Duration,
    ) -> Result<(), Error> {
        self.post_generic(url, body, Some(timeout)).await?;
        Ok(())
    }

    /// Generic POST function supporting arbitrary responses and timeouts.
    async fn post_generic<T: Serialize, U: IntoUrl>(
        &self,
        url: U,
        body: &T,
        timeout: Option<Duration>,
    ) -> Result<Response, Error> {
        let mut builder = self.client.post(url);
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }
        let response = builder.json(body).send().await?;
        ok_or_error(response).await
    }

    async fn post_with_raw_response<T: Serialize, U: IntoUrl>(
        &self,
        url: U,
        body: &T,
    ) -> Result<Response, Error> {
        let response = self
            .client
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(Error::Reqwest)?;
        ok_or_error(response).await
    }

    /// `POST /eth/v1/builder/validators`
    pub async fn post_builder_validators(
        &self,
        validator: &SignedValidatorRegistrationData,
    ) -> Result<(), Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("builder")
            .push("validators");

        //TODO(sean): move config and shorten to 500 millis
        self.post_with_timeout(path, &validator, Duration::from_secs(1))
            .await
    }

    /// `POST /eth/v1/builder/blinded_blocks`
    pub async fn post_builder_blinded_blocks<E: EthSpec>(
        &self,
        blinded_block: &SignedBeaconBlock<E, BlindedPayload<E>>,
    ) -> Result<ForkVersionedResponse<ExecutionPayload<E>>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("builder")
            .push("blinded_blocks");

        Ok(self
            .post_with_raw_response(path, &blinded_block)
            .await?
            .json()
            .await?)
    }

    //TODO(sean) add timeouts
    /// `GET /eth/v1/builder/header`
    pub async fn get_builder_header<E: EthSpec, Payload: ExecPayload<E>>(
        &self,
        slot: Slot,
        parent_hash: ExecutionBlockHash,
        pubkey: &PublicKeyBytes,
    ) -> Result<ForkVersionedResponse<SignedBuilderBid<E, Payload>>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("builder")
            .push("header")
            .push(slot.to_string().as_str())
            .push(format!("{parent_hash:?}").as_str())
            .push(pubkey.as_hex_string().as_str());

        self.get(path).await
    }

    /// `GET /eth/v1/builder/status`
    pub async fn get_builder_status<E: EthSpec>(&self) -> Result<(), Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("builder")
            .push("status");

        self.get(path).await
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
