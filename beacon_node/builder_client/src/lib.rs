use eth2::types::{BlindedPayload, EthSpec, ExecutionBlockHash, ExecutionPayload, ExecutionPayloadHeader, ForkVersionedResponse, GenericResponse, Hash256, PublicKeyBytes, SignedBeaconBlock, SignedValidatorRegistrationData, Slot};
use eth2::{ok_or_error};
pub use eth2::Error;
use reqwest::{IntoUrl, Response};
use sensitive_url::SensitiveUrl;
use serde::de::DeserializeOwned;
use serde::Serialize;

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

    /// Perform a HTTP POST request.
    async fn post<T: Serialize, U: IntoUrl, V: DeserializeOwned>(
        &self,
        url: U,
        body: &T,
    ) -> Result<V, Error> {
        let response = self.post_with_raw_response(url, body).await?;
        Ok(response.json().await?)
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
    ) -> Result<GenericResponse<()>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("builder")
            .push("validators");

        self.post(path, &validator).await
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

        self.post(path, &blinded_block).await
    }

    //TODO(sean) add timeouts
    /// `GET /eth/v1/builder/header`
    pub async fn get_builder_header<E: EthSpec>(
        &self,
        slot: Slot,
        parent_hash: ExecutionBlockHash,
        pubkey: &PublicKeyBytes,
    ) -> Result<ForkVersionedResponse<ExecutionPayloadHeader<E>>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("builder")
            .push("header")
            .push(slot.to_string().as_str())
            .push(parent_hash.to_string().as_str())
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
