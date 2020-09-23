use super::types::*;
use crate::Error;
use reqwest::{IntoUrl, Response};
use serde::{de::DeserializeOwned, Serialize};

pub use reqwest;
pub use reqwest::{StatusCode, Url};

/// A wrapper around `reqwest::Client` which provides convenience methods for interfacing with a
/// Lighthouse Beacon Node HTTP server (`http_api`).
#[derive(Clone)]
pub struct ValidatorClientHttpClient {
    client: reqwest::Client,
    server: Url,
}

impl ValidatorClientHttpClient {
    /// Returns `Err(())` if the URL is invalid.
    pub fn new(server: Url) -> Self {
        Self {
            client: reqwest::Client::new(),
            server,
        }
    }

    /// Returns `Err(())` if the URL is invalid.
    pub fn from_components(server: Url, client: reqwest::Client) -> Self {
        Self { client, server }
    }

    /// Perform a HTTP GET request.
    async fn get<T: DeserializeOwned, U: IntoUrl>(&self, url: U) -> Result<T, Error> {
        let response = self.client.get(url).send().await.map_err(Error::Reqwest)?;
        ok_or_error(response)
            .await?
            .json()
            .await
            .map_err(Error::Reqwest)
    }

    /// Perform a HTTP GET request, returning `None` on a 404 error.
    async fn get_opt<T: DeserializeOwned, U: IntoUrl>(&self, url: U) -> Result<Option<T>, Error> {
        let response = self.client.get(url).send().await.map_err(Error::Reqwest)?;
        match ok_or_error(response).await {
            Ok(resp) => resp.json().await.map(Option::Some).map_err(Error::Reqwest),
            Err(err) => {
                if err.status() == Some(StatusCode::NOT_FOUND) {
                    Ok(None)
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Perform a HTTP POST request.
    async fn post<T: Serialize, U: IntoUrl>(&self, url: U, body: &T) -> Result<(), Error> {
        let response = self
            .client
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(Error::Reqwest)?;
        ok_or_error(response).await?;
        Ok(())
    }

    /// `GET lighthouse/version`
    pub async fn get_lighthouse_version(&self) -> Result<GenericResponse<VersionData>, Error> {
        let mut path = self.server.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("version");

        self.get(path).await
    }

    /// `GET lighthouse/health`
    pub async fn get_lighthouse_health(&self) -> Result<GenericResponse<Health>, Error> {
        let mut path = self.server.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("health");

        self.get(path).await
    }

    /*
    /// `POST validator/aggregate_and_proofs`
    pub async fn post_validator_aggregate_and_proof<T: EthSpec>(
        &self,
        aggregate: &SignedAggregateAndProof<T>,
    ) -> Result<(), Error> {
        let mut path = self.eth_path()?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("validator")
            .push("aggregate_and_proofs");

        self.post(path, aggregate).await?;

        Ok(())
    }
    */
}

/// Returns `Ok(response)` if the response is a `200 OK` response. Otherwise, creates an
/// appropriate error message.
async fn ok_or_error(response: Response) -> Result<Response, Error> {
    let status = response.status();

    if status == StatusCode::OK {
        Ok(response)
    } else if let Ok(message) = response.json().await {
        Err(Error::ServerMessage(message))
    } else {
        Err(Error::StatusCode(status))
    }
}
