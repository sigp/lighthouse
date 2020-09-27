use super::types::*;
use crate::Error;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    IntoUrl, Response,
};
use serde::{de::DeserializeOwned, Serialize};

pub use reqwest;
pub use reqwest::{StatusCode, Url};

/// A wrapper around `reqwest::Client` which provides convenience methods for interfacing with a
/// Lighthouse Beacon Node HTTP server (`http_api`).
#[derive(Clone)]
pub struct ValidatorClientHttpClient {
    client: reqwest::Client,
    server: Url,
    // TODO: zeroize.
    secret: String,
}

impl ValidatorClientHttpClient {
    /// Returns `Err(())` if the URL is invalid.
    pub fn new(server: Url, secret: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            server,
            secret,
        }
    }

    /// Returns `Err(())` if the URL is invalid.
    pub fn from_components(server: Url, client: reqwest::Client, secret: String) -> Self {
        Self {
            client,
            server,
            secret,
        }
    }

    fn headers(&self) -> Result<HeaderMap, Error> {
        let header_value = HeaderValue::from_str(&format!("Basic {}", &self.secret))
            .map_err(Error::InvalidSecret)?;

        let mut headers = HeaderMap::new();
        headers.insert("Authorization", header_value);

        Ok(headers)
    }

    /// Perform a HTTP GET request.
    async fn get<T: DeserializeOwned, U: IntoUrl>(&self, url: U) -> Result<T, Error> {
        let response = self
            .client
            .get(url)
            .headers(self.headers()?)
            .send()
            .await
            .map_err(Error::Reqwest)?;
        ok_or_error(response)
            .await?
            .json()
            .await
            .map_err(Error::Reqwest)
    }

    /// Perform a HTTP GET request, returning `None` on a 404 error.
    async fn get_opt<T: DeserializeOwned, U: IntoUrl>(&self, url: U) -> Result<Option<T>, Error> {
        let response = self
            .client
            .get(url)
            .headers(self.headers()?)
            .send()
            .await
            .map_err(Error::Reqwest)?;
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
    async fn post<T: Serialize, U: IntoUrl, V: DeserializeOwned>(
        &self,
        url: U,
        body: &T,
    ) -> Result<V, Error> {
        let response = self
            .client
            .post(url)
            .headers(self.headers()?)
            .json(body)
            .send()
            .await
            .map_err(Error::Reqwest)?;
        ok_or_error(response)
            .await?
            .json()
            .await
            .map_err(Error::Reqwest)
    }

    /// Perform a HTTP PATCH request.
    async fn patch<T: Serialize, U: IntoUrl>(&self, url: U, body: &T) -> Result<(), Error> {
        let response = self
            .client
            .patch(url)
            .headers(self.headers()?)
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

    /// `GET lighthouse/validators`
    pub async fn get_lighthouse_validators(
        &self,
    ) -> Result<GenericResponse<Vec<ValidatorData>>, Error> {
        let mut path = self.server.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators");

        self.get(path).await
    }

    /// `GET lighthouse/validators/{validator_pubkey}`
    pub async fn get_lighthouse_validators_pubkey(
        &self,
        validator_pubkey: &PublicKeyBytes,
    ) -> Result<Option<GenericResponse<ValidatorData>>, Error> {
        let mut path = self.server.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators")
            .push(&validator_pubkey.to_string());

        self.get_opt(path).await
    }

    /// `POST lighthouse/validators/hd`
    pub async fn post_lighthouse_validators_hd(
        &self,
        request: &HdValidatorsPostRequest,
    ) -> Result<GenericResponse<CreateHdValidatorResponseData>, Error> {
        let mut path = self.server.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators")
            .push("hd");

        self.post(path, &request).await
    }

    /// `POST lighthouse/validators/keystore`
    pub async fn post_lighthouse_validators_keystore(
        &self,
        request: &KeystoreValidatorsPostRequest,
    ) -> Result<GenericResponse<ValidatorData>, Error> {
        let mut path = self.server.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators")
            .push("keystore");

        self.post(path, &request).await
    }

    /// `PATCH lighthouse/validators/{validator_pubkey}`
    pub async fn patch_lighthouse_validators(
        &self,
        voting_pubkey: &PublicKeyBytes,
        enabled: bool,
    ) -> Result<(), Error> {
        let mut path = self.server.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators")
            .push(&voting_pubkey.to_string());

        dbg!(&path);

        self.patch(path, &ValidatorPatchRequest { enabled }).await
    }
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
