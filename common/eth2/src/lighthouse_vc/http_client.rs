use super::{types::*, PK_LEN, SECRET_PREFIX};
use crate::Error;
use libsecp256k1::PublicKey;
use reqwest::IntoUrl;
use sensitive_url::SensitiveUrl;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::{self, Display};

pub use reqwest;
pub use reqwest::{Response, StatusCode, Url};
use types::graffiti::GraffitiString;

/// A wrapper around `reqwest::Client` which provides convenience methods for interfacing with a
/// Lighthouse Validator Client HTTP server (`validator_client/src/http_api`).
#[derive(Clone)]
pub struct ValidatorClientHttpClient {
    client: reqwest::Client,
    server: SensitiveUrl,
    authorization_header: AuthorizationHeader,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuthorizationHeader {
    /// Do not send any Authorization header.
    Omit,
    /// Send a `Basic` Authorization header (legacy).
    Basic,
    /// Send a `Bearer` Authorization header.
    Bearer,
}

impl Display for AuthorizationHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // The `Omit` variant should never be `Display`ed, but would result in a harmless rejection.
        write!(f, "{:?}", self)
    }
}

/// Parse an API token and return a secp256k1 public key.
///
/// If the token does not start with the Lighthouse token prefix then `Ok(None)` will be returned.
/// An error will be returned if the token looks like a Lighthouse token but doesn't correspond to a
/// valid public key.
pub fn parse_pubkey(secret: &str) -> Result<Option<PublicKey>, Error> {
    let secret = if !secret.starts_with(SECRET_PREFIX) {
        return Ok(None);
    } else {
        &secret[SECRET_PREFIX.len()..]
    };

    serde_utils::hex::decode(secret)
        .map_err(|e| Error::InvalidSecret(format!("invalid hex: {:?}", e)))
        .and_then(|bytes| {
            if bytes.len() != PK_LEN {
                return Err(Error::InvalidSecret(format!(
                    "expected {} bytes not {}",
                    PK_LEN,
                    bytes.len()
                )));
            }

            let mut arr = [0; PK_LEN];
            arr.copy_from_slice(&bytes);
            PublicKey::parse_compressed(&arr)
                .map_err(|e| Error::InvalidSecret(format!("invalid secp256k1 pubkey: {:?}", e)))
        })
        .map(Some)
}

impl ValidatorClientHttpClient {
    /// Create a new client.
    pub fn new(server: SensitiveUrl) -> Result<Self, Error> {
        Ok(Self {
            client: reqwest::Client::new(),
            server,
            authorization_header: AuthorizationHeader::Bearer,
        })
    }

    /// Create a client without an API token.
    ///
    /// A token can be fetched by using `self.get_auth`, and then reading the token from disk.
    pub fn new_unauthenticated(server: SensitiveUrl) -> Result<Self, Error> {
        Ok(Self {
            client: reqwest::Client::new(),
            server,
            authorization_header: AuthorizationHeader::Omit,
        })
    }

    pub fn from_components(server: SensitiveUrl, client: reqwest::Client) -> Result<Self, Error> {
        Ok(Self {
            client,
            server,
            authorization_header: AuthorizationHeader::Bearer,
        })
    }

    /// Set to `false` to disable sending the `Authorization` header on requests.
    ///
    /// Failing to send the `Authorization` header will cause the VC to reject requests with a 403.
    /// This function is intended only for testing purposes.
    pub fn send_authorization_header(&mut self, should_send: bool) {
        if should_send {
            self.authorization_header = AuthorizationHeader::Bearer;
        } else {
            self.authorization_header = AuthorizationHeader::Omit;
        }
    }

    /// Perform a HTTP GET request, returning the `Response` for further processing.
    async fn get_response<U: IntoUrl>(&self, url: U) -> Result<Response, Error> {
        let response = self.client.get(url).send().await.map_err(Error::from)?;
        ok_or_error(response).await
    }

    /// Perform a HTTP DELETE request, returning the `Response` for further processing.
    async fn delete_response<U: IntoUrl>(&self, url: U) -> Result<Response, Error> {
        let response = self.client.delete(url).send().await.map_err(Error::from)?;
        ok_or_error(response).await
    }

    async fn get<T: DeserializeOwned, U: IntoUrl>(&self, url: U) -> Result<T, Error> {
        let response = self.get_response(url).await?;
        Ok(response.json().await?)
    }

    async fn delete<U: IntoUrl>(&self, url: U) -> Result<(), Error> {
        let response = self.delete_response(url).await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(Error::StatusCode(response.status()))
        }
    }

    /// Perform a HTTP GET request, returning `None` on a 404 error.
    async fn get_opt<T: DeserializeOwned, U: IntoUrl>(&self, url: U) -> Result<Option<T>, Error> {
        match self.get_response(url).await {
            Ok(resp) => Ok(resp.json().await.map(Option::Some)?),
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
            .map_err(Error::from)?;
        ok_or_error(response).await
    }

    async fn post<T: Serialize, U: IntoUrl, V: DeserializeOwned>(
        &self,
        url: U,
        body: &T,
    ) -> Result<V, Error> {
        let response = self.post_with_raw_response(url, body).await?;
        Ok(response.json().await?)
    }

    /// Perform a HTTP PATCH request.
    async fn patch<T: Serialize, U: IntoUrl>(&self, url: U, body: &T) -> Result<(), Error> {
        let response = self
            .client
            .patch(url)
            .json(body)
            .send()
            .await
            .map_err(Error::from)?;
        ok_or_error(response).await?;
        Ok(())
    }

    /// Perform a HTTP DELETE request.
    async fn delete_with_raw_response<T: Serialize, U: IntoUrl>(
        &self,
        url: U,
        body: &T,
    ) -> Result<Response, Error> {
        let response = self
            .client
            .delete(url)
            .json(body)
            .send()
            .await
            .map_err(Error::from)?;
        ok_or_error(response).await
    }

    /// Perform a HTTP DELETE request.
    async fn delete_with_unsigned_response<T: Serialize, U: IntoUrl, V: DeserializeOwned>(
        &self,
        url: U,
        body: &T,
    ) -> Result<V, Error> {
        let response = self.delete_with_raw_response(url, body).await?;
        Ok(response.json().await?)
    }

    /// `GET lighthouse/version`
    pub async fn get_lighthouse_version(&self) -> Result<GenericResponse<VersionData>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("version");

        self.get(path).await
    }

    /// `GET lighthouse/health`
    pub async fn get_lighthouse_health(&self) -> Result<GenericResponse<Health>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("health");

        self.get(path).await
    }

    /// `GET lighthouse/spec`
    pub async fn get_lighthouse_spec<T: Serialize + DeserializeOwned>(
        &self,
    ) -> Result<GenericResponse<T>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("spec");

        self.get(path).await
    }

    /// `GET lighthouse/validators`
    pub async fn get_lighthouse_validators(
        &self,
    ) -> Result<GenericResponse<Vec<ValidatorData>>, Error> {
        let mut path = self.server.full.clone();

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
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators")
            .push(&validator_pubkey.to_string());

        self.get_opt(path).await
    }

    /// `POST lighthouse/validators`
    pub async fn post_lighthouse_validators(
        &self,
        validators: Vec<ValidatorRequest>,
    ) -> Result<GenericResponse<PostValidatorsResponseData>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators");

        self.post(path, &validators).await
    }

    /// `POST lighthouse/validators/mnemonic`
    pub async fn post_lighthouse_validators_mnemonic(
        &self,
        request: &CreateValidatorsMnemonicRequest,
    ) -> Result<GenericResponse<Vec<CreatedValidator>>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators")
            .push("mnemonic");

        self.post(path, &request).await
    }

    /// `POST lighthouse/validators/keystore`
    pub async fn post_lighthouse_validators_keystore(
        &self,
        request: &KeystoreValidatorsPostRequest,
    ) -> Result<GenericResponse<ValidatorData>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators")
            .push("keystore");

        self.post(path, &request).await
    }

    /// `POST lighthouse/validators/web3signer`
    pub async fn post_lighthouse_validators_web3signer(
        &self,
        request: &[Web3SignerValidatorRequest],
    ) -> Result<(), Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators")
            .push("web3signer");

        self.post(path, &request).await
    }

    /// `PATCH lighthouse/validators/{validator_pubkey}`
    #[allow(clippy::too_many_arguments)]
    pub async fn patch_lighthouse_validators(
        &self,
        voting_pubkey: &PublicKeyBytes,
        enabled: Option<bool>,
        gas_limit: Option<u64>,
        builder_proposals: Option<bool>,
        builder_boost_factor: Option<u64>,
        prefer_builder_proposals: Option<bool>,
        graffiti: Option<GraffitiString>,
    ) -> Result<(), Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators")
            .push(&voting_pubkey.to_string());

        self.patch(
            path,
            &ValidatorPatchRequest {
                enabled,
                gas_limit,
                builder_proposals,
                builder_boost_factor,
                prefer_builder_proposals,
                graffiti,
            },
        )
        .await
    }

    /// `DELETE eth/v1/keystores`
    pub async fn delete_lighthouse_keystores(
        &self,
        req: &DeleteKeystoresRequest,
    ) -> Result<ExportKeystoresResponse, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("keystores");

        self.delete_with_unsigned_response(path, req).await
    }

    fn make_keystores_url(&self) -> Result<Url, Error> {
        let mut url = self.server.full.clone();
        url.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("keystores");
        Ok(url)
    }

    fn make_remotekeys_url(&self) -> Result<Url, Error> {
        let mut url = self.server.full.clone();
        url.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("remotekeys");
        Ok(url)
    }

    fn make_fee_recipient_url(&self, pubkey: &PublicKeyBytes) -> Result<Url, Error> {
        let mut url = self.server.full.clone();
        url.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("validator")
            .push(&pubkey.to_string())
            .push("feerecipient");
        Ok(url)
    }

    fn make_graffiti_url(&self, pubkey: &PublicKeyBytes) -> Result<Url, Error> {
        let mut url = self.server.full.clone();
        url.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("validator")
            .push(&pubkey.to_string())
            .push("graffiti");
        Ok(url)
    }

    fn make_gas_limit_url(&self, pubkey: &PublicKeyBytes) -> Result<Url, Error> {
        let mut url = self.server.full.clone();
        url.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("validator")
            .push(&pubkey.to_string())
            .push("gas_limit");
        Ok(url)
    }

    /// `GET eth/v1/keystores`
    pub async fn get_keystores(&self) -> Result<ListKeystoresResponse, Error> {
        let url = self.make_keystores_url()?;
        self.get(url).await
    }

    /// `POST eth/v1/keystores`
    pub async fn post_keystores(
        &self,
        req: &ImportKeystoresRequest,
    ) -> Result<ImportKeystoresResponse, Error> {
        let url = self.make_keystores_url()?;
        self.post(url, req).await
    }

    /// `DELETE eth/v1/keystores`
    pub async fn delete_keystores(
        &self,
        req: &DeleteKeystoresRequest,
    ) -> Result<DeleteKeystoresResponse, Error> {
        let url = self.make_keystores_url()?;
        self.delete_with_unsigned_response(url, req).await
    }

    /// `GET eth/v1/remotekeys`
    pub async fn get_remotekeys(&self) -> Result<ListRemotekeysResponse, Error> {
        let url = self.make_remotekeys_url()?;
        self.get(url).await
    }

    /// `POST eth/v1/remotekeys`
    pub async fn post_remotekeys(
        &self,
        req: &ImportRemotekeysRequest,
    ) -> Result<ImportRemotekeysResponse, Error> {
        let url = self.make_remotekeys_url()?;
        self.post(url, req).await
    }

    /// `DELETE eth/v1/remotekeys`
    pub async fn delete_remotekeys(
        &self,
        req: &DeleteRemotekeysRequest,
    ) -> Result<DeleteRemotekeysResponse, Error> {
        let url = self.make_remotekeys_url()?;
        self.delete_with_unsigned_response(url, req).await
    }

    /// `GET /eth/v1/validator/{pubkey}/feerecipient`
    pub async fn get_fee_recipient(
        &self,
        pubkey: &PublicKeyBytes,
    ) -> Result<GetFeeRecipientResponse, Error> {
        let url = self.make_fee_recipient_url(pubkey)?;
        self.get(url)
            .await
            .map(|generic: GenericResponse<GetFeeRecipientResponse>| generic.data)
    }

    /// `POST /eth/v1/validator/{pubkey}/feerecipient`
    pub async fn post_fee_recipient(
        &self,
        pubkey: &PublicKeyBytes,
        req: &UpdateFeeRecipientRequest,
    ) -> Result<Response, Error> {
        let url = self.make_fee_recipient_url(pubkey)?;
        self.post_with_raw_response(url, req).await
    }

    /// `DELETE /eth/v1/validator/{pubkey}/feerecipient`
    pub async fn delete_fee_recipient(&self, pubkey: &PublicKeyBytes) -> Result<Response, Error> {
        let url = self.make_fee_recipient_url(pubkey)?;
        self.delete_with_raw_response(url, &()).await
    }

    /// `GET /eth/v1/validator/{pubkey}/gas_limit`
    pub async fn get_gas_limit(
        &self,
        pubkey: &PublicKeyBytes,
    ) -> Result<GetGasLimitResponse, Error> {
        let url = self.make_gas_limit_url(pubkey)?;
        self.get(url)
            .await
            .map(|generic: GenericResponse<GetGasLimitResponse>| generic.data)
    }

    /// `POST /eth/v1/validator/{pubkey}/gas_limit`
    pub async fn post_gas_limit(
        &self,
        pubkey: &PublicKeyBytes,
        req: &UpdateGasLimitRequest,
    ) -> Result<Response, Error> {
        let url = self.make_gas_limit_url(pubkey)?;
        self.post_with_raw_response(url, req).await
    }

    /// `DELETE /eth/v1/validator/{pubkey}/gas_limit`
    pub async fn delete_gas_limit(&self, pubkey: &PublicKeyBytes) -> Result<Response, Error> {
        let url = self.make_gas_limit_url(pubkey)?;
        self.delete_with_raw_response(url, &()).await
    }

    /// `POST /eth/v1/validator/{pubkey}/voluntary_exit`
    pub async fn post_validator_voluntary_exit(
        &self,
        pubkey: &PublicKeyBytes,
        epoch: Option<Epoch>,
    ) -> Result<GenericResponse<SignedVoluntaryExit>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("validator")
            .push(&pubkey.to_string())
            .push("voluntary_exit");

        if let Some(epoch) = epoch {
            path.query_pairs_mut()
                .append_pair("epoch", &epoch.to_string());
        }

        self.post(path, &()).await
    }

    /// `GET /eth/v1/validator/{pubkey}/graffiti`
    pub async fn get_graffiti(
        &self,
        pubkey: &PublicKeyBytes,
    ) -> Result<GetGraffitiResponse, Error> {
        let url = self.make_graffiti_url(pubkey)?;
        self.get(url)
            .await
            .map(|generic: GenericResponse<GetGraffitiResponse>| generic.data)
    }

    /// `POST /eth/v1/validator/{pubkey}/graffiti`
    pub async fn set_graffiti(
        &self,
        pubkey: &PublicKeyBytes,
        graffiti: GraffitiString,
    ) -> Result<(), Error> {
        let url = self.make_graffiti_url(pubkey)?;
        let set_graffiti_request = SetGraffitiRequest { graffiti };
        self.post(url, &set_graffiti_request).await
    }

    /// `DELETE /eth/v1/validator/{pubkey}/graffiti`
    pub async fn delete_graffiti(&self, pubkey: &PublicKeyBytes) -> Result<(), Error> {
        let url = self.make_graffiti_url(pubkey)?;
        self.delete(url).await
    }
}

/// Returns `Ok(response)` if the response is a `200 OK` response or a
/// `202 Accepted` response. Otherwise, creates an appropriate error message.
async fn ok_or_error(response: Response) -> Result<Response, Error> {
    let status = response.status();

    if status == StatusCode::OK
        || status == StatusCode::ACCEPTED
        || status == StatusCode::NO_CONTENT
    {
        Ok(response)
    } else if let Ok(message) = response.json().await {
        Err(Error::ServerMessage(message))
    } else {
        Err(Error::StatusCode(status))
    }
}
