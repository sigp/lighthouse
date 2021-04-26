use super::{types::*, PK_LEN, SECRET_PREFIX};
use crate::Error;
use account_utils::ZeroizeString;
use bytes::Bytes;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    IntoUrl,
};
use ring::digest::{digest, SHA256};
use secp256k1::{Message, PublicKey, Signature};
use sensitive_url::SensitiveUrl;
use serde::{de::DeserializeOwned, Serialize};

pub use reqwest;
pub use reqwest::{Response, StatusCode, Url};

/// A wrapper around `reqwest::Client` which provides convenience methods for interfacing with a
/// Lighthouse Validator Client HTTP server (`validator_client/src/http_api`).
#[derive(Clone)]
pub struct ValidatorClientHttpClient {
    client: reqwest::Client,
    server: SensitiveUrl,
    secret: ZeroizeString,
    server_pubkey: PublicKey,
}

/// Parse an API token and return a secp256k1 public key.
pub fn parse_pubkey(secret: &str) -> Result<PublicKey, Error> {
    let secret = if !secret.starts_with(SECRET_PREFIX) {
        return Err(Error::InvalidSecret(format!(
            "secret does not start with {}",
            SECRET_PREFIX
        )));
    } else {
        &secret[SECRET_PREFIX.len()..]
    };

    serde_utils::hex::decode(&secret)
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
}

impl ValidatorClientHttpClient {
    pub fn new(server: SensitiveUrl, secret: String) -> Result<Self, Error> {
        Ok(Self {
            client: reqwest::Client::new(),
            server,
            server_pubkey: parse_pubkey(&secret)?,
            secret: secret.into(),
        })
    }

    pub fn from_components(
        server: SensitiveUrl,
        client: reqwest::Client,
        secret: String,
    ) -> Result<Self, Error> {
        Ok(Self {
            client,
            server,
            server_pubkey: parse_pubkey(&secret)?,
            secret: secret.into(),
        })
    }

    async fn signed_body(&self, response: Response) -> Result<Bytes, Error> {
        let sig = response
            .headers()
            .get("Signature")
            .ok_or(Error::MissingSignatureHeader)?
            .to_str()
            .map_err(|_| Error::InvalidSignatureHeader)?
            .to_string();

        let body = response.bytes().await.map_err(Error::Reqwest)?;

        let message =
            Message::parse_slice(digest(&SHA256, &body).as_ref()).expect("sha256 is 32 bytes");

        serde_utils::hex::decode(&sig)
            .ok()
            .and_then(|bytes| {
                let sig = Signature::parse_der(&bytes).ok()?;
                Some(secp256k1::verify(&message, &sig, &self.server_pubkey))
            })
            .filter(|is_valid| *is_valid)
            .ok_or(Error::InvalidSignatureHeader)?;

        Ok(body)
    }

    async fn signed_json<T: DeserializeOwned>(&self, response: Response) -> Result<T, Error> {
        let body = self.signed_body(response).await?;
        serde_json::from_slice(&body).map_err(Error::InvalidJson)
    }

    fn headers(&self) -> Result<HeaderMap, Error> {
        let header_value = HeaderValue::from_str(&format!("Basic {}", self.secret.as_str()))
            .map_err(|e| {
                Error::InvalidSecret(format!("secret is invalid as a header value: {}", e))
            })?;

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
        let response = ok_or_error(response).await?;
        self.signed_json(response).await
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
            Ok(resp) => self.signed_json(resp).await.map(Option::Some),
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
        let response = ok_or_error(response).await?;
        self.signed_json(response).await
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
        let response = ok_or_error(response).await?;
        self.signed_body(response).await?;
        Ok(())
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
    pub async fn get_lighthouse_spec(&self) -> Result<GenericResponse<YamlConfig>, Error> {
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

    /// `PATCH lighthouse/validators/{validator_pubkey}`
    pub async fn patch_lighthouse_validators(
        &self,
        voting_pubkey: &PublicKeyBytes,
        enabled: bool,
    ) -> Result<(), Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators")
            .push(&voting_pubkey.to_string());

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
