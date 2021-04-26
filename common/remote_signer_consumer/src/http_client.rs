use crate::{
    Error, RemoteSignerObject, RemoteSignerRequestBody, RemoteSignerResponseBodyError,
    RemoteSignerResponseBodyOK,
};
use reqwest::StatusCode;
pub use reqwest::Url;
use sensitive_url::SensitiveUrl;
use types::{Domain, Fork, Hash256};

/// A wrapper around `reqwest::Client` which provides convenience methods
/// to interface with a BLS Remote Signer.
pub struct RemoteSignerHttpConsumer {
    client: reqwest::Client,
    server: SensitiveUrl,
}

impl RemoteSignerHttpConsumer {
    pub fn from_components(server: SensitiveUrl, client: reqwest::Client) -> Self {
        Self { client, server }
    }

    /// `POST /sign/:public-key`
    ///
    /// # Arguments
    ///
    /// * `public_key`              - Goes within the url to identify the key we want to use as signer.
    /// * `bls_domain`              - BLS Signature domain. Supporting `BeaconProposer`, `BeaconAttester`,`Randao`.
    /// * `data`                    - A `BeaconBlock`, `AttestationData`, or `Epoch`.
    /// * `fork`                    - A `Fork` object containing previous and current versions.
    /// * `genesis_validators_root` - A `Hash256` for domain separation and chain versioning.
    ///
    /// It sends through the wire a serialized `RemoteSignerRequestBody`.
    pub async fn sign<R: RemoteSignerObject>(
        &self,
        public_key: &str,
        bls_domain: Domain,
        data: R,
        fork: Fork,
        genesis_validators_root: Hash256,
    ) -> Result<String, Error> {
        if public_key.is_empty() {
            return Err(Error::InvalidParameter(
                "Empty parameter public_key".to_string(),
            ));
        }

        let mut path = self.server.full.clone();
        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("sign")
            .push(public_key);

        let bls_domain = match bls_domain {
            Domain::BeaconProposer => data.validate_object(bls_domain),
            Domain::BeaconAttester => data.validate_object(bls_domain),
            Domain::Randao => data.validate_object(bls_domain),
            _ => Err(Error::InvalidParameter(format!(
                "Unsupported BLS Domain: {:?}",
                bls_domain
            ))),
        }?;

        let body = RemoteSignerRequestBody {
            bls_domain,
            data,
            fork,
            genesis_validators_root,
        };

        let response = self
            .client
            .post(path)
            .json(&body)
            .send()
            .await
            .map_err(Error::Reqwest)?;

        match response.status() {
            StatusCode::OK => match response.json::<RemoteSignerResponseBodyOK>().await {
                Ok(resp_json) => Ok(resp_json.signature),
                Err(e) => Err(Error::Reqwest(e)),
            },
            _ => match response.json::<RemoteSignerResponseBodyError>().await {
                Ok(resp_json) => Err(Error::ServerMessage(resp_json.error)),
                Err(e) => Err(Error::Reqwest(e)),
            },
        }
    }
}
