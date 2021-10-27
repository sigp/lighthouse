use account_utils::ZeroizeString;
use eth2_keystore::Keystore;
use serde::{Deserialize, Serialize};
use slashing_protection::interchange::Interchange;
use types::PublicKeyBytes;

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct AuthResponse {
    pub token_path: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct ListKeystoresResponse {
    pub keystores: Vec<SingleKeystoreResponse>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct SingleKeystoreResponse {
    pub validating_pubkey: PublicKeyBytes,
    pub derivation_path: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct ImportKeystoresRequest {
    pub keystores: Vec<Keystore>,
    pub keystores_password: ZeroizeString,
    pub slashing_protection: Option<Interchange>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ImportKeystoresResponse {
    pub statuses: Vec<Status<ImportKeystoreStatus>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Status<T> {
    pub status: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl<T> Status<T> {
    pub fn ok(status: T) -> Self {
        Self {
            status,
            message: None,
        }
    }

    pub fn error(status: T, message: String) -> Self {
        Self {
            status,
            message: Some(message),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImportKeystoreStatus {
    Imported,
    Duplicate,
    Error,
}

#[derive(Deserialize, Serialize)]
pub struct DeleteKeystoresRequest {
    pub pubkeys: Vec<PublicKeyBytes>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeleteKeystoresResponse {
    pub statuses: Vec<Status<DeleteKeystoreStatus>>,
    pub slashing_protection: Interchange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeleteKeystoreStatus {
    Deleted,
    NotFound,
    Error,
}
