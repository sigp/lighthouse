use account_utils::ZeroizeString;
use eth2_keystore::Keystore;
use serde::{Deserialize, Serialize};
use slashing_protection::interchange::Interchange;
use types::{Address, PublicKeyBytes};

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct GetFeeRecipientResponse {
    pub pubkey: PublicKeyBytes,
    pub ethaddress: Address,
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct AuthResponse {
    pub token_path: String,
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ListKeystoresResponse {
    pub data: Vec<SingleKeystoreResponse>,
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct SingleKeystoreResponse {
    pub validating_pubkey: PublicKeyBytes,
    pub derivation_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readonly: Option<bool>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImportKeystoresRequest {
    pub keystores: Vec<KeystoreJsonStr>,
    pub passwords: Vec<ZeroizeString>,
    pub slashing_protection: Option<InterchangeJsonStr>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct KeystoreJsonStr(#[serde(with = "eth2_serde_utils::json_str")] pub Keystore);

impl std::ops::Deref for KeystoreJsonStr {
    type Target = Keystore;
    fn deref(&self) -> &Keystore {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct InterchangeJsonStr(#[serde(with = "eth2_serde_utils::json_str")] pub Interchange);

#[derive(Debug, Deserialize, Serialize)]
pub struct ImportKeystoresResponse {
    pub data: Vec<Status<ImportKeystoreStatus>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ImportKeystoreStatus {
    Imported,
    Duplicate,
    Error,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteKeystoresRequest {
    pub pubkeys: Vec<PublicKeyBytes>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeleteKeystoresResponse {
    pub data: Vec<Status<DeleteKeystoreStatus>>,
    #[serde(with = "eth2_serde_utils::json_str")]
    pub slashing_protection: Interchange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteKeystoreStatus {
    Deleted,
    NotActive,
    NotFound,
    Error,
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ListRemotekeysResponse {
    pub data: Vec<SingleListRemotekeysResponse>,
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct SingleListRemotekeysResponse {
    pub pubkey: PublicKeyBytes,
    pub url: String,
    pub readonly: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRemotekeysRequest {
    pub remote_keys: Vec<SingleImportRemotekeysRequest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct SingleImportRemotekeysRequest {
    pub pubkey: PublicKeyBytes,
    pub url: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ImportRemotekeyStatus {
    Imported,
    Duplicate,
    Error,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ImportRemotekeysResponse {
    pub data: Vec<Status<ImportRemotekeyStatus>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteRemotekeysRequest {
    pub pubkeys: Vec<PublicKeyBytes>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteRemotekeyStatus {
    Deleted,
    NotFound,
    Error,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeleteRemotekeysResponse {
    pub data: Vec<Status<DeleteRemotekeyStatus>>,
}
