use account_utils::ZeroizeString;
use eth2_keystore::Keystore;
use graffiti::GraffitiString;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub use crate::lighthouse::Health;
pub use crate::types::{GenericResponse, VersionData};
pub use types::*;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatorData {
    pub enabled: bool,
    pub description: String,
    pub voting_pubkey: PublicKeyBytes,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatorRequest {
    pub enable: bool,
    pub description: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graffiti: Option<GraffitiString>,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub deposit_gwei: u64,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateValidatorsMnemonicRequest {
    pub mnemonic: ZeroizeString,
    #[serde(with = "eth2_serde_utils::quoted_u32")]
    pub key_derivation_path_offset: u32,
    pub validators: Vec<ValidatorRequest>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreatedValidator {
    pub enabled: bool,
    pub description: String,
    pub voting_pubkey: PublicKeyBytes,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graffiti: Option<GraffitiString>,
    pub eth1_deposit_tx_data: String,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub deposit_gwei: u64,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PostValidatorsResponseData {
    pub mnemonic: ZeroizeString,
    pub validators: Vec<CreatedValidator>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatorPatchRequest {
    pub enabled: bool,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct KeystoreValidatorsPostRequest {
    pub password: ZeroizeString,
    pub enable: bool,
    pub keystore: Keystore,
    pub graffiti: Option<GraffitiString>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Web3SignerValidatorRequest {
    pub enable: bool,
    pub description: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graffiti: Option<GraffitiString>,
    pub voting_public_key: PublicKey,
    pub url: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_certificate_path: Option<PathBuf>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_timeout_ms: Option<u64>,
}
