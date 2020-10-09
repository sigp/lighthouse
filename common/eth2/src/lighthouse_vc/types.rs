use account_utils::ZeroizeString;
use eth2_keystore::Keystore;
use serde::{Deserialize, Serialize};

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
    #[serde(with = "serde_utils::quoted_u64")]
    pub deposit_gwei: u64,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateValidatorsMnemonicRequest {
    pub mnemonic: ZeroizeString,
    #[serde(with = "serde_utils::quoted_u32")]
    pub key_derivation_path_offset: u32,
    pub validators: Vec<ValidatorRequest>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreatedValidator {
    pub enabled: bool,
    pub description: String,
    pub voting_pubkey: PublicKeyBytes,
    pub eth1_deposit_tx_data: String,
    #[serde(with = "serde_utils::quoted_u64")]
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
}
