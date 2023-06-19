use account_utils::ZeroizeString;
use eth2_keystore::Keystore;
use graffiti::GraffitiString;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub use crate::lighthouse::Health;
pub use crate::lighthouse_vc::std_types::*;
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
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_fee_recipient: Option<Address>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder_proposals: Option<bool>,
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
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graffiti: Option<GraffitiString>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_fee_recipient: Option<Address>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder_proposals: Option<bool>,
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
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder_proposals: Option<bool>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graffiti: Option<GraffitiString>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct KeystoreValidatorsPostRequest {
    pub password: ZeroizeString,
    pub enable: bool,
    pub keystore: Keystore,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graffiti: Option<GraffitiString>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_fee_recipient: Option<Address>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder_proposals: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Web3SignerValidatorRequest {
    pub enable: bool,
    pub description: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graffiti: Option<GraffitiString>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_fee_recipient: Option<Address>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builder_proposals: Option<bool>,
    pub voting_public_key: PublicKey,
    pub url: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_certificate_path: Option<PathBuf>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_identity_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_identity_password: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UpdateFeeRecipientRequest {
    pub ethaddress: Address,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UpdateGasLimitRequest {
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_limit: u64,
}

#[derive(Deserialize)]
pub struct VoluntaryExitQuery {
    pub epoch: Option<Epoch>,
}
