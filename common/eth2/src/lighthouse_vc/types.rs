use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub use crate::lighthouse::Health;
pub use crate::types::{GenericResponse, VersionData};
pub use types::*;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct ValidatorData {
    pub enabled: bool,
    pub voting_pubkey: PublicKeyBytes,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct HdValidator {
    pub enable: bool,
    pub validator_desc: String,
    pub deposit_gwei: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct HdValidatorsPostRequest {
    pub mnemonic: Option<String>,
    pub key_derivation_path_offset: u64,
    pub validators: Vec<HdValidator>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct CreateHdValidatorResponseData {
    pub mnemonic: Option<String>,
    pub validators: Vec<ValidatorData>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct ValidatorPatchRequest {
    pub enabled: bool,
}
