use serde::{Deserialize, Serialize};

pub use crate::lighthouse::Health;
pub use crate::types::{GenericResponse, VersionData};
pub use types::*;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatorData {
    pub enabled: bool,
    pub voting_pubkey: PublicKeyBytes,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateValidatorData {
    pub validator_desc: String,
    pub deposit_gwei: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateHdValidatorPostData {
    pub mnemonic: Option<String>,
    pub key_derivation_path_offset: u64,
    pub validators: Vec<CreateValidatorData>,
}
