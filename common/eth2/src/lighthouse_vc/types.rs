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
    validator_desc: String,
    deposit_gwei: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateHdValidatorPostData {
    mnemonic: Option<String>,
    offset: u64,
    validators: Vec<CreateValidatorData>,
}
