use serde::{Deserialize, Serialize};

pub use crate::lighthouse::Health;
pub use crate::types::{GenericResponse, VersionData};
pub use types::*;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatorData {
    pub enabled: bool,
    pub voting_pubkey: PublicKeyBytes,
}
