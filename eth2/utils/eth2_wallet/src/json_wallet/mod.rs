use serde::{Deserialize, Serialize};
use serde_repr::*;
pub use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonWallet {
    name: String,
    nextaccount: u32,
    uuid: Uuid,
    version: Version,
}

/// Version for `JsonWallet`.
#[derive(Debug, Clone, PartialEq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum Version {
    V1 = 1,
}

impl Version {
    pub fn one() -> Self {
        Version::V1
    }
}
