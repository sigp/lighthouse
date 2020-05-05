use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

/// Used for ensuring that serde only decodes valid checksum functions.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HexBytes(Vec<u8>);

impl HexBytes {
    pub fn empty() -> Self {
        Self(vec![])
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<Vec<u8>> for HexBytes {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}

impl Into<String> for HexBytes {
    fn into(self) -> String {
        hex::encode(self.0)
    }
}

impl TryFrom<String> for HexBytes {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        hex::decode(s)
            .map(Self)
            .map_err(|e| format!("Invalid hex: {}", e))
    }
}
