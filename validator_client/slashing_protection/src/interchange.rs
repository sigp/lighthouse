use serde_derive::{Deserialize, Serialize};
use std::collections::HashSet;
use std::iter::FromIterator;
use types::{Epoch, Hash256, PublicKey, Slot};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterchangeMetadata {
    #[serde(with = "serde_utils::quoted_u64::require_quotes")]
    pub interchange_format_version: u64,
    pub genesis_validators_root: Hash256,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterchangeData {
    pub pubkey: PublicKey,
    pub signed_blocks: Vec<SignedBlock>,
    pub signed_attestations: Vec<SignedAttestation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedBlock {
    #[serde(with = "serde_utils::quoted_u64::require_quotes")]
    pub slot: Slot,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_root: Option<Hash256>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAttestation {
    #[serde(with = "serde_utils::quoted_u64::require_quotes")]
    pub source_epoch: Epoch,
    #[serde(with = "serde_utils::quoted_u64::require_quotes")]
    pub target_epoch: Epoch,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_root: Option<Hash256>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Interchange {
    pub metadata: InterchangeMetadata,
    pub data: Vec<InterchangeData>,
}

impl Interchange {
    pub fn from_json_str(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn from_json_reader(reader: impl std::io::Read) -> Result<Self, serde_json::Error> {
        serde_json::from_reader(reader)
    }

    pub fn write_to(&self, writer: impl std::io::Write) -> Result<(), serde_json::Error> {
        serde_json::to_writer(writer, self)
    }

    /// Do these two `Interchange`s contain the same data (ignoring ordering)?
    pub fn equiv(&self, other: &Self) -> bool {
        let self_set = HashSet::<_>::from_iter(self.data.iter());
        let other_set = HashSet::<_>::from_iter(other.data.iter());
        self.metadata == other.metadata && self_set == other_set
    }

    /// The number of entries in `data`.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Is the `data` part of the interchange completely empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
