use crate::InterchangeError;
use serde_derive::{Deserialize, Serialize};
use std::cmp::max;
use std::collections::{HashMap, HashSet};
use std::io;
use types::{Epoch, Hash256, PublicKeyBytes, Slot};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterchangeMetadata {
    #[serde(with = "eth2_serde_utils::quoted_u64::require_quotes")]
    pub interchange_format_version: u64,
    pub genesis_validators_root: Hash256,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterchangeData {
    pub pubkey: PublicKeyBytes,
    pub signed_blocks: Vec<SignedBlock>,
    pub signed_attestations: Vec<SignedAttestation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedBlock {
    #[serde(with = "eth2_serde_utils::quoted_u64::require_quotes")]
    pub slot: Slot,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_root: Option<Hash256>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAttestation {
    #[serde(with = "eth2_serde_utils::quoted_u64::require_quotes")]
    pub source_epoch: Epoch,
    #[serde(with = "eth2_serde_utils::quoted_u64::require_quotes")]
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

    pub fn from_json_reader(mut reader: impl std::io::Read) -> Result<Self, io::Error> {
        // We read the entire file into memory first, as this is *a lot* faster than using
        // `serde_json::from_reader`. See https://github.com/serde-rs/json/issues/160
        let mut json_str = String::new();
        reader.read_to_string(&mut json_str)?;
        Ok(Interchange::from_json_str(&json_str)?)
    }

    pub fn write_to(&self, writer: impl std::io::Write) -> Result<(), serde_json::Error> {
        serde_json::to_writer(writer, self)
    }

    /// Do these two `Interchange`s contain the same data (ignoring ordering)?
    pub fn equiv(&self, other: &Self) -> bool {
        let self_set = self.data.iter().collect::<HashSet<_>>();
        let other_set = other.data.iter().collect::<HashSet<_>>();
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

    /// Minify an interchange by constructing a synthetic block & attestation for each validator.
    pub fn minify(&self) -> Result<Self, InterchangeError> {
        // Map from pubkey to optional max block and max attestation.
        let mut validator_data =
            HashMap::<PublicKeyBytes, (Option<SignedBlock>, Option<SignedAttestation>)>::new();

        for data in self.data.iter() {
            // Existing maximum attestation and maximum block.
            let (max_block, max_attestation) = validator_data
                .entry(data.pubkey)
                .or_insert_with(|| (None, None));

            // Find maximum source and target epochs.
            let max_source_epoch = data
                .signed_attestations
                .iter()
                .map(|attestation| attestation.source_epoch)
                .max();
            let max_target_epoch = data
                .signed_attestations
                .iter()
                .map(|attestation| attestation.target_epoch)
                .max();

            match (max_source_epoch, max_target_epoch) {
                (Some(source_epoch), Some(target_epoch)) => {
                    if let Some(prev_max) = max_attestation {
                        prev_max.source_epoch = max(prev_max.source_epoch, source_epoch);
                        prev_max.target_epoch = max(prev_max.target_epoch, target_epoch);
                    } else {
                        *max_attestation = Some(SignedAttestation {
                            source_epoch,
                            target_epoch,
                            signing_root: None,
                        });
                    }
                }
                (None, None) => {}
                _ => return Err(InterchangeError::MaxInconsistent),
            };

            // Find maximum block slot.
            let max_block_slot = data.signed_blocks.iter().map(|block| block.slot).max();

            if let Some(max_slot) = max_block_slot {
                if let Some(prev_max) = max_block {
                    prev_max.slot = max(prev_max.slot, max_slot);
                } else {
                    *max_block = Some(SignedBlock {
                        slot: max_slot,
                        signing_root: None,
                    });
                }
            }
        }

        let data = validator_data
            .into_iter()
            .map(|(pubkey, (maybe_block, maybe_att))| InterchangeData {
                pubkey,
                signed_blocks: maybe_block.into_iter().collect(),
                signed_attestations: maybe_att.into_iter().collect(),
            })
            .collect();

        Ok(Self {
            metadata: self.metadata.clone(),
            data,
        })
    }
}
