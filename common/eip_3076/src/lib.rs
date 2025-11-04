use serde::{Deserialize, Serialize};
use std::cmp::max;
use std::collections::{HashMap, HashSet};
#[cfg(feature = "json")]
use std::io;
use types::{Epoch, Hash256, PublicKeyBytes, Slot};

#[derive(Debug)]
pub enum Error {
    MaxInconsistent,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
pub struct InterchangeMetadata {
    #[serde(with = "serde_utils::quoted_u64::require_quotes")]
    pub interchange_format_version: u64,
    pub genesis_validators_root: Hash256,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
pub struct InterchangeData {
    pub pubkey: PublicKeyBytes,
    pub signed_blocks: Vec<SignedBlock>,
    pub signed_attestations: Vec<SignedAttestation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
pub struct SignedBlock {
    #[serde(with = "serde_utils::quoted_u64::require_quotes")]
    pub slot: Slot,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_root: Option<Hash256>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
pub struct SignedAttestation {
    #[serde(with = "serde_utils::quoted_u64::require_quotes")]
    pub source_epoch: Epoch,
    #[serde(with = "serde_utils::quoted_u64::require_quotes")]
    pub target_epoch: Epoch,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_root: Option<Hash256>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
pub struct Interchange {
    pub metadata: InterchangeMetadata,
    pub data: Vec<InterchangeData>,
}

impl Interchange {
    #[cfg(feature = "json")]
    pub fn from_json_str(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    #[cfg(feature = "json")]
    pub fn from_json_reader(mut reader: impl std::io::Read) -> Result<Self, io::Error> {
        // We read the entire file into memory first, as this is *a lot* faster than using
        // `serde_json::from_reader`. See https://github.com/serde-rs/json/issues/160
        let mut json_str = String::new();
        reader.read_to_string(&mut json_str)?;
        Ok(Interchange::from_json_str(&json_str)?)
    }

    #[cfg(feature = "json")]
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
    pub fn minify(&self) -> Result<Self, Error> {
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
                _ => return Err(Error::MaxInconsistent),
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

#[cfg(feature = "json")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::tempdir;
    use types::FixedBytesExtended;

    fn get_interchange() -> Interchange {
        Interchange {
            metadata: InterchangeMetadata {
                interchange_format_version: 5,
                genesis_validators_root: Hash256::from_low_u64_be(555),
            },
            data: vec![
                InterchangeData {
                    pubkey: PublicKeyBytes::deserialize(&[1u8; 48]).unwrap(),
                    signed_blocks: vec![SignedBlock {
                        slot: Slot::new(100),
                        signing_root: Some(Hash256::from_low_u64_be(1)),
                    }],
                    signed_attestations: vec![SignedAttestation {
                        source_epoch: Epoch::new(0),
                        target_epoch: Epoch::new(5),
                        signing_root: Some(Hash256::from_low_u64_be(2)),
                    }],
                },
                InterchangeData {
                    pubkey: PublicKeyBytes::deserialize(&[2u8; 48]).unwrap(),
                    signed_blocks: vec![],
                    signed_attestations: vec![],
                },
            ],
        }
    }

    #[test]
    fn test_roundtrip() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("interchange.json");

        let interchange = get_interchange();

        let mut file = File::create(&file_path).unwrap();
        interchange.write_to(&mut file).unwrap();

        let file = File::open(&file_path).unwrap();
        let from_file = Interchange::from_json_reader(file).unwrap();

        assert_eq!(interchange, from_file);
    }

    #[test]
    fn test_empty_roundtrip() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("empty.json");

        let empty = Interchange {
            metadata: InterchangeMetadata {
                interchange_format_version: 5,
                genesis_validators_root: Hash256::zero(),
            },
            data: vec![],
        };

        let mut file = File::create(&file_path).unwrap();
        empty.write_to(&mut file).unwrap();

        let file = File::open(&file_path).unwrap();
        let from_file = Interchange::from_json_reader(file).unwrap();

        assert_eq!(empty, from_file);
    }

    #[test]
    fn test_minify_roundtrip() {
        let interchange = get_interchange();

        let minified = interchange.minify().unwrap();

        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("minified.json");

        let mut file = File::create(&file_path).unwrap();
        minified.write_to(&mut file).unwrap();

        let file = File::open(&file_path).unwrap();
        let from_file = Interchange::from_json_reader(file).unwrap();

        assert_eq!(minified, from_file);
    }
}
