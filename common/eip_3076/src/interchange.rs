use serde::{Deserialize, Serialize};
use std::cmp::max;
use std::collections::{HashMap, HashSet};
use std::io;
use types::{Epoch, Hash256, PublicKeyBytes, Slot};

use crate::NotSafe;

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

#[derive(Debug)]
pub enum InterchangeError {
    UnsupportedVersion(u64),
    GenesisValidatorsMismatch {
        interchange_file: Hash256,
        client: Hash256,
    },
    MaxInconsistent,
    SummaryInconsistent,
    SQLError(String),
    SQLPoolError(r2d2::Error),
    SerdeJsonError(serde_json::Error),
    InvalidPubkey(String),
    NotSafe(NotSafe),
    AtomicBatchAborted(Vec<InterchangeImportOutcome>),
}

impl From<NotSafe> for InterchangeError {
    fn from(error: NotSafe) -> Self {
        InterchangeError::NotSafe(error)
    }
}

impl From<rusqlite::Error> for InterchangeError {
    fn from(error: rusqlite::Error) -> Self {
        Self::SQLError(error.to_string())
    }
}

impl From<r2d2::Error> for InterchangeError {
    fn from(error: r2d2::Error) -> Self {
        InterchangeError::SQLPoolError(error)
    }
}

impl From<serde_json::Error> for InterchangeError {
    fn from(error: serde_json::Error) -> Self {
        InterchangeError::SerdeJsonError(error)
    }
}

/// Check that `new` is `Some` and greater than or equal to prev.
///
/// If prev is `None` and `new` is `Some` then `true` is returned.
fn monotonic<T: PartialOrd>(new: Option<T>, prev: Option<T>) -> bool {
    new.is_some_and(|new_val| prev.is_none_or(|prev_val| new_val >= prev_val))
}

/// The result of importing a single entry from an interchange file.
#[derive(Debug)]
pub enum InterchangeImportOutcome {
    Success {
        pubkey: PublicKeyBytes,
        summary: ValidatorSummary,
    },
    Failure {
        pubkey: PublicKeyBytes,
        error: NotSafe,
    },
}

impl InterchangeImportOutcome {
    pub fn failed(&self) -> bool {
        matches!(self, InterchangeImportOutcome::Failure { .. })
    }
}

/// Minimum and maximum slots and epochs signed by a validator.
#[derive(Debug)]
pub struct ValidatorSummary {
    pub min_block_slot: Option<Slot>,
    pub max_block_slot: Option<Slot>,
    pub min_attestation_source: Option<Epoch>,
    pub min_attestation_target: Option<Epoch>,
    pub max_attestation_source: Option<Epoch>,
    pub max_attestation_target: Option<Epoch>,
}

impl ValidatorSummary {
    pub fn check_block_consistency(&self, prev: &Self, imported_blocks: bool) -> bool {
        if imported_blocks {
            // Max block slot should be monotonically increasing and non-null.
            // Minimum should match maximum due to pruning.
            monotonic(self.max_block_slot, prev.max_block_slot)
                && self.min_block_slot == self.max_block_slot
        } else {
            // Block slots should be unchanged.
            prev.min_block_slot == self.min_block_slot && prev.max_block_slot == self.max_block_slot
        }
    }

    pub fn check_attestation_consistency(&self, prev: &Self, imported_attestations: bool) -> bool {
        if imported_attestations {
            // Max source and target epochs should be monotically increasing and non-null.
            // Minimums should match maximums due to pruning.
            monotonic(self.max_attestation_source, prev.max_attestation_source)
                && monotonic(self.max_attestation_target, prev.max_attestation_target)
                && self.min_attestation_source == self.max_attestation_source
                && self.min_attestation_target == self.max_attestation_target
        } else {
            // Attestation epochs should be unchanged.
            self.min_attestation_source == prev.min_attestation_source
                && self.max_attestation_source == prev.max_attestation_source
                && self.min_attestation_target == prev.min_attestation_target
                && self.max_attestation_target == prev.max_attestation_target
        }
    }
}
