//! Gossip verification for inclusion lists.
//!
//! A `SignedInclusionList` is verified and wrapped as a `GossipVerifiedInclusionList`, which can
//! then be imported into the `InclusionListStore`.
//!
//! ```ignore
//!    SignedInclusionList
//!              |
//!              ▼
//!    GossipVerifiedInclusionList
//! ```
use crate::BeaconChainError;
use std::sync::Arc;
use strum::AsRefStr;
use types::{BeaconStateError, ChainSpec, Hash256, ProgressiveTransactions, Slot};

pub mod gossip_verified_inclusion_list;

#[cfg(test)]
mod tests;

/// EIP-2718 transaction type of blob transaction
const BLOB_TX_TYPE_ID: u8 = 0x03;

#[derive(Debug)]
pub enum InclusionListVerificationError {
    /// Two valid inclusion lists were already seen from this validator for this slot and
    /// dependent root.
    AlreadySeenTwice {
        validator_index: u64,
        slot: Slot,
        dependent_root: Hash256,
    },
    /// The inclusion list is from a slot that is later than the current slot (with respect to
    /// the gossip clock disparity).
    FutureSlot {
        message_slot: Slot,
        latest_permissible_slot: Slot,
    },
    /// The inclusion list is from a slot that is prior to the earliest permissible slot (with
    /// respect to the gossip clock disparity).
    PastSlot {
        message_slot: Slot,
        earliest_permissible_slot: Slot,
    },
    /// The inclusion list transactions have a total size of zero.
    EmptyTransactions,
    /// The inclusion list transactions are too large or contain an empty transaction.
    InvalidTransactions(InclusionListTransactionsError),
    /// The block with root `dependent_root` has not been seen.
    DependentRootUnknown { dependent_root: Hash256 },
    /// The block with root `dependent_root` is not before the start of the lookahead epoch.
    DependentRootTooRecent {
        dependent_root: Hash256,
        block_slot: Slot,
        dependent_slot: Slot,
    },
    /// The block with root `dependent_root` is not a possible dependent block for the given
    /// epoch.
    InvalidDependentRoot { dependent_root: Hash256 },
    /// The validator is not in the inclusion list committee for the slot.
    NotInCommittee { validator_index: u64, slot: Slot },
    /// The validator index is not known to the pubkey cache.
    UnknownValidatorIndex(u64),
    /// The signature is invalid.
    InvalidSignature,
    /// The slot clock cannot be read.
    UnableToReadSlot,
    /// Some Beacon Chain Error
    BeaconChainError(Arc<BeaconChainError>),
    /// Some Beacon State error
    BeaconStateError(BeaconStateError),
}

impl std::fmt::Display for InclusionListVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<BeaconChainError> for InclusionListVerificationError {
    fn from(e: BeaconChainError) -> Self {
        InclusionListVerificationError::BeaconChainError(Arc::new(e))
    }
}

impl From<BeaconStateError> for InclusionListVerificationError {
    fn from(e: BeaconStateError) -> Self {
        InclusionListVerificationError::BeaconStateError(e)
    }
}

#[derive(Debug, PartialEq, Eq, AsRefStr)]
pub enum InclusionListTransactionsError {
    /// A transaction in the inclusion list has zero length
    EmptyTransaction { index: usize },
    /// A transaction in the inclusion list is a blob transaction
    BlobTransaction { index: usize },
    /// The inclusion list exceeds the maximum allowed size
    ListExceedsSizeLimit { size: u64, max: u64 },
}

/// Verify the size bounds the spec places on inclusion list transactions.
pub fn verify_inclusion_list_transactions_bounds(
    transactions: &ProgressiveTransactions,
    spec: &ChainSpec,
) -> Result<(), InclusionListTransactionsError> {
    let max_size = spec.max_transactions_bytes_per_inclusion_list;
    let list_size = transactions.iter().map(|tx| tx.len() as u64).sum();
    if list_size > max_size {
        return Err(InclusionListTransactionsError::ListExceedsSizeLimit {
            size: list_size,
            max: max_size,
        });
    }

    if let Some(index) = transactions.iter().position(|tx| tx.is_empty()) {
        return Err(InclusionListTransactionsError::EmptyTransaction { index });
    }

    Ok(())
}

/// Verify the inclusion list contains no blob transactions
pub fn verify_no_blob_transactions(
    transactions: &ProgressiveTransactions,
) -> Result<(), InclusionListTransactionsError> {
    if let Some(index) = transactions
        .iter()
        .position(|tx| tx.first() == Some(&BLOB_TX_TYPE_ID))
    {
        return Err(InclusionListTransactionsError::BlobTransaction { index });
    }

    Ok(())
}
