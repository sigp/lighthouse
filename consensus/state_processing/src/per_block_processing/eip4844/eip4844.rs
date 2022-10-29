use crate::BlockProcessingError;
use eth2_hashing::{hash, hash_fixed};
use itertools::{EitherOrBoth, Itertools};
use ssz::Decode;
use ssz_types::VariableList;
use std::slice::Iter;
use std::vec::IntoIter;
use types::consts::eip4844::{BLOB_TX_TYPE, VERSIONED_HASH_VERSION_KZG};
use types::{
    AbstractExecPayload, BeaconBlockBodyRef, EthSpec, ExecPayload, FullPayload, FullPayloadRef,
    KzgCommitment, Transaction, Transactions, VersionedHash,
};

pub fn process_blob_kzg_commitments<T: EthSpec, Payload: AbstractExecPayload<T>>(
    block_body: BeaconBlockBodyRef<T, Payload>,
) -> Result<(), BlockProcessingError> {
    if let (Ok(payload), Ok(kzg_commitments)) = (
        block_body.execution_payload(),
        block_body.blob_kzg_commitments(),
    ) {
        if let Some(transactions) = payload.transactions() {
            if !verify_kzg_commitments_against_transactions::<T>(transactions, kzg_commitments)? {
                return Err(BlockProcessingError::BlobVersionHashMismatch);
            }
        }
    }

    Ok(())
}

pub fn verify_kzg_commitments_against_transactions<T: EthSpec>(
    transactions: &Transactions<T>,
    kzg_commitments: &VariableList<KzgCommitment, T::MaxBlobsPerBlock>,
) -> Result<bool, BlockProcessingError> {
    let nested_iter = transactions
        .into_iter()
        .filter(|tx| {
            tx.get(0)
                .map(|tx_type| *tx_type == BLOB_TX_TYPE)
                .unwrap_or(false)
        })
        .map(|tx| tx_peek_blob_versioned_hashes::<T>(tx));

    itertools::process_results(nested_iter, |mut iter| {
        let zipped_iter = iter
            .flatten()
            // Need to use `itertools::zip_longest` here because just zipping hides if one iter is shorter
            // and `itertools::zip_eq` panics.
            .zip_longest(kzg_commitments.into_iter())
            .map(|next| match next {
                EitherOrBoth::Both(hash, commitmnet) => Ok((hash?, commitmnet)),
                _ => Err(BlockProcessingError::BlobVersionHashMismatch),
            });

        itertools::process_results(zipped_iter, |mut iter| {
            iter.all(|(tx_versioned_hash, commitment)| {
                tx_versioned_hash == kzg_commitment_to_versioned_hash(commitment)
            })
        })
    })?
}

fn tx_peek_blob_versioned_hashes<T: EthSpec>(
    opaque_tx: &Transaction<T::MaxBytesPerTransaction>,
) -> Result<
    impl IntoIterator<Item = Result<VersionedHash, BlockProcessingError>> + '_,
    BlockProcessingError,
> {
    let tx_len = opaque_tx.len();
    let message_offset = 1 + u32::from_ssz_bytes(opaque_tx.get(1..5).ok_or(
        BlockProcessingError::BlobVersionHashIndexOutOfBounds {
            length: tx_len,
            index: 5,
        },
    )?)?;

    let message_offset_usize = message_offset as usize;

    // field offset: 32 + 8 + 32 + 32 + 8 + 4 + 32 + 4 + 4 = 156
    let blob_versioned_hashes_offset = message_offset
        + u32::from_ssz_bytes(
            opaque_tx
                .get((message_offset_usize + 156)..(message_offset_usize + 160))
                .ok_or(BlockProcessingError::BlobVersionHashIndexOutOfBounds {
                    length: tx_len,
                    index: 160,
                })?,
        )?;

    let num_hashes = (tx_len - blob_versioned_hashes_offset as usize) / 32;

    Ok((0..num_hashes).into_iter().map(move |i| {
        let bytes = opaque_tx.get(i..i + 32).ok_or(
            BlockProcessingError::BlobVersionHashIndexOutOfBounds {
                length: tx_len,
                index: i + 32,
            },
        )?;
        Ok(VersionedHash::from_slice(bytes))
    }))
}

fn kzg_commitment_to_versioned_hash(kzg_commitment: &KzgCommitment) -> VersionedHash {
    let mut hashed_commitment = hash_fixed(&kzg_commitment.0);
    hashed_commitment[0] = VERSIONED_HASH_VERSION_KZG;
    VersionedHash::from(hashed_commitment)
}
