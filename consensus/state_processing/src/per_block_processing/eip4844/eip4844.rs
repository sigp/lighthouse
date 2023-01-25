use crate::{BlockProcessingError, ConsensusContext};
use eth2_hashing::hash_fixed;
use itertools::{EitherOrBoth, Itertools};
use safe_arith::SafeArith;
use ssz::Decode;
use types::consts::eip4844::{BLOB_TX_TYPE, VERSIONED_HASH_VERSION_KZG};
use types::{
    AbstractExecPayload, BeaconBlockBodyRef, EthSpec, ExecPayload, KzgCommitment, Transaction,
    Transactions, VersionedHash,
};

pub fn process_blob_kzg_commitments<T: EthSpec, Payload: AbstractExecPayload<T>>(
    block_body: BeaconBlockBodyRef<T, Payload>,
    ctxt: &mut ConsensusContext<T>,
) -> Result<(), BlockProcessingError> {
    // Return early if this check has already been run.
    if ctxt.kzg_commitments_consistent() {
        return Ok(());
    }
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
    kzg_commitments: &[KzgCommitment],
) -> Result<bool, BlockProcessingError> {
    let nested_iter = transactions
        .into_iter()
        .filter(|tx| {
            tx.first()
                .map(|tx_type| *tx_type == BLOB_TX_TYPE)
                .unwrap_or(false)
        })
        .map(|tx| tx_peek_blob_versioned_hashes::<T>(tx));

    itertools::process_results(nested_iter, |iter| {
        let zipped_iter = iter
            .flatten()
            // Need to use `itertools::zip_longest` here because just zipping hides if one iter is shorter
            // and `itertools::zip_eq` panics.
            .zip_longest(kzg_commitments.into_iter())
            .enumerate()
            .map(|(index, next)| match next {
                EitherOrBoth::Both(hash, commitment) => Ok((hash?, commitment)),
                // The number of versioned hashes from the blob transactions exceeds the number of
                // commitments in the block.
                EitherOrBoth::Left(_) => Err(BlockProcessingError::BlobNumCommitmentsMismatch {
                    commitments_processed_in_block: index,
                    commitments_processed_in_transactions: index.safe_add(1)?,
                }),
                // The number of commitments in the block exceeds the number of versioned hashes
                // in the blob transactions.
                EitherOrBoth::Right(_) => Err(BlockProcessingError::BlobNumCommitmentsMismatch {
                    commitments_processed_in_block: index.safe_add(1)?,
                    commitments_processed_in_transactions: index,
                }),
            });

        itertools::process_results(zipped_iter, |mut iter| {
            iter.all(|(tx_versioned_hash, commitment)| {
                tx_versioned_hash == kzg_commitment_to_versioned_hash(commitment)
            })
        })
    })?
}

/// Only transactions of type `BLOB_TX_TYPE` should be passed into this function.
fn tx_peek_blob_versioned_hashes<T: EthSpec>(
    opaque_tx: &Transaction<T::MaxBytesPerTransaction>,
) -> Result<
    impl IntoIterator<Item = Result<VersionedHash, BlockProcessingError>> + '_,
    BlockProcessingError,
> {
    let tx_len = opaque_tx.len();
    let message_offset = 1.safe_add(u32::from_ssz_bytes(opaque_tx.get(1..5).ok_or(
        BlockProcessingError::BlobVersionHashIndexOutOfBounds {
            length: tx_len,
            index: 5,
        },
    )?)?)?;

    let message_offset_usize = message_offset as usize;

    // field offset: 32 + 8 + 32 + 32 + 8 + 4 + 32 + 4 + 4 + 32 = 188
    let blob_versioned_hashes_offset = message_offset.safe_add(u32::from_ssz_bytes(
        opaque_tx
            .get(message_offset_usize.safe_add(188)?..message_offset_usize.safe_add(192)?)
            .ok_or(BlockProcessingError::BlobVersionHashIndexOutOfBounds {
                length: tx_len,
                index: message_offset_usize.safe_add(192)?,
            })?,
    )?)?;

    let num_hashes = tx_len
        .safe_sub(blob_versioned_hashes_offset as usize)?
        .safe_div(32)?;

    Ok((0..num_hashes).into_iter().map(move |i| {
        let next_version_hash_index =
            (blob_versioned_hashes_offset as usize).safe_add(i.safe_mul(32)?)?;
        let bytes = opaque_tx
            .get(next_version_hash_index..next_version_hash_index.safe_add(32)?)
            .ok_or(BlockProcessingError::BlobVersionHashIndexOutOfBounds {
                length: tx_len,
                index: (next_version_hash_index).safe_add(32)?,
            })?;
        Ok(VersionedHash::from_slice(bytes))
    }))
}

fn kzg_commitment_to_versioned_hash(kzg_commitment: &KzgCommitment) -> VersionedHash {
    let mut hashed_commitment = hash_fixed(&kzg_commitment.0);
    hashed_commitment[0] = VERSIONED_HASH_VERSION_KZG;
    VersionedHash::from(hashed_commitment)
}
