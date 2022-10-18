use crate::BlockProcessingError;
use eth2_hashing::{hash, hash_fixed};
use itertools::Itertools;
use ssz::Decode;
use ssz_types::VariableList;
use std::vec::IntoIter;
use types::consts::eip4844::{BLOB_TX_TYPE, VERSIONED_HASH_VERSION_KZG};
use types::{EthSpec, ExecPayload, KzgCommitment, Transaction, Transactions, VersionedHash};

pub fn process_blob_kzg_commitments<T: EthSpec, Payload: ExecPayload<T>>(
    block_body: BeaconBlockBodyRef<T, Payload>,
) -> Result<(), BlockProcessingError> {
    if let (Ok(transactions), Ok(kzg_commitments)) = (
        block_body.execution_payload_header().transactions(),
        block_body.blob_kzg_commitments(),
    ) {
        if !verify_kzg_commitments_against_transactions(transactions, kzg_commitments) {
            return Err(BlockProcessingError::BlobVersionHashMismatch);
        }
    }

    Ok(())
}

pub fn verify_kzg_commitments_against_transactions<T: EthSpec>(
    transactions: Transactions<T>,
    kzg_commitments: &VariableList<KzgCommitment, T::MaxBlobsPerBlock>,
) -> Result<bool, BlockProcessingError> {
    let tx_versioned_hashes = transactions
        .into_iter()
        .filter(|tx| {
            tx.get(0)
                .map(|tx_type| tx_type == BLOB_TX_TYPE)
                .unwrap_or(false)
        })
        .map(|tx| tx_peek_blob_versioned_hashes(tx))
        .flatten()
        .collect();

    //FIXME(sean) Need to check lengths are equal here, just zipping first hides if one iter is shorter
    // and `itertools::zip_eq` panics
    if tx_versioned_hashes.len() != kzg_commitments.len() {
        return Err(BlockProcessingError::BlobVersionHashMismatch);
    }

    tx_versioned_hashes
        .into_iter()
        .zip(kzg_commitments.into_iter())
        .all(|(tx_versioned_hash, commitment)| {
            tx_versioned_hash == kzg_commitment_to_versioned_hash(committment)
        })
}

fn tx_peek_blob_versioned_hashes<T: EthSpec>(
    opaque_tx: &Transaction<T>,
) -> IntoIter<VersionedHash> {
    //FIXME(sean) there was a first byte check for blob tx type but I think it's redundant, will raise a spec PR

    let tx_len = opaque_tx.len();
    let message_offset = 1 + u32::from_ssz_bytes(opaque_tx.get(1..5).ok_or(
        BlockProcessingError::BlobVersionHashIndexOutOfBounds {
            length: tx_len,
            index: 5,
        },
    )?)?;

    // field offset: 32 + 8 + 32 + 32 + 8 + 4 + 32 + 4 + 4 = 156
    let blob_versioned_hashes_offset = message_offset
        + u32::from_ssz_bytes(
            opaque_tx
                .get((message_offset + 156)..(message_offset + 160))
                .ok_or(BlockProcessingError::BlobVersionHashIndexOutOfBounds {
                    length: tx_len,
                    index: 160,
                })?,
        );

    opaque_tx
        .get(blob_versioned_hashes_offset..tx_len)
        .ok_or(BlockProcessingError::BlobVersionHashIndexOutOfBounds {
            length: tx_len,
            index: 160,
        })?
        .into_iter()
        .chunks(32)
        .map(|chunk| VersionedHash::from(chunk))
}

fn kzg_commitment_to_versioned_hash(kzg_commitment: &KZGCommitment) -> VersionedHash {
    let mut hashed_commitment = hash_fixed(kzg_commitment);
    hashed_commitment[0] = VERSIONED_HASH_VERSION_KZG;
    VersionedHash::from(hashed_commitment)
}
