use kzg::{Error as KzgError, Kzg, BYTES_PER_BLOB};
use types::{Blob, EthSpec, KzgCommitment, KzgProof};

/// Converts a blob ssz List object to an array to be used with the kzg
/// crypto library.
fn ssz_blob_to_crypto_blob<T: EthSpec>(blob: Blob<T>) -> kzg::Blob {
    let blob_vec: Vec<u8> = blob.into();
    let mut arr = [0; BYTES_PER_BLOB];
    arr.copy_from_slice(&blob_vec);
    arr.into()
}

/// Validate a single blob-commitment-proof triplet from a `BlobSidecar`.
pub fn validate_blob<T: EthSpec>(
    kzg: &Kzg,
    blob: Blob<T>,
    kzg_commitment: KzgCommitment,
    kzg_proof: KzgProof,
) -> Result<bool, KzgError> {
    kzg.verify_blob_kzg_proof(
        ssz_blob_to_crypto_blob::<T>(blob),
        kzg_commitment,
        kzg_proof,
    )
}

/// Validate a batch of blob-commitment-proof triplets from multiple `BlobSidecars`.
pub fn validate_blobs<T: EthSpec>(
    kzg: &Kzg,
    expected_kzg_commitments: &[KzgCommitment],
    blobs: &[Blob<T>],
    kzg_proofs: &[KzgProof],
) -> Result<bool, KzgError> {
    let blobs = blobs
        .iter()
        .map(|blob| ssz_blob_to_crypto_blob::<T>(blob.clone())) // Avoid this clone
        .collect::<Vec<_>>();

    kzg.verify_blob_kzg_proof_batch(&blobs, expected_kzg_commitments, kzg_proofs)
}

/// Compute the kzg proof given an ssz blob and its kzg commitment.
pub fn compute_blob_kzg_proof<T: EthSpec>(
    kzg: &Kzg,
    blob: Blob<T>,
    kzg_commitment: KzgCommitment,
) -> Result<KzgProof, KzgError> {
    kzg.compute_blob_kzg_proof(ssz_blob_to_crypto_blob::<T>(blob), kzg_commitment)
}

/// Compute the kzg commitment for a given blob.
pub fn blob_to_kzg_commitment<T: EthSpec>(
    kzg: &Kzg,
    blob: Blob<T>,
) -> Result<KzgCommitment, KzgError> {
    kzg.blob_to_kzg_commitment(ssz_blob_to_crypto_blob::<T>(blob))
}
