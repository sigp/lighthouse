use kzg::{Error as KzgError, Kzg};
use types::{Blob, EthSpec, Hash256, KzgCommitment, KzgProof};

/// Validate a single blob-commitment-proof triplet from a `BlobSidecar`.
pub fn validate_blob(
    kzg: &Kzg,
    blob: &Blob,
    kzg_commitment: KzgCommitment,
    kzg_proof: KzgProof,
) -> Result<bool, KzgError> {
    kzg.verify_blob_kzg_proof(blob.c_kzg_blob(), kzg_commitment, kzg_proof)
}

/// Validate a batch of blob-commitment-proof triplets from multiple `BlobSidecars`.
pub fn validate_blobs(
    kzg: &Kzg,
    expected_kzg_commitments: &[KzgCommitment],
    blobs: &[Blob],
    kzg_proofs: &[KzgProof],
) -> Result<bool, KzgError> {
    let blobs = blobs
        .iter()
        // unfortunately we can't avoid this clone until we have a better API
        .map(|blob| blob.c_kzg_blob().clone())
        .collect::<Vec<_>>();

    kzg.verify_blob_kzg_proof_batch(&blobs, expected_kzg_commitments, kzg_proofs)
}

/// Compute the kzg proof given an ssz blob and its kzg commitment.
pub fn compute_blob_kzg_proof(
    kzg: &Kzg,
    blob: &Blob,
    kzg_commitment: KzgCommitment,
) -> Result<KzgProof, KzgError> {
    // Avoid this blob clone
    kzg.compute_blob_kzg_proof(blob.c_kzg_blob(), kzg_commitment)
}

/// Compute the kzg commitment for a given blob.
pub fn blob_to_kzg_commitment(kzg: &Kzg, blob: Blob) -> Result<KzgCommitment, KzgError> {
    kzg.blob_to_kzg_commitment(blob.c_kzg_blob().clone())
}

/// Compute the kzg proof for a given blob and an evaluation point z.
pub fn compute_kzg_proof<T: EthSpec>(
    kzg: &Kzg,
    blob: &Blob,
    z: Hash256,
) -> Result<(KzgProof, Hash256), KzgError> {
    let z = z.0.into();
    kzg.compute_kzg_proof(blob.c_kzg_blob(), z)
        .map(|(proof, z)| (proof, Hash256::from_slice(&z.to_vec())))
}

/// Verify a `kzg_proof` for a `kzg_commitment` that evaluating a polynomial at `z` results in `y`
pub fn verify_kzg_proof<T: EthSpec>(
    kzg: &Kzg,
    kzg_commitment: KzgCommitment,
    kzg_proof: KzgProof,
    z: Hash256,
    y: Hash256,
) -> Result<bool, KzgError> {
    kzg.verify_kzg_proof(kzg_commitment, z.0.into(), y.0.into(), kzg_proof)
}
