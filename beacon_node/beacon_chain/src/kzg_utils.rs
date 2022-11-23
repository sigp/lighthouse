use kzg::Kzg;
use types::{Blob, BlobsSidecar, EthSpec, Hash256, KzgCommitment, KzgProof, Slot};

// TODO(pawan): make this generic over blob size
fn ssz_blob_to_crypto_blob<T: EthSpec>(blob: Blob<T>) -> Option<[u8; 131072]> {
    if blob.len() != 131072 {
        return None;
    }
    let blob_vec: Vec<u8> = blob.into();
    let mut arr = [0; 131072];
    arr.copy_from_slice(&blob_vec);
    Some(arr)
}

pub fn validate_blobs_sidecar<T: EthSpec>(
    kzg: &Kzg,
    slot: Slot,
    beacon_block_root: Hash256,
    expected_kzg_commitments: &[KzgCommitment],
    blobs_sidecar: BlobsSidecar<T>,
) -> Result<bool, String> {
    if slot != blobs_sidecar.beacon_block_slot
        || beacon_block_root != blobs_sidecar.beacon_block_root
        || blobs_sidecar.blobs.len() != expected_kzg_commitments.len()
    {
        return Ok(false);
    }

    let blobs = blobs_sidecar
        .blobs
        .into_iter()
        .map(|blob| ssz_blob_to_crypto_blob::<T>(blob.clone())) // TODO(pawan): avoid this clone
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| "Invalid blobs in sidecar".to_string())?;

    kzg.verify_aggregate_kzg_proof(
        &blobs,
        expected_kzg_commitments,
        blobs_sidecar.kzg_aggregated_proof,
    )
    .map_err(|e| format!("Failed to verify kzg proof: {:?}", e))
}

pub fn compute_aggregate_kzg_proof<T: EthSpec>(
    kzg: &Kzg,
    blobs: &[Blob<T>],
) -> Result<KzgProof, String> {
    let blobs = blobs
        .into_iter()
        .map(|blob| ssz_blob_to_crypto_blob::<T>(blob.clone())) // TODO(pawan): avoid this clone
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| "Invalid blobs in sidecar".to_string())?;
    kzg.compute_aggregate_kzg_proof(&blobs)
        .map_err(|e| format!("Failed to compute kzg proof: {:?}", e))
}

pub fn blob_to_kzg_commitment<T: EthSpec>(kzg: &Kzg, blob: Blob<T>) -> Option<KzgCommitment> {
    let blob = ssz_blob_to_crypto_blob::<T>(blob)?;
    Some(kzg.blob_to_kzg_commitment(blob))
}
