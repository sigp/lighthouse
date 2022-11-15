use types::{Blob, BlobsSidecar, EthSpec, KzgCommitment, KzgProof};

pub fn validate_blobs_sidecar(
    slot: Slot,
    beacon_block_root: Hash256,
    expected_kzg_commitments: &[KzgCommitment],
    blobs_sidecar: BlobsSidecar<T: EthSpec>,
) -> bool {
    //TODO(pawan): change to a Result later
    if slot != blobs_sidecar.blobs
        || beacon_block_root != blobs_sidecar.beacon_block_root
        || blobs_sidecar.blobs.len() != expected_kzg_commitments.len()
        || !verify_aggregate_kzg_proof(
            blobs_sidecar.blobs,
            expected_kzg_commitments,
            blobs_sidecar.kzg_aggregate_proof,
        )
    {
        return false;
    } else {
        return true;
    }
}

pub fn compute_aggregate_kzg_proof(blobs: &[Blob<T: EthSpec>]) -> KzgProof {
    unimplemented!()
}
