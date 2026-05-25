pub mod consts;

pub use kzg::{Error as KzgError, Kzg, KzgCommitment, KzgProof};

use crate::core::EthSpec;
use crate::{BeaconStateError, Hash256};
use merkle_proof::{MerkleTree, MerkleTreeError};
use ssz_types::{FixedVector, VariableList};
use tree_hash::{BYTES_PER_CHUNK, TreeHash};

// Note on List limit:
// - Deneb to Electra: `MaxBlobCommitmentsPerBlock`
// - Fulu: `MaxCellsPerBlock`
// We choose to use a single type (with the larger value from Fulu as `N`) instead of having to
// introduce a new type for Fulu. This is to avoid messy conversions and having to add extra types
// with no gains - as `N` does not impact serialisation at all, and only affects merkleization,
// which we don't current do on `KzgProofs` anyway.
pub type KzgProofs<E> = VariableList<KzgProof, <E as EthSpec>::MaxCellsPerBlock>;

pub type KzgCommitments<E> =
    VariableList<KzgCommitment, <E as EthSpec>::MaxBlobCommitmentsPerBlock>;

/// Util method helpful for logging.
pub fn format_kzg_commitments(commitments: &[KzgCommitment]) -> String {
    let commitment_strings: Vec<String> = commitments.iter().map(|x| x.to_string()).collect();
    let commitments_joined = commitment_strings.join(", ");
    let surrounded_commitments = format!("[{}]", commitments_joined);
    surrounded_commitments
}

pub fn complete_kzg_commitment_merkle_proof<E: EthSpec>(
    kzg_commitments: &KzgCommitments<E>,
    index: usize,
    kzg_commitments_proof: &[Hash256],
) -> Result<FixedVector<Hash256, E::KzgCommitmentInclusionProofDepth>, BeaconStateError> {
    // We compute the branches by generating 2 merkle trees:
    // 1. Merkle tree for the `blob_kzg_commitments` List object
    // 2. Merkle tree for the `BeaconBlockBody` container
    // We then merge the branches for both the trees all the way up to the root.

    // Part1 (Branches for the subtree rooted at `blob_kzg_commitments`)
    //
    // Branches for `blob_kzg_commitments` without length mix-in
    let blob_leaves = kzg_commitments
        .iter()
        .map(|commitment| commitment.tree_hash_root())
        .collect::<Vec<_>>();
    let depth = E::max_blob_commitments_per_block()
        .next_power_of_two()
        .ilog2();
    let tree = MerkleTree::create(&blob_leaves, depth as usize);
    let (_, mut proof) = tree
        .generate_proof(index, depth as usize)
        .map_err(BeaconStateError::MerkleTreeError)?;

    // Add the branch corresponding to the length mix-in.
    let length = blob_leaves.len();
    let usize_len = std::mem::size_of::<usize>();
    let mut length_bytes = [0; BYTES_PER_CHUNK];
    length_bytes
        .get_mut(0..usize_len)
        .ok_or(BeaconStateError::MerkleTreeError(
            MerkleTreeError::PleaseNotifyTheDevs,
        ))?
        .copy_from_slice(&length.to_le_bytes());
    let length_root = Hash256::from_slice(length_bytes.as_slice());
    proof.push(length_root);

    // Part 2
    // Branches for `BeaconBlockBody` container
    // Join the proofs for the subtree and the main tree
    proof.extend_from_slice(kzg_commitments_proof);

    Ok(FixedVector::new(proof)?)
}
