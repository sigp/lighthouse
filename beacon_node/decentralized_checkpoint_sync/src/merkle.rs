use merkle_proof::verify_merkle_proof;
use types::Hash256;

/// Verify a state branch which may have been zero-prefixed during a light-client schema upgrade.
pub(crate) fn is_valid_normalized_merkle_branch(
    leaf: Hash256,
    branch: &[Hash256],
    index: usize,
    depth: usize,
    root: Hash256,
) -> bool {
    let Some(extra) = branch.len().checked_sub(depth) else {
        return false;
    };
    let Some((padding, proof)) = branch.split_at_checked(extra) else {
        return false;
    };
    padding.iter().all(|node| *node == Hash256::default())
        && verify_merkle_proof(leaf, proof, depth, index, root)
}
