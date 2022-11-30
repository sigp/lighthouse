use int_to_bytes::int_to_fixed_bytes32;
use merkle_proof::MerkleTree;
use rayon::prelude::*;
use tree_hash::TreeHash;
use types::{ChainSpec, Deposit, DepositData, Hash256};

/// Accepts the genesis block validator `DepositData` list and produces a list of `Deposit`, with
/// proofs.
pub fn genesis_deposits(
    deposit_data: Vec<DepositData>,
    spec: &ChainSpec,
) -> Result<Vec<Deposit>, String> {
    let deposit_root_leaves = deposit_data
        .par_iter()
        .map(|data| data.tree_hash_root())
        .collect::<Vec<_>>();

    let mut proofs = vec![];
    let depth = spec.deposit_contract_tree_depth as usize;
    let mut tree = MerkleTree::create(&[], depth);
    for (i, deposit_leaf) in deposit_root_leaves.iter().enumerate() {
        if tree.push_leaf(*deposit_leaf, depth).is_err() {
            return Err(String::from("Failed to push leaf"));
        }

        let (_, mut proof) = tree
            .generate_proof(i, depth)
            .map_err(|e| format!("Error generating merkle proof: {:?}", e))?;
        proof.push(Hash256::from_slice(&int_to_fixed_bytes32((i + 1) as u64)));

        assert_eq!(
            proof.len(),
            depth + 1,
            "Deposit proof should be correct len"
        );

        proofs.push(proof);
    }

    Ok(deposit_data
        .into_iter()
        .zip(proofs.into_iter())
        .map(|(data, proof)| (data, proof.into()))
        .map(|(data, proof)| Deposit { proof, data })
        .collect())
}
