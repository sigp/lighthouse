use eth2_hashing::hash;
use int_to_bytes::int_to_bytes32;
use merkle_proof::{MerkleTree, MerkleTreeError};
use safe_arith::SafeArith;
use types::Hash256;

/// Emulates the eth1 deposit contract merkle tree.
pub struct DepositDataTree {
    tree: MerkleTree,
    mix_in_length: usize,
    depth: usize,
}

impl DepositDataTree {
    /// Create a new Merkle tree from a list of leaves (`DepositData::tree_hash_root`) and a fixed depth.
    pub fn create(leaves: &[Hash256], mix_in_length: usize, depth: usize) -> Self {
        Self {
            tree: MerkleTree::create(leaves, depth),
            mix_in_length,
            depth,
        }
    }

    /// Returns 32 bytes representing the "mix in length" for the merkle root of this tree.
    fn length_bytes(&self) -> Vec<u8> {
        int_to_bytes32(self.mix_in_length as u64)
    }

    /// Retrieve the root hash of this Merkle tree with the length mixed in.
    pub fn root(&self) -> Hash256 {
        let mut preimage = [0; 64];
        preimage[0..32].copy_from_slice(&self.tree.hash()[..]);
        preimage[32..64].copy_from_slice(&self.length_bytes());
        Hash256::from_slice(&hash(&preimage))
    }

    /// Return the leaf at `index` and a Merkle proof of its inclusion.
    ///
    /// The Merkle proof is in "bottom-up" order, starting with a leaf node
    /// and moving up the tree. Its length will be exactly equal to `depth + 1`.
    pub fn generate_proof(&self, index: usize) -> (Hash256, Vec<Hash256>) {
        let (root, mut proof) = self.tree.generate_proof(index, self.depth);
        proof.push(Hash256::from_slice(&self.length_bytes()));
        (root, proof)
    }

    /// Add a deposit to the merkle tree.
    pub fn push_leaf(&mut self, leaf: Hash256) -> Result<(), MerkleTreeError> {
        self.tree.push_leaf(leaf, self.depth)?;
        self.mix_in_length.safe_add_assign(1)?;
        Ok(())
    }
}
