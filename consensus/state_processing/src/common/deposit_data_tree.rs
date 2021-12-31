use eth2_hashing::hash;
use int_to_bytes::int_to_bytes32;
use merkle_proof::{MerkleTree, MerkleTreeError};
use safe_arith::SafeArith;
use types::{DepositTreeSnapshot, Hash256};

/// Emulates the eth1 deposit contract merkle tree.
#[derive(PartialEq)]
pub struct DepositDataTree {
    tree: MerkleTree,
    mix_in_length: usize,
    deposits_finalized: usize,
    finalized_eth1_block_hash: Option<Hash256>,
    depth: usize,
}

impl DepositDataTree {
    /// Create a new Merkle tree from a list of leaves (`DepositData::tree_hash_root`) and a fixed depth.
    pub fn create(leaves: &[Hash256], mix_in_length: usize, depth: usize) -> Self {
        Self {
            tree: MerkleTree::create(leaves, depth),
            mix_in_length,
            deposits_finalized: 0,
            finalized_eth1_block_hash: None,
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
    pub fn generate_proof(&self, index: usize) -> Result<(Hash256, Vec<Hash256>), MerkleTreeError> {
        let (root, mut proof) = self.tree.generate_proof(index, self.depth)?;
        proof.push(Hash256::from_slice(&self.length_bytes()));
        Ok((root, proof))
    }

    /// Add a deposit to the merkle tree.
    pub fn push_leaf(&mut self, leaf: Hash256) -> Result<(), MerkleTreeError> {
        self.tree.push_leaf(leaf, self.depth)?;
        self.mix_in_length.safe_add_assign(1)?;
        Ok(())
    }

    /// Finalize deposits up to `count`
    pub fn finalize(
        &mut self,
        count: usize,
        eth1_block_hash: Hash256,
    ) -> Result<(), MerkleTreeError> {
        self.tree.finalize_deposits(count, self.depth)?;
        self.deposits_finalized = count;
        self.finalized_eth1_block_hash = Some(eth1_block_hash);
        Ok(())
    }

    /// Get snapshot of finalized deposit tree
    pub fn get_snapshot(&self) -> DepositTreeSnapshot {
        DepositTreeSnapshot {
            branches: self.tree.get_finalized_snapshot(),
            deposits: self.deposits_finalized as u64,
            eth1_block_hash: self.finalized_eth1_block_hash.unwrap_or_else(Hash256::zero),
        }
    }

    /// Create a new Merkle tree from a snapshot
    pub fn from_snapshot(
        snapshot: &DepositTreeSnapshot,
        depth: usize,
    ) -> Result<Self, MerkleTreeError> {
        let finalized_eth1_block_hash = if snapshot.eth1_block_hash.is_zero() {
            None
        } else {
            Some(snapshot.eth1_block_hash)
        };
        Ok(Self {
            tree: MerkleTree::from_finalized_snapshot(
                &snapshot.branches,
                snapshot.deposits as usize,
                depth,
            )?,
            mix_in_length: snapshot.deposits as usize,
            deposits_finalized: snapshot.deposits as usize,
            finalized_eth1_block_hash,
            depth,
        })
    }

    #[allow(dead_code)]
    pub fn print_tree(&self) {
        self.tree.print_node(0);
        println!("========================================================");
    }
}
