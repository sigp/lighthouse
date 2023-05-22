use ethereum_hashing::{hash, hash32_concat, ZERO_HASHES};
use ethereum_types::H256;
use lazy_static::lazy_static;
use safe_arith::ArithError;

const MAX_TREE_DEPTH: usize = 32;
const EMPTY_SLICE: &[H256] = &[];

lazy_static! {
    /// Zero nodes to act as "synthetic" left and right subtrees of other zero nodes.
    static ref ZERO_NODES: Vec<MerkleTree> = {
        (0..=MAX_TREE_DEPTH).map(MerkleTree::Zero).collect()
    };
}

/// Right-sparse Merkle tree.
///
/// Efficiently represents a Merkle tree of fixed depth where only the first N
/// indices are populated by non-zero leaves (perfect for the deposit contract tree).
#[derive(Debug, PartialEq)]
pub enum MerkleTree {
    /// Finalized Node
    Finalized(H256),
    /// Leaf node with the hash of its content.
    Leaf(H256),
    /// Internal node with hash, left subtree and right subtree.
    Node(H256, Box<Self>, Box<Self>),
    /// Zero subtree of a given depth.
    ///
    /// It represents a Merkle tree of 2^depth zero leaves.
    Zero(usize),
}

#[derive(Debug, PartialEq, Clone)]
pub enum MerkleTreeError {
    // Trying to push in a leaf
    LeafReached,
    // No more space in the MerkleTree
    MerkleTreeFull,
    // MerkleTree is invalid
    Invalid,
    // Incorrect Depth provided
    DepthTooSmall,
    // Overflow occurred
    ArithError,
    // Can't finalize a zero node
    ZeroNodeFinalized,
    // Can't push to finalized node
    FinalizedNodePushed,
    // Invalid Snapshot
    InvalidSnapshot(InvalidSnapshot),
    // Can't proof a finalized node
    ProofEncounteredFinalizedNode,
    // This should never happen
    PleaseNotifyTheDevs,
}

#[derive(Debug, PartialEq, Clone)]
pub enum InvalidSnapshot {
    // Branch hashes are empty but deposits are not
    EmptyBranchWithNonZeroDeposits(usize),
    // End of tree reached but deposits != 1
    EndOfTree,
}

impl MerkleTree {
    /// Create a new Merkle tree from a list of leaves and a fixed depth.
    pub fn create(leaves: &[H256], depth: usize) -> Self {
        use MerkleTree::*;

        if leaves.is_empty() {
            return Zero(depth);
        }

        match depth {
            0 => {
                debug_assert_eq!(leaves.len(), 1);
                Leaf(leaves[0])
            }
            _ => {
                // Split leaves into left and right subtrees
                let subtree_capacity = 2usize.pow(depth as u32 - 1);
                let (left_leaves, right_leaves) = if leaves.len() <= subtree_capacity {
                    (leaves, EMPTY_SLICE)
                } else {
                    leaves.split_at(subtree_capacity)
                };

                let left_subtree = MerkleTree::create(left_leaves, depth - 1);
                let right_subtree = MerkleTree::create(right_leaves, depth - 1);
                let hash = H256::from_slice(&hash32_concat(
                    left_subtree.hash().as_bytes(),
                    right_subtree.hash().as_bytes(),
                ));

                Node(hash, Box::new(left_subtree), Box::new(right_subtree))
            }
        }
    }

    /// Push an element in the MerkleTree.
    /// MerkleTree and depth must be correct, as the algorithm expects valid data.
    pub fn push_leaf(&mut self, elem: H256, depth: usize) -> Result<(), MerkleTreeError> {
        use MerkleTree::*;

        if depth == 0 {
            return Err(MerkleTreeError::DepthTooSmall);
        }

        match self {
            Leaf(_) => return Err(MerkleTreeError::LeafReached),
            Zero(_) => {
                *self = MerkleTree::create(&[elem], depth);
            }
            Node(ref mut hash, ref mut left, ref mut right) => {
                let left: &mut MerkleTree = &mut *left;
                let right: &mut MerkleTree = &mut *right;
                match (&*left, &*right) {
                    // Tree is full
                    (Leaf(_), Leaf(_)) | (Finalized(_), Leaf(_)) => {
                        return Err(MerkleTreeError::MerkleTreeFull)
                    }
                    // There is a right node so insert in right node
                    (Node(_, _, _), Node(_, _, _)) | (Finalized(_), Node(_, _, _)) => {
                        right.push_leaf(elem, depth - 1)?;
                    }
                    // Both branches are zero, insert in left one
                    (Zero(_), Zero(_)) => {
                        *left = MerkleTree::create(&[elem], depth - 1);
                    }
                    // Leaf on left branch and zero on right branch, insert on right side
                    (Leaf(_), Zero(_)) | (Finalized(_), Zero(_)) => {
                        *right = MerkleTree::create(&[elem], depth - 1);
                    }
                    // Try inserting on the left node -> if it fails because it is full, insert in right side.
                    (Node(_, _, _), Zero(_)) => {
                        match left.push_leaf(elem, depth - 1) {
                            Ok(_) => (),
                            // Left node is full, insert in right node
                            Err(MerkleTreeError::MerkleTreeFull) => {
                                *right = MerkleTree::create(&[elem], depth - 1);
                            }
                            Err(e) => return Err(e),
                        };
                    }
                    // All other possibilities are invalid MerkleTrees
                    (_, _) => return Err(MerkleTreeError::Invalid),
                };
                hash.assign_from_slice(&hash32_concat(
                    left.hash().as_bytes(),
                    right.hash().as_bytes(),
                ));
            }
            Finalized(_) => return Err(MerkleTreeError::FinalizedNodePushed),
        }

        Ok(())
    }

    /// Retrieve the root hash of this Merkle tree.
    pub fn hash(&self) -> H256 {
        match *self {
            MerkleTree::Finalized(h) => h,
            MerkleTree::Leaf(h) => h,
            MerkleTree::Node(h, _, _) => h,
            MerkleTree::Zero(depth) => H256::from_slice(&ZERO_HASHES[depth]),
        }
    }

    /// Get a reference to the left and right subtrees if they exist.
    pub fn left_and_right_branches(&self) -> Option<(&Self, &Self)> {
        match *self {
            MerkleTree::Finalized(_) | MerkleTree::Leaf(_) | MerkleTree::Zero(0) => None,
            MerkleTree::Node(_, ref l, ref r) => Some((l, r)),
            MerkleTree::Zero(depth) => Some((&ZERO_NODES[depth - 1], &ZERO_NODES[depth - 1])),
        }
    }

    /// Is this Merkle tree a leaf?
    pub fn is_leaf(&self) -> bool {
        matches!(self, MerkleTree::Leaf(_))
    }

    /// Finalize deposits up to deposit with count = deposits_to_finalize
    pub fn finalize_deposits(
        &mut self,
        deposits_to_finalize: usize,
        level: usize,
    ) -> Result<(), MerkleTreeError> {
        match self {
            MerkleTree::Finalized(_) => Ok(()),
            MerkleTree::Zero(_) => Err(MerkleTreeError::ZeroNodeFinalized),
            MerkleTree::Leaf(hash) => {
                if level != 0 {
                    // This shouldn't happen but this is a sanity check
                    return Err(MerkleTreeError::PleaseNotifyTheDevs);
                }
                *self = MerkleTree::Finalized(*hash);
                Ok(())
            }
            MerkleTree::Node(hash, left, right) => {
                if level == 0 {
                    // this shouldn't happen but we'll put it here for safety
                    return Err(MerkleTreeError::PleaseNotifyTheDevs);
                }
                let deposits = 0x1 << level;
                if deposits <= deposits_to_finalize {
                    *self = MerkleTree::Finalized(*hash);
                    return Ok(());
                }
                left.finalize_deposits(deposits_to_finalize, level - 1)?;
                if deposits_to_finalize > deposits / 2 {
                    let remaining = deposits_to_finalize - deposits / 2;
                    right.finalize_deposits(remaining, level - 1)?;
                }
                Ok(())
            }
        }
    }

    fn append_finalized_hashes(&self, result: &mut Vec<H256>) {
        match self {
            MerkleTree::Zero(_) | MerkleTree::Leaf(_) => {}
            MerkleTree::Finalized(h) => result.push(*h),
            MerkleTree::Node(_, left, right) => {
                left.append_finalized_hashes(result);
                right.append_finalized_hashes(result);
            }
        }
    }

    pub fn get_finalized_hashes(&self) -> Vec<H256> {
        let mut result = vec![];
        self.append_finalized_hashes(&mut result);
        result
    }

    pub fn from_finalized_snapshot(
        finalized_branch: &[H256],
        deposit_count: usize,
        level: usize,
    ) -> Result<Self, MerkleTreeError> {
        if finalized_branch.is_empty() {
            return if deposit_count == 0 {
                Ok(MerkleTree::Zero(level))
            } else {
                Err(InvalidSnapshot::EmptyBranchWithNonZeroDeposits(deposit_count).into())
            };
        }
        if deposit_count == (0x1 << level) {
            return Ok(MerkleTree::Finalized(
                *finalized_branch
                    .get(0)
                    .ok_or(MerkleTreeError::PleaseNotifyTheDevs)?,
            ));
        }
        if level == 0 {
            return Err(InvalidSnapshot::EndOfTree.into());
        }

        let (left, right) = match deposit_count.checked_sub(0x1 << (level - 1)) {
            // left tree is fully finalized
            Some(right_deposits) => {
                let (left_hash, right_branch) = finalized_branch
                    .split_first()
                    .ok_or(MerkleTreeError::PleaseNotifyTheDevs)?;
                (
                    MerkleTree::Finalized(*left_hash),
                    MerkleTree::from_finalized_snapshot(right_branch, right_deposits, level - 1)?,
                )
            }
            // left tree is not fully finalized -> right tree is zero
            None => (
                MerkleTree::from_finalized_snapshot(finalized_branch, deposit_count, level - 1)?,
                MerkleTree::Zero(level - 1),
            ),
        };

        let hash = H256::from_slice(&hash32_concat(
            left.hash().as_bytes(),
            right.hash().as_bytes(),
        ));
        Ok(MerkleTree::Node(hash, Box::new(left), Box::new(right)))
    }

    /// Return the leaf at `index` and a Merkle proof of its inclusion.
    ///
    /// The Merkle proof is in "bottom-up" order, starting with a leaf node
    /// and moving up the tree. Its length will be exactly equal to `depth`.
    pub fn generate_proof(
        &self,
        index: usize,
        depth: usize,
    ) -> Result<(H256, Vec<H256>), MerkleTreeError> {
        let mut proof = vec![];
        let mut current_node = self;
        let mut current_depth = depth;
        while current_depth > 0 {
            let ith_bit = (index >> (current_depth - 1)) & 0x01;
            if let &MerkleTree::Finalized(_) = current_node {
                return Err(MerkleTreeError::ProofEncounteredFinalizedNode);
            }
            // Note: unwrap is safe because leaves are only ever constructed at depth == 0.
            let (left, right) = current_node.left_and_right_branches().unwrap();

            // Go right, include the left branch in the proof.
            if ith_bit == 1 {
                proof.push(left.hash());
                current_node = right;
            } else {
                proof.push(right.hash());
                current_node = left;
            }
            current_depth -= 1;
        }

        debug_assert_eq!(proof.len(), depth);
        debug_assert!(current_node.is_leaf());

        // Put proof in bottom-up order.
        proof.reverse();

        Ok((current_node.hash(), proof))
    }

    /// useful for debugging
    pub fn print_node(&self, mut space: u32) {
        const SPACES: u32 = 10;
        space += SPACES;
        let (pair, text) = match self {
            MerkleTree::Node(hash, left, right) => (Some((left, right)), format!("Node({})", hash)),
            MerkleTree::Leaf(hash) => (None, format!("Leaf({})", hash)),
            MerkleTree::Zero(depth) => (
                None,
                format!("Z[{}]({})", depth, H256::from_slice(&ZERO_HASHES[*depth])),
            ),
            MerkleTree::Finalized(hash) => (None, format!("Finl({})", hash)),
        };
        if let Some((_, right)) = pair {
            right.print_node(space);
        }
        println!();
        for _i in SPACES..space {
            print!(" ");
        }
        println!("{}", text);
        if let Some((left, _)) = pair {
            left.print_node(space);
        }
    }
}

/// Verify a proof that `leaf` exists at `index` in a Merkle tree rooted at `root`.
///
/// The `branch` argument is the main component of the proof: it should be a list of internal
/// node hashes such that the root can be reconstructed (in bottom-up order).
pub fn verify_merkle_proof(
    leaf: H256,
    branch: &[H256],
    depth: usize,
    index: usize,
    root: H256,
) -> bool {
    if branch.len() == depth {
        merkle_root_from_branch(leaf, branch, depth, index) == root
    } else {
        false
    }
}

/// Compute a root hash from a leaf and a Merkle proof.
fn merkle_root_from_branch(leaf: H256, branch: &[H256], depth: usize, index: usize) -> H256 {
    assert_eq!(branch.len(), depth, "proof length should equal depth");

    let mut merkle_root = leaf.as_bytes().to_vec();

    for (i, leaf) in branch.iter().enumerate().take(depth) {
        let ith_bit = (index >> i) & 0x01;
        if ith_bit == 1 {
            merkle_root = hash32_concat(leaf.as_bytes(), &merkle_root)[..].to_vec();
        } else {
            let mut input = merkle_root;
            input.extend_from_slice(leaf.as_bytes());
            merkle_root = hash(&input);
        }
    }

    H256::from_slice(&merkle_root)
}

impl From<ArithError> for MerkleTreeError {
    fn from(_: ArithError) -> Self {
        MerkleTreeError::ArithError
    }
}

impl From<InvalidSnapshot> for MerkleTreeError {
    fn from(e: InvalidSnapshot) -> Self {
        MerkleTreeError::InvalidSnapshot(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;

    /// Check that we can:
    /// 1. Build a MerkleTree from arbitrary leaves and an arbitrary depth.
    /// 2. Generate valid proofs for all of the leaves of this MerkleTree.
    #[quickcheck]
    fn quickcheck_create_and_verify(int_leaves: Vec<u64>, depth: usize) -> TestResult {
        if depth > MAX_TREE_DEPTH || int_leaves.len() > 2usize.pow(depth as u32) {
            return TestResult::discard();
        }

        let leaves: Vec<_> = int_leaves.into_iter().map(H256::from_low_u64_be).collect();
        let merkle_tree = MerkleTree::create(&leaves, depth);
        let merkle_root = merkle_tree.hash();

        let proofs_ok = (0..leaves.len()).all(|i| {
            let (leaf, branch) = merkle_tree
                .generate_proof(i, depth)
                .expect("should generate proof");
            leaf == leaves[i] && verify_merkle_proof(leaf, &branch, depth, i, merkle_root)
        });

        TestResult::from_bool(proofs_ok)
    }

    #[quickcheck]
    fn quickcheck_push_leaf_and_verify(int_leaves: Vec<u64>, depth: usize) -> TestResult {
        if depth == 0 || depth > MAX_TREE_DEPTH || int_leaves.len() > 2usize.pow(depth as u32) {
            return TestResult::discard();
        }

        let leaves_iter = int_leaves.into_iter().map(H256::from_low_u64_be);

        let mut merkle_tree = MerkleTree::create(&[], depth);

        let proofs_ok = leaves_iter.enumerate().all(|(i, leaf)| {
            assert_eq!(merkle_tree.push_leaf(leaf, depth), Ok(()));
            let (stored_leaf, branch) = merkle_tree
                .generate_proof(i, depth)
                .expect("should generate proof");
            stored_leaf == leaf && verify_merkle_proof(leaf, &branch, depth, i, merkle_tree.hash())
        });

        TestResult::from_bool(proofs_ok)
    }

    #[test]
    fn sparse_zero_correct() {
        let depth = 2;
        let zero = H256::from([0x00; 32]);
        let dense_tree = MerkleTree::create(&[zero, zero, zero, zero], depth);
        let sparse_tree = MerkleTree::create(&[], depth);
        assert_eq!(dense_tree.hash(), sparse_tree.hash());
    }

    #[test]
    fn create_small_example() {
        // Construct a small merkle tree manually and check that it's consistent with
        // the MerkleTree type.
        let leaf_b00 = H256::from([0xAA; 32]);
        let leaf_b01 = H256::from([0xBB; 32]);
        let leaf_b10 = H256::from([0xCC; 32]);
        let leaf_b11 = H256::from([0xDD; 32]);

        let node_b0x = H256::from_slice(&hash32_concat(leaf_b00.as_bytes(), leaf_b01.as_bytes()));
        let node_b1x = H256::from_slice(&hash32_concat(leaf_b10.as_bytes(), leaf_b11.as_bytes()));

        let root = H256::from_slice(&hash32_concat(node_b0x.as_bytes(), node_b1x.as_bytes()));

        let tree = MerkleTree::create(&[leaf_b00, leaf_b01, leaf_b10, leaf_b11], 2);
        assert_eq!(tree.hash(), root);
    }

    #[test]
    fn verify_small_example() {
        // Construct a small merkle tree manually
        let leaf_b00 = H256::from([0xAA; 32]);
        let leaf_b01 = H256::from([0xBB; 32]);
        let leaf_b10 = H256::from([0xCC; 32]);
        let leaf_b11 = H256::from([0xDD; 32]);

        let node_b0x = H256::from_slice(&hash32_concat(leaf_b00.as_bytes(), leaf_b01.as_bytes()));
        let node_b1x = H256::from_slice(&hash32_concat(leaf_b10.as_bytes(), leaf_b11.as_bytes()));

        let root = H256::from_slice(&hash32_concat(node_b0x.as_bytes(), node_b1x.as_bytes()));

        // Run some proofs
        assert!(verify_merkle_proof(
            leaf_b00,
            &[leaf_b01, node_b1x],
            2,
            0b00,
            root
        ));
        assert!(verify_merkle_proof(
            leaf_b01,
            &[leaf_b00, node_b1x],
            2,
            0b01,
            root
        ));
        assert!(verify_merkle_proof(
            leaf_b10,
            &[leaf_b11, node_b0x],
            2,
            0b10,
            root
        ));
        assert!(verify_merkle_proof(
            leaf_b11,
            &[leaf_b10, node_b0x],
            2,
            0b11,
            root
        ));
        assert!(verify_merkle_proof(
            leaf_b11,
            &[leaf_b10],
            1,
            0b11,
            node_b1x
        ));

        // Ensure that incorrect proofs fail
        // Zero-length proof
        assert!(!verify_merkle_proof(leaf_b01, &[], 2, 0b01, root));
        // Proof in reverse order
        assert!(!verify_merkle_proof(
            leaf_b01,
            &[node_b1x, leaf_b00],
            2,
            0b01,
            root
        ));
        // Proof too short
        assert!(!verify_merkle_proof(leaf_b01, &[leaf_b00], 2, 0b01, root));
        // Wrong index
        assert!(!verify_merkle_proof(
            leaf_b01,
            &[leaf_b00, node_b1x],
            2,
            0b10,
            root
        ));
        // Wrong root
        assert!(!verify_merkle_proof(
            leaf_b01,
            &[leaf_b00, node_b1x],
            2,
            0b01,
            node_b1x
        ));
    }

    #[test]
    fn verify_zero_depth() {
        let leaf = H256::from([0xD6; 32]);
        let junk = H256::from([0xD7; 32]);
        assert!(verify_merkle_proof(leaf, &[], 0, 0, leaf));
        assert!(!verify_merkle_proof(leaf, &[], 0, 7, junk));
    }

    #[test]
    fn push_complete_example() {
        let depth = 2;
        let mut tree = MerkleTree::create(&[], depth);

        let leaf_b00 = H256::from([0xAA; 32]);

        let res = tree.push_leaf(leaf_b00, 0);
        assert_eq!(res, Err(MerkleTreeError::DepthTooSmall));
        let expected_tree = MerkleTree::create(&[], depth);
        assert_eq!(tree.hash(), expected_tree.hash());

        tree.push_leaf(leaf_b00, depth)
            .expect("Pushing in empty tree failed");
        let expected_tree = MerkleTree::create(&[leaf_b00], depth);
        assert_eq!(tree.hash(), expected_tree.hash());

        let leaf_b01 = H256::from([0xBB; 32]);
        tree.push_leaf(leaf_b01, depth)
            .expect("Pushing in left then right node failed");
        let expected_tree = MerkleTree::create(&[leaf_b00, leaf_b01], depth);
        assert_eq!(tree.hash(), expected_tree.hash());

        let leaf_b10 = H256::from([0xCC; 32]);
        tree.push_leaf(leaf_b10, depth)
            .expect("Pushing in right then left node failed");
        let expected_tree = MerkleTree::create(&[leaf_b00, leaf_b01, leaf_b10], depth);
        assert_eq!(tree.hash(), expected_tree.hash());

        let leaf_b11 = H256::from([0xDD; 32]);
        tree.push_leaf(leaf_b11, depth)
            .expect("Pushing in outtermost leaf failed");
        let expected_tree = MerkleTree::create(&[leaf_b00, leaf_b01, leaf_b10, leaf_b11], depth);
        assert_eq!(tree.hash(), expected_tree.hash());

        let leaf_b12 = H256::from([0xEE; 32]);
        let res = tree.push_leaf(leaf_b12, depth);
        assert_eq!(res, Err(MerkleTreeError::MerkleTreeFull));
        assert_eq!(tree.hash(), expected_tree.hash());
    }
}
