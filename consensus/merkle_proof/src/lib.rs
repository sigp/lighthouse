use ethereum_hashing::{ZERO_HASHES, hash32_concat};
use safe_arith::{ArithError, SafeArith};
use std::sync::LazyLock;

type H256 = fixed_bytes::Hash256;
pub use fixed_bytes::FixedBytesExtended;

const MAX_TREE_DEPTH: usize = 32;
const EMPTY_SLICE: &[H256] = &[];

/// Zero nodes to act as "synthetic" left and right subtrees of other zero nodes.
static ZERO_NODES: LazyLock<Vec<MerkleTree>> =
    LazyLock::new(|| (0..=MAX_TREE_DEPTH).map(MerkleTree::Zero).collect());

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
    // Trying to generate a proof for a non-leaf node
    NonLeafProof,
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
                    left_subtree.hash().as_slice(),
                    right_subtree.hash().as_slice(),
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
            Node(hash, left, right) => {
                let left: &mut MerkleTree = &mut *left;
                let right: &mut MerkleTree = &mut *right;
                match (&*left, &*right) {
                    // Tree is full
                    (Leaf(_), Leaf(_)) | (Finalized(_), Leaf(_)) => {
                        return Err(MerkleTreeError::MerkleTreeFull);
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
                hash.copy_from_slice(&hash32_concat(
                    left.hash().as_slice(),
                    right.hash().as_slice(),
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
                    .first()
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
            left.hash().as_slice(),
            right.hash().as_slice(),
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

        if proof.len() != depth {
            // This should be unreachable regardless of how the method is called, because we push
            // one proof element for each layer of `depth`.
            return Err(MerkleTreeError::PleaseNotifyTheDevs);
        }

        // Generating a proof for a non-leaf node is invalid and indicates an error on the part of
        // the caller.
        if !current_node.is_leaf() {
            return Err(MerkleTreeError::NonLeafProof);
        }

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
pub fn merkle_root_from_branch(leaf: H256, branch: &[H256], depth: usize, index: usize) -> H256 {
    assert_eq!(branch.len(), depth, "proof length should equal depth");

    let mut merkle_root = leaf.0;

    for (i, branch_node) in branch.iter().enumerate().take(depth) {
        let ith_bit = (index >> i) & 0x01;
        let (left, right) = if ith_bit == 1 {
            (branch_node.as_slice(), merkle_root.as_slice())
        } else {
            (merkle_root.as_slice(), branch_node.as_slice())
        };
        merkle_root = hash32_concat(left, right);
    }

    H256::from(merkle_root)
}

/// Return the first field index, the number of chunks and the binary depth of the progressive
/// subtree at `level`, which holds `4^level` chunks starting at field `(4^level - 1) / 3`
/// (EIP-7916).
fn progressive_level(level: usize) -> Result<(usize, usize, usize), MerkleTreeError> {
    let depth = level.safe_mul(2)?;
    if depth > MAX_TREE_DEPTH {
        return Err(MerkleTreeError::ArithError);
    }
    let size = 1usize.safe_shl(depth as u32)?;
    let start = size.safe_sub(1)?.safe_div(3)?;
    Ok((start, size, depth))
}

/// Find the progressive subtree containing `field_index`, returning the subtree's level, the
/// offset of the field within it, and its chunk count.
fn progressive_field_location(
    field_index: usize,
) -> Result<(usize, usize, usize), MerkleTreeError> {
    for level in 0..=MAX_TREE_DEPTH / 2 {
        let (start, size, _) = progressive_level(level)?;
        if field_index < start.safe_add(size)? {
            return Ok((level, field_index.safe_sub(start)?, size));
        }
    }
    Err(MerkleTreeError::Invalid)
}

/// Return the slice of `field_roots` covered by the subtree at `level`, along with its binary
/// depth.
fn progressive_level_leaves(
    field_roots: &[H256],
    level: usize,
) -> Result<(&[H256], usize), MerkleTreeError> {
    let (start, size, depth) = progressive_level(level)?;
    let end = start.safe_add(size)?.min(field_roots.len());
    let leaves = field_roots.get(start..end).unwrap_or(EMPTY_SLICE);
    Ok((leaves, depth))
}

/// Compute the root of the binary subtree at `level` from the field roots it covers.
fn progressive_level_root(field_roots: &[H256], level: usize) -> Result<H256, MerkleTreeError> {
    let (leaves, depth) = progressive_level_leaves(field_roots, level)?;
    Ok(MerkleTree::create(leaves, depth).hash())
}

/// Compute the root of the progressive tree containing every field from `level` onwards:
/// `hash(binary_root(level), progressive_root(level + 1))`, or zero once no fields remain.
fn progressive_root_from(field_roots: &[H256], level: usize) -> Result<H256, MerkleTreeError> {
    let (start, _, _) = progressive_level(level)?;
    if start >= field_roots.len() {
        return Ok(H256::zero());
    }
    let left = progressive_level_root(field_roots, level)?;
    let right = progressive_root_from(field_roots, level.safe_add(1)?)?;
    Ok(H256::from(hash32_concat(left.as_slice(), right.as_slice())))
}

/// Compute the generalized index of the field at `field_index` in a progressive container. The
/// subtree root at `level` has generalized index `3 * 2^(level + 1) - 2`, with its fields
/// `2 * level` layers below it.
pub fn progressive_container_gindex(field_index: usize) -> Result<usize, MerkleTreeError> {
    let (level, offset, size) = progressive_field_location(field_index)?;
    let subtree_gindex = 3usize
        .safe_mul(1usize.safe_shl(level.safe_add(1)? as u32)?)?
        .safe_sub(2)?;
    Ok(subtree_gindex.safe_mul(size)?.safe_add(offset)?)
}

/// Compute the packed `active_fields` chunk for a container in which every field is active,
/// which is true of every Gloas progressive container.
pub fn active_fields_all_active(num_fields: usize) -> Result<H256, MerkleTreeError> {
    let mut bytes = [0u8; 32];
    for field in 0..num_fields {
        let byte = bytes
            .get_mut(field.safe_div(8)?)
            .ok_or(MerkleTreeError::Invalid)?;
        *byte |= 1u8.safe_shl(field.safe_rem(8)? as u32)?;
    }
    Ok(H256::from(bytes))
}

/// Generate a Merkle proof for the field at `field_index` of a progressive container (EIP-7688).
///
/// `field_roots` must contain the `tree_hash_root` of every field in declaration order. The
/// proof is in bottom-up order, ending with the `active_fields` chunk.
pub fn progressive_container_proof(
    field_roots: &[H256],
    field_index: usize,
    active_fields: H256,
) -> Result<Vec<H256>, MerkleTreeError> {
    if field_index >= field_roots.len() {
        return Err(MerkleTreeError::Invalid);
    }
    let (level, offset, _) = progressive_field_location(field_index)?;
    let (leaves, depth) = progressive_level_leaves(field_roots, level)?;

    let (_, mut proof) = MerkleTree::create(leaves, depth).generate_proof(offset, depth)?;

    proof.push(progressive_root_from(field_roots, level.safe_add(1)?)?);
    for shallower in (0..level).rev() {
        proof.push(progressive_level_root(field_roots, shallower)?);
    }
    proof.push(active_fields);

    Ok(proof)
}

/// Compute the root of a progressive container from its field roots.
pub fn progressive_container_root(
    field_roots: &[H256],
    active_fields: H256,
) -> Result<H256, MerkleTreeError> {
    let progressive_root = progressive_root_from(field_roots, 0)?;
    Ok(H256::from(hash32_concat(
        progressive_root.as_slice(),
        active_fields.as_slice(),
    )))
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
mod progressive_tests {
    use super::*;
    use proptest::prelude::*;

    fn field_roots(count: usize) -> Vec<H256> {
        (0..count)
            .map(|i| H256::from_low_u64_be(i as u64 + 1))
            .collect()
    }

    /// Check the generalized indices against the Gloas `light_client/single_merkle_proof` spec
    /// test vectors.
    #[test]
    fn gindices_match_spec_vectors() {
        // `current_sync_committee` and `next_sync_committee` are fields 22 and 23 of the
        // `BeaconState`.
        assert_eq!(progressive_container_gindex(22).unwrap(), 2945);
        assert_eq!(progressive_container_gindex(23).unwrap(), 2946);

        // `finalized_root` is the right child of `finalized_checkpoint`, which is field 20.
        assert_eq!(progressive_container_gindex(20).unwrap() * 2 + 1, 735);

        // `signed_execution_payload_bid` is field 10 of the `BeaconBlockBody`.
        assert_eq!(progressive_container_gindex(10).unwrap(), 357);
    }

    #[test]
    fn gindices_at_subtree_boundaries() {
        // The subtrees hold 1, 4, 16 and 64 fields, with roots at generalized indices 4, 10, 22
        // and 46.
        assert_eq!(progressive_container_gindex(0).unwrap(), 4);
        assert_eq!(progressive_container_gindex(1).unwrap(), 40);
        assert_eq!(progressive_container_gindex(4).unwrap(), 43);
        assert_eq!(progressive_container_gindex(5).unwrap(), 352);
        assert_eq!(progressive_container_gindex(20).unwrap(), 367);
        assert_eq!(progressive_container_gindex(21).unwrap(), 2944);
    }

    /// Check the packed `active_fields` chunks against the spec test vectors.
    #[test]
    fn active_fields_match_spec_vectors() {
        // The `BeaconState` has 46 fields, the `BeaconBlockBody` 13 and the
        // `ExecutionPayloadBid` 12.
        let cases: [(usize, &[u8]); 4] = [
            (46, &[0xff, 0xff, 0xff, 0xff, 0xff, 0x3f]),
            (13, &[0xff, 0x1f]),
            (12, &[0xff, 0x0f]),
            (0, &[]),
        ];
        for (num_fields, prefix) in cases {
            let mut expected = [0u8; 32];
            expected[..prefix.len()].copy_from_slice(prefix);
            assert_eq!(
                active_fields_all_active(num_fields).unwrap(),
                H256::from(expected),
                "{num_fields} fields"
            );
        }
    }

    /// Check that every proof verifies against the container root, for container sizes spanning
    /// the first four subtrees.
    #[test]
    fn proofs_rebuild_the_root() {
        for num_fields in 1..=85 {
            let roots = field_roots(num_fields);
            let active_fields = active_fields_all_active(num_fields).unwrap();
            let root = progressive_container_root(&roots, active_fields).unwrap();

            for field_index in 0..num_fields {
                let branch =
                    progressive_container_proof(&roots, field_index, active_fields).unwrap();
                let gindex = progressive_container_gindex(field_index).unwrap();
                let depth = branch.len();

                assert!(
                    (1usize << depth..1usize << (depth + 1)).contains(&gindex),
                    "gindex {gindex} does not sit at depth {depth}"
                );
                assert!(
                    verify_merkle_proof(
                        roots[field_index],
                        &branch,
                        depth,
                        gindex - (1 << depth),
                        root
                    ),
                    "field {field_index} of {num_fields} failed to verify"
                );
            }
        }
    }

    /// Requesting a proof for a field beyond the end of the container is an error.
    #[test]
    fn rejects_out_of_range_field() {
        let roots = field_roots(4);
        let active_fields = active_fields_all_active(4).unwrap();
        assert_eq!(
            progressive_container_proof(&roots, 4, active_fields),
            Err(MerkleTreeError::Invalid)
        );
    }

    proptest::proptest! {
        /// Check that proofs verify for arbitrary leaves and container sizes into level 4, and
        /// fail once a branch node is corrupted.
        #[test]
        fn proptest_progressive_create_and_verify(
            (int_leaves, active) in (proptest::collection::vec(any::<u64>(), 0..=350), any::<u64>())
        ) {
            let roots: Vec<_> = int_leaves.into_iter().map(H256::from_low_u64_be).collect();
            let active_fields = H256::from_low_u64_be(active);
            let root = progressive_container_root(&roots, active_fields).unwrap();

            let proofs_ok = (0..roots.len()).all(|i| {
                let branch = progressive_container_proof(&roots, i, active_fields).unwrap();
                let gindex = progressive_container_gindex(i).unwrap();
                let depth = branch.len();
                let index = gindex - (1 << depth);

                let mut corrupted = branch.clone();
                let node = &mut corrupted[i % depth];
                *node = H256::from(hash32_concat(node.as_slice(), node.as_slice()));

                verify_merkle_proof(roots[i], &branch, depth, index, root)
                    && !verify_merkle_proof(roots[i], &corrupted, depth, index, root)
            });

            prop_assert!(proofs_ok);
        }

        /// Check the recursive root against `tree_hash`'s streaming `ProgressiveMerkleHasher`.
        #[test]
        fn proptest_progressive_root_matches_tree_hash(
            int_leaves in proptest::collection::vec(any::<u64>(), 0..=350)
        ) {
            let roots: Vec<_> = int_leaves.into_iter().map(H256::from_low_u64_be).collect();

            let mut hasher = tree_hash::ProgressiveMerkleHasher::new();
            for root in &roots {
                hasher.write(root.as_slice()).unwrap();
            }

            prop_assert_eq!(progressive_root_from(&roots, 0).unwrap(), hasher.finish().unwrap());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    // Limit test depth to avoid generating huge trees. Depth 10 = 1024 max leaves.
    const TEST_MAX_DEPTH: usize = 10;

    fn merkle_leaves_strategy(max_depth: usize) -> impl Strategy<Value = (Vec<u64>, usize)> {
        (0..=max_depth).prop_flat_map(|depth| {
            let max_leaves = 2usize.pow(depth as u32);
            (
                proptest::collection::vec(any::<u64>(), 0..=max_leaves),
                Just(depth),
            )
        })
    }

    fn merkle_leaves_strategy_min_depth(
        max_depth: usize,
        min_depth: usize,
    ) -> impl Strategy<Value = (Vec<u64>, usize)> {
        (min_depth..=max_depth).prop_flat_map(|depth| {
            let max_leaves = 2usize.pow(depth as u32);
            (
                proptest::collection::vec(any::<u64>(), 0..=max_leaves),
                Just(depth),
            )
        })
    }

    proptest::proptest! {
        /// Check that we can:
        /// 1. Build a MerkleTree from arbitrary leaves and an arbitrary depth.
        /// 2. Generate valid proofs for all of the leaves of this MerkleTree.
        #[test]
        fn proptest_create_and_verify((int_leaves, depth) in merkle_leaves_strategy(TEST_MAX_DEPTH)) {
            let leaves: Vec<_> = int_leaves.into_iter().map(H256::from_low_u64_be).collect();
            let merkle_tree = MerkleTree::create(&leaves, depth);
            let merkle_root = merkle_tree.hash();

            let proofs_ok = (0..leaves.len()).all(|i| {
                let (leaf, branch) = merkle_tree
                    .generate_proof(i, depth)
                    .expect("should generate proof");
                leaf == leaves[i] && verify_merkle_proof(leaf, &branch, depth, i, merkle_root)
            });

            proptest::prop_assert!(proofs_ok);
        }

        #[test]
        fn proptest_push_leaf_and_verify((int_leaves, depth) in merkle_leaves_strategy_min_depth(TEST_MAX_DEPTH, 1)) {
            let leaves_iter = int_leaves.into_iter().map(H256::from_low_u64_be);
            let mut merkle_tree = MerkleTree::create(&[], depth);

            let proofs_ok = leaves_iter.enumerate().all(|(i, leaf)| {
                assert_eq!(merkle_tree.push_leaf(leaf, depth), Ok(()));
                let (stored_leaf, branch) = merkle_tree
                    .generate_proof(i, depth)
                    .expect("should generate proof");
                stored_leaf == leaf && verify_merkle_proof(leaf, &branch, depth, i, merkle_tree.hash())
            });

            proptest::prop_assert!(proofs_ok);
        }
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

        let node_b0x = H256::from_slice(&hash32_concat(leaf_b00.as_slice(), leaf_b01.as_slice()));
        let node_b1x = H256::from_slice(&hash32_concat(leaf_b10.as_slice(), leaf_b11.as_slice()));

        let root = H256::from_slice(&hash32_concat(node_b0x.as_slice(), node_b1x.as_slice()));

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

        let node_b0x = H256::from_slice(&hash32_concat(leaf_b00.as_slice(), leaf_b01.as_slice()));
        let node_b1x = H256::from_slice(&hash32_concat(leaf_b10.as_slice(), leaf_b11.as_slice()));

        let root = H256::from_slice(&hash32_concat(node_b0x.as_slice(), node_b1x.as_slice()));

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
