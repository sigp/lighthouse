//! Builds the `data`/`branch` halves of a `BeaconStatePart` for one chunk: the raw item bytes,
//! and a Merkle proof that the chunk's subtree is included in its field's full items root (what
//! `List`/`ProgressiveList::tree_hash_items_root()` returns). Not yet wired into an actual
//! `beacon_state_parts_by_range` handler (no caller exists in this crate yet), hence `#[allow(dead_code)]`
//! below; every function is exercised and verified correct by this module's own tests, which
//! reconstruct the root from a generated chunk + branch and check it against a real
//! `milhouse::List`/`ProgressiveList`'s `tree_hash_items_root()`.
#![allow(dead_code)]

use std::ops::Range;

use ethereum_hashing::hash32_concat;
use ssz::Encode;
use tree_hash::{Hash256, TreeHash, TreeHashType};

/// `hash(a, b)`, the one primitive every SSZ merkle structure (flat or progressive) is built
/// from.
fn hash_pair(a: &Hash256, b: &Hash256) -> Hash256 {
    Hash256::from(hash32_concat(a.as_slice(), b.as_slice()))
}

/// Precomputed zero-subtree roots: `zero_hashes[0]` is a zero leaf, `zero_hashes[d]` is the root
/// of an all-zero subtree of depth `d` (`2^d` zero leaves). Lets a proof reach an astronomically
/// large SSZ capacity (e.g. a list limit of 2^30) without ever materializing the padding.
fn zero_hashes(max_depth: usize) -> Vec<Hash256> {
    let mut zh = vec![Hash256::ZERO];
    for _ in 0..max_depth {
        let prev = *zh.last().expect("just pushed at least one entry");
        zh.push(hash_pair(&prev, &prev));
    }
    zh
}

/// The 32-byte merkle leaves for `items`, matching exactly what `MerkleHasher`/
/// `ProgressiveMerkleHasher` would stream internally: for `Basic` (packable) types, each item's
/// packed encoding is concatenated and split into 32-byte chunks; for everything else, one leaf
/// per item (`tree_hash_root()`).
fn item_leaves<T: TreeHash>(items: &[T]) -> Vec<Hash256> {
    match T::tree_hash_type() {
        TreeHashType::Basic => {
            let mut bytes = Vec::new();
            for item in items {
                bytes.extend_from_slice(&item.tree_hash_packed_encoding());
            }
            bytes
                .chunks(32)
                .map(|chunk| {
                    let mut leaf = [0u8; 32];
                    if let Some(dest) = leaf.get_mut(..chunk.len()) {
                        dest.copy_from_slice(chunk);
                    }
                    Hash256::from_slice(&leaf)
                })
                .collect()
        }
        TreeHashType::Container | TreeHashType::List | TreeHashType::Vector => {
            items.iter().map(|item| item.tree_hash_root()).collect()
        }
    }
}

/// Every level of a flat binary tree over `leaves`, zero-padded up to the next power of two.
/// `levels[0]` is the (padded) leaf level, `levels.last()` is the single-node root level.
fn flat_tree_levels(leaves: &[Hash256]) -> Vec<Vec<Hash256>> {
    let padded_len = leaves.len().max(1).next_power_of_two();
    let mut level: Vec<Hash256> = (0..padded_len)
        .map(|i| leaves.get(i).copied().unwrap_or(Hash256::ZERO))
        .collect();
    let mut levels = vec![level.clone()];
    while level.len() > 1 {
        level = level.chunks(2).map(hash_pair_chunk).collect();
        levels.push(level.clone());
    }
    levels
}

/// `hash_pair` over a 2-element chunk from `.chunks(2)`; always exactly 2 elements here, since
/// every level built by this module has a power-of-two length.
fn hash_pair_chunk(pair: &[Hash256]) -> Hash256 {
    match pair {
        [a, b] => hash_pair(a, b),
        [a] => hash_pair(a, a),
        [] => Hash256::ZERO,
        _ => unreachable!("chunks(2) never yields more than 2 elements"),
    }
}

/// The root and sibling path (bottom to top, standard merkle proof order) for the subtree
/// spanning leaves `[start, start + len)` of a tree built from `flat_tree_levels`. `start` must
/// be a multiple of `len`, and `len` must be a power of two.
fn flat_subtree_proof(
    levels: &[Vec<Hash256>],
    start: usize,
    len: usize,
) -> (Hash256, Vec<Hash256>) {
    let subtree_level = len.trailing_zeros() as usize;
    let mut index = start.checked_div(len.max(1)).unwrap_or(0);
    let subtree_root = levels
        .get(subtree_level)
        .and_then(|level| level.get(index))
        .copied()
        .expect("subtree_level/index are in bounds by construction");

    let mut siblings = Vec::new();
    let top = levels.len().saturating_sub(1);
    for level in levels.get(subtree_level..top).unwrap_or(&[]) {
        let sibling_index = index ^ 1;
        siblings.push(
            level
                .get(sibling_index)
                .copied()
                .expect("sibling_index is in bounds by construction"),
        );
        index = index.checked_div(2).unwrap_or(0);
    }
    (subtree_root, siblings)
}

/// Extra siblings needed to extend a proof from a subtree root over `real_capacity` leaves (a
/// power of two) up to a declared SSZ `full_capacity` (also a power of two, `>= real_capacity`).
/// Real data always starts at leaf 0, so the real subtree sits as the left child at every one of
/// these extra depths, with an all-zero sibling on the right each time.
fn pad_to_capacity(real_capacity: usize, full_capacity: usize) -> Vec<Hash256> {
    debug_assert!(full_capacity >= real_capacity);
    debug_assert!(real_capacity.is_power_of_two() && full_capacity.is_power_of_two());
    // The real subtree's own depth (it spans `real_capacity` leaves); each extension step's
    // sibling must span the SAME width as the node it's paired with at that step, which doubles
    // every step, so the siblings start at this depth and increase from there, not from a bare
    // zero leaf (depth 0) each time.
    let real_depth = real_capacity.max(1).trailing_zeros() as usize;
    let extra_depth = full_capacity
        .checked_div(real_capacity.max(1))
        .unwrap_or(1)
        .trailing_zeros() as usize;
    let total_depth = real_depth.saturating_add(extra_depth);
    let zh = zero_hashes(total_depth);
    (real_depth..total_depth)
        .map(|d| zh.get(d).copied().expect("d < total_depth == zh.len() - 1"))
        .collect()
}

/// `branch` for a chunk of a plain (non-progressive) `List` field: `[start, start + len)` of
/// `items`, proved against the field's full SSZ capacity (`capacity_items`, converted internally
/// to leaves via the item type's packing factor).
pub fn plain_list_chunk_branch<T: TreeHash>(
    items: &[T],
    capacity_items: usize,
    range: Range<usize>,
) -> Vec<Hash256> {
    let packing_factor = match T::tree_hash_type() {
        TreeHashType::Basic => T::tree_hash_packing_factor(),
        _ => 1,
    };
    let leaf_range_start = range.start.checked_div(packing_factor).unwrap_or(0);
    let leaf_range_len = range
        .len()
        .div_ceil(packing_factor)
        .max(1)
        .next_power_of_two();
    let full_capacity_leaves = capacity_items
        .div_ceil(packing_factor)
        .max(1)
        .next_power_of_two();

    let leaves = item_leaves(items);
    let levels = flat_tree_levels(&leaves);
    let real_capacity = levels.first().map_or(1, Vec::len);

    let (_subtree_root, mut branch) = flat_subtree_proof(&levels, leaf_range_start, leaf_range_len);
    branch.extend(pad_to_capacity(real_capacity, full_capacity_leaves));
    branch
}

/// Start/size (in leaves) of each `ProgressiveList` level that has at least one leaf, given the
/// field's total leaf count. Level `i` holds `4^i` leaves; this walks levels until they cover
/// `total_leaves`, so the last entry may be only partially real (zero-padded internally).
fn progressive_level_bounds(total_leaves: usize) -> Vec<(usize, usize)> {
    let mut bounds = Vec::new();
    let mut start = 0usize;
    let mut size = 1usize;
    while start < total_leaves {
        bounds.push((start, size));
        start = start.saturating_add(size);
        size = size.saturating_mul(4);
    }
    bounds
}

/// Each level's own full root (`L_i`), computed from that level's leaf slice, zero-padded to the
/// level's declared size (`4^i`) if it's the last, partial level.
fn progressive_level_roots(leaves: &[Hash256]) -> Vec<Hash256> {
    progressive_level_bounds(leaves.len())
        .into_iter()
        .map(|(start, size)| {
            let end = start.saturating_add(size).min(leaves.len());
            let level_leaves = leaves.get(start..end).unwrap_or(&[]);
            // A full level matches `size` exactly; a partial final level is zero-padded inside
            // `flat_tree_levels_fixed`, matching `size` since `size` is itself a power of two
            // and `level_leaves.len() <= size`.
            flat_tree_levels_fixed(level_leaves, size)
        })
        .collect()
}

/// Like `flat_tree_levels`, but padded to exactly `capacity` (not `leaves.len()`'s own next
/// power of two), returning just the root. Used for progressive levels, whose declared size
/// (`4^i`) may be larger than the real leaves present in a partial final level.
fn flat_tree_levels_fixed(leaves: &[Hash256], capacity: usize) -> Hash256 {
    let mut level: Vec<Hash256> = (0..capacity)
        .map(|i| leaves.get(i).copied().unwrap_or(Hash256::ZERO))
        .collect();
    while level.len() > 1 {
        level = level.chunks(2).map(hash_pair_chunk).collect();
    }
    level.first().copied().unwrap_or(Hash256::ZERO)
}

/// Folds `level_roots[from..]` the same way `ProgressiveMerkleHasher` folds trailing levels:
/// starting from `ZERO` (nothing deeper), combining from the deepest level backward. Returns
/// `ZERO` if there's nothing at or after `from`.
fn fold_levels_from(level_roots: &[Hash256], from: usize) -> Hash256 {
    let mut result = Hash256::ZERO;
    if from >= level_roots.len() {
        return result;
    }
    for root in level_roots.get(from..).unwrap_or(&[]).iter().rev() {
        result = hash_pair(root, &result);
    }
    result
}

/// `branch` for a chunk of a `ProgressiveList` field, local chunk index `local_chunk_index`
/// (`0` is the irregular folded first chunk; everything after is a round `items_per_chunk`-sized
/// slice). Proves the chunk against the field's full items root (what `List`/`ProgressiveList`'s
/// own `tree_hash_items_root()` getter returns, pre-`mix_in_length`), not the field's overall
/// `tree_hash_root()`, matching `ListSummary`'s own `{ items_root, num_items }` shape: a verifier
/// who already trusts the containing `BeaconStateSummary` already has `num_items`, so `branch`
/// only needs to cover the items_root half.
///
/// For the first chunk (`local_chunk_index == 0`): the chunk's own data *is* every item in every
/// folded level, so the verifier can recompute each folded level's root directly, no sibling
/// needed for them. The branch is always exactly one hash, standing in for "everything deeper
/// than the folded prefix" (`Hash256::ZERO` if the first chunk is the *only* chunk), since the
/// real algorithm always combines the deepest active level with something on its right, even
/// when that something is the zero placeholder for "no more data".
///
/// For a round chunk at level `m`: the verifier only has a slice of level `m`'s own items, not
/// the earlier levels' raw data, so it needs each earlier level's full root (`L_0..L_{m-1}`) as
/// explicit siblings, then the standard within-level binary-tree siblings for its own slice of
/// level `m`, then (if there's anything deeper than `m`) one more hash for that.
///
/// `first_chunk_size`/`items_per_chunk` are the field's own values (e.g.
/// `ChunkedField::Validators.first_chunk_size()`/`.items_per_chunk()`), passed as plain numbers
/// so this function stays independent of `ChunkedField` itself.
pub fn progressive_chunk_branch<T: TreeHash>(
    items: &[T],
    first_chunk_size: usize,
    items_per_chunk: usize,
    local_chunk_index: usize,
) -> Vec<Hash256> {
    let leaves = item_leaves(items);
    let level_roots = progressive_level_roots(&leaves);
    let packing_factor = match T::tree_hash_type() {
        TreeHashType::Basic => T::tree_hash_packing_factor(),
        _ => 1,
    };

    let packing_factor = packing_factor.max(1);
    if local_chunk_index == 0 {
        let first_chunk_leaves = first_chunk_size.checked_div(packing_factor).unwrap_or(0);
        let folded_levels = progressive_level_bounds(first_chunk_leaves).len();
        return vec![fold_levels_from(&level_roots, folded_levels)];
    }

    // Which level this round chunk lives in, and where within it.
    let first_chunk_leaves = first_chunk_size.checked_div(packing_factor).unwrap_or(0);
    let items_per_chunk_leaves = items_per_chunk.checked_div(packing_factor).unwrap_or(0);
    let chunk_start_leaf = first_chunk_leaves.saturating_add(
        local_chunk_index
            .saturating_sub(1)
            .saturating_mul(items_per_chunk_leaves),
    );

    let level_bounds = progressive_level_bounds(leaves.len());
    let (m, &(level_start, level_size)) = level_bounds
        .iter()
        .enumerate()
        .find(|&(_, &(start, size))| {
            chunk_start_leaf >= start && chunk_start_leaf < start.saturating_add(size)
        })
        .expect("a round chunk always falls within some level, by construction");

    // Standard binary-tree siblings within level m, for this chunk's slice of it.
    let level_end = level_start.saturating_add(level_size).min(leaves.len());
    let level_leaves = leaves.get(level_start..level_end).unwrap_or(&[]);
    let levels_within = flat_tree_levels(level_leaves_padded(level_leaves, level_size).as_slice());
    let local_start = chunk_start_leaf.saturating_sub(level_start);
    let local_len = items_per_chunk_leaves.min(level_size);
    let (_chunk_root, mut branch) = flat_subtree_proof(&levels_within, local_start, local_len);

    // Earlier levels' full roots, L_0..L_{m-1}, as explicit siblings (verifier has no raw data
    // for them).
    let mut chain_siblings: Vec<Hash256> = level_roots.get(..m).unwrap_or(&[]).to_vec();
    chain_siblings.reverse(); // closest-first: L_{m-1}, L_{m-2}, ..., L_0.
    branch.extend(chain_siblings);

    // Everything deeper than level m, folded into a single hash (ZERO if m is the deepest level
    // with any data at all), always pushed for a uniform verification format.
    branch.push(fold_levels_from(&level_roots, m.saturating_add(1)));

    branch
}

/// Pads `leaves` up to exactly `capacity` with zero leaves (capacity is always a power of two
/// here, a progressive level's declared `4^i` size).
fn level_leaves_padded(leaves: &[Hash256], capacity: usize) -> Vec<Hash256> {
    let mut padded = leaves.to_vec();
    padded.resize(capacity, Hash256::ZERO);
    padded
}

/// The raw SSZ-encoded bytes for `items[range]`, concatenated: the `data` half of a
/// `BeaconStatePart`.
pub fn chunk_data<T: Encode>(items: &[T], range: Range<usize>) -> Vec<u8> {
    items
        .get(range)
        .unwrap_or(&[])
        .iter()
        .flat_map(|item| item.as_ssz_bytes())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::FixedBytesExtended;
    use milhouse::{List, ProgressiveList};
    use typenum::U1024;

    /// Local re-implementation of `ChunkedField::num_chunks`/`chunk_range`'s math, parameterized
    /// directly rather than tied to the enum, so tests can use small, fast synthetic sizes
    /// instead of the real multi-thousand-item field constants.
    fn chunk_range(
        len: usize,
        first_chunk_size: usize,
        items_per_chunk: usize,
        i: usize,
    ) -> Option<Range<usize>> {
        if len == 0 {
            return None;
        }
        if i == 0 {
            return Some(0..first_chunk_size.min(len));
        }
        let start = first_chunk_size + (i - 1) * items_per_chunk;
        if start >= len {
            return None;
        }
        Some(start..(start + items_per_chunk).min(len))
    }

    /// Reconstructs a root from a chunk's own root and a standard bottom-up sibling path,
    /// using `index`'s parity at each step to know whether the sibling is on the left or right.
    /// Once `index` reaches 0 it stays 0, which correctly treats every remaining step as "we are
    /// the left child, sibling is zero-padding on the right", with no special-casing needed.
    fn fold_branch(mut node: Hash256, mut index: usize, siblings: &[Hash256]) -> Hash256 {
        for sibling in siblings {
            node = if index % 2 == 1 {
                hash_pair(sibling, &node)
            } else {
                hash_pair(&node, sibling)
            };
            index /= 2;
        }
        node
    }

    fn leaf_root<T: TreeHash>(items: &[T]) -> Hash256 {
        let leaves = item_leaves(items);
        *flat_tree_levels(&leaves).last().unwrap().first().unwrap()
    }

    #[test]
    fn plain_list_branch_reconstructs_real_items_root() {
        let capacity_items = 1024; // must match the `U1024` capacity used below
        for len in [0usize, 1, 3, 4, 7, 16, 33, 64] {
            let items: Vec<u64> = (0..len as u64).collect();
            let list = List::<u64, U1024>::new(items.clone()).unwrap();
            let expected = list.tree_hash_items_root();

            let items_per_chunk = 4;
            let mut i = 0;
            loop {
                let Some(range) = chunk_range(len, items_per_chunk, items_per_chunk, i) else {
                    break;
                };
                let chunk_items = &items[range.clone()];
                let branch = plain_list_chunk_branch(&items, capacity_items, range.clone());

                let packing_factor = u64::tree_hash_packing_factor();
                let leaf_start = range.start / packing_factor;
                let leaf_len = range.len().div_ceil(packing_factor).next_power_of_two();
                let chunk_root = leaf_root(chunk_items);
                let reconstructed = fold_branch(chunk_root, leaf_start / leaf_len, &branch);

                assert_eq!(
                    reconstructed, expected,
                    "len={len} chunk={i} range={range:?} mismatch"
                );
                i += 1;
            }
        }
    }

    #[test]
    fn progressive_branch_reconstructs_real_items_root_unpacked() {
        // Hash256 is TreeHashType::Vector (one leaf per item, no packing), exercising the
        // Container/List/Vector branch of item_leaves, matching real fields like Validators.
        let first_chunk_size = 5; // levels 0+1 folded (1 + 4 = 5), small and fast to test.
        let items_per_chunk = 4; // level 2 (16 items) onward splits into 4-item round chunks.

        for len in [0usize, 1, 2, 5, 6, 9, 20, 21, 25, 40] {
            let items: Vec<Hash256> = (0..len as u64)
                .map(|i| Hash256::from_low_u64_be(i + 1))
                .collect();
            let plist = ProgressiveList::<Hash256>::try_from(items.clone()).unwrap();
            let expected = plist.tree_hash_items_root();

            let mut i = 0;
            loop {
                let Some(range) = chunk_range(len, first_chunk_size, items_per_chunk, i) else {
                    break;
                };
                let branch = progressive_chunk_branch(&items, first_chunk_size, items_per_chunk, i);

                let reconstructed = if i == 0 {
                    // First chunk: recompute each folded level directly from its own data, then
                    // combine with the single "deeper" sibling.
                    let folded_items = &items[range.clone()];
                    let level_roots = progressive_level_roots(&item_leaves(folded_items));
                    let deeper = branch[0];
                    fold_levels_from_seed(&level_roots, deeper)
                } else {
                    // Round chunk: branch = [within-level siblings] ++ [chain siblings,
                    // L_{m-1}..L_0] ++ [deeper, 1 entry]. Figure out which level (m) and where
                    // within it this chunk sits, the same way progressive_chunk_branch does, to
                    // know where to split branch back apart.
                    let chunk_start_leaf = first_chunk_size + (i - 1) * items_per_chunk;
                    let level_bounds = progressive_level_bounds(len);
                    let (_m, &(level_start, level_size)) = level_bounds
                        .iter()
                        .enumerate()
                        .find(|&(_, &(start, size))| {
                            chunk_start_leaf >= start && chunk_start_leaf < start + size
                        })
                        .unwrap();
                    let local_start = chunk_start_leaf - level_start;
                    let local_len = items_per_chunk.min(level_size);
                    let within_len =
                        (local_len.trailing_zeros()..level_size.trailing_zeros()).len();

                    // Pad the chunk's real items up to its full nominal leaf width before
                    // hashing: the chunk's own `range` may be clipped short (trailing partial
                    // chunk), but the subtree it proves against is always the full nominal
                    // width, zero-padded, same as the production code's own padding.
                    let chunk_items = &items[range.clone()];
                    let mut chunk_leaves = item_leaves(chunk_items);
                    chunk_leaves.resize(local_len, Hash256::ZERO);
                    let chunk_root = *flat_tree_levels(&chunk_leaves)
                        .last()
                        .unwrap()
                        .first()
                        .unwrap();
                    let l_m =
                        fold_branch(chunk_root, local_start / local_len, &branch[..within_len]);

                    let deeper = *branch.last().unwrap();
                    let chain_siblings = &branch[within_len..branch.len() - 1]; // L_{m-1}..L_0
                    let mut result = hash_pair(&l_m, &deeper); // Chain_m = hash(L_m, deeper)
                    for sib in chain_siblings {
                        result = hash_pair(sib, &result);
                    }
                    result
                };

                assert_eq!(
                    reconstructed, expected,
                    "len={len} chunk={i} range={range:?} mismatch"
                );
                i += 1;
            }
        }
    }

    #[test]
    fn progressive_branch_reconstructs_real_items_root_packed() {
        // u64 is TreeHashType::Basic with packing_factor 4, exercising the packed path that
        // chunking.rs's `packing_factor` fix (see project memory) was specifically about.
        let packing_factor = 4usize;
        let first_chunk_size = 5 * packing_factor; // 5 leaves' worth of items (levels 0+1).
        let items_per_chunk = 4 * packing_factor; // 4 leaves' worth of items per round chunk.

        for len in [
            0usize, 1, 4, 16, 19, 20, 21, 36, 40, 64, 80, 83, 84, 85, 100,
        ] {
            let items: Vec<u64> = (0..len as u64).collect();
            let plist = ProgressiveList::<u64>::try_from(items.clone()).unwrap();
            let expected = plist.tree_hash_items_root();

            let first_chunk_leaves = first_chunk_size / packing_factor;
            let items_per_chunk_leaves = items_per_chunk / packing_factor;
            let total_leaves = len.div_ceil(packing_factor);

            let mut i = 0;
            loop {
                let Some(range) = chunk_range(len, first_chunk_size, items_per_chunk, i) else {
                    break;
                };
                let branch = progressive_chunk_branch(&items, first_chunk_size, items_per_chunk, i);

                let reconstructed = if i == 0 {
                    let folded_items = &items[range.clone()];
                    let level_roots = progressive_level_roots(&item_leaves(folded_items));
                    let deeper = branch[0];
                    fold_levels_from_seed(&level_roots, deeper)
                } else {
                    let chunk_start_leaf = first_chunk_leaves + (i - 1) * items_per_chunk_leaves;
                    let level_bounds = progressive_level_bounds(total_leaves);
                    let (_m, &(level_start, level_size)) = level_bounds
                        .iter()
                        .enumerate()
                        .find(|&(_, &(start, size))| {
                            chunk_start_leaf >= start && chunk_start_leaf < start + size
                        })
                        .unwrap();
                    let local_start = chunk_start_leaf - level_start;
                    let local_len = items_per_chunk_leaves.min(level_size);
                    let within_len =
                        (local_len.trailing_zeros()..level_size.trailing_zeros()).len();

                    let chunk_items = &items[range.clone()];
                    let mut chunk_leaves = item_leaves(chunk_items);
                    chunk_leaves.resize(local_len, Hash256::ZERO);
                    let chunk_root = *flat_tree_levels(&chunk_leaves)
                        .last()
                        .unwrap()
                        .first()
                        .unwrap();
                    let l_m =
                        fold_branch(chunk_root, local_start / local_len, &branch[..within_len]);

                    let deeper = *branch.last().unwrap();
                    let chain_siblings = &branch[within_len..branch.len() - 1];
                    let mut result = hash_pair(&l_m, &deeper);
                    for sib in chain_siblings {
                        result = hash_pair(sib, &result);
                    }
                    result
                };

                assert_eq!(
                    reconstructed, expected,
                    "len={len} chunk={i} range={range:?} mismatch"
                );
                i += 1;
            }
        }
    }

    /// Same as `fold_levels_from`, but starting from an explicit seed instead of `ZERO`.
    fn fold_levels_from_seed(level_roots: &[Hash256], seed: Hash256) -> Hash256 {
        let mut result = seed;
        for root in level_roots.iter().rev() {
            result = hash_pair(root, &result);
        }
        result
    }

    #[test]
    fn chunk_data_is_concatenated_ssz_bytes() {
        let items: Vec<u64> = vec![1, 2, 3, 4, 5];
        let data = chunk_data(&items, 1..4);
        let expected: Vec<u8> = items[1..4].iter().flat_map(|i| i.as_ssz_bytes()).collect();
        assert_eq!(data, expected);
        assert_eq!(data.len(), 3 * 8); // 3 u64s, 8 bytes each.
    }
}
