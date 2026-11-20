use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::core::Hash256;

/// Summary of an SSZ `Vector[T, N]` field: its merkleization root.
///
/// Used by `BeaconStateSummary` to stand in for fixed-length `Vector` fields while preserving the
/// same `hash_tree_root`, the same way [`super::ListSummary`] stands in for `List` fields. Unlike
/// `ListSummary`, no length is stored: a `Vector`'s length `N` is a compile-time constant (via
/// `EthSpec`), and a `Vector`'s `hash_tree_root` (`merkleize(pack(items))`) has no
/// `mix_in_length` step, so `items_root` alone reproduces it exactly.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    Hash,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
)]
pub struct VectorSummary {
    pub items_root: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_hash::TreeHash;

    ssz_and_tree_hash_tests!(VectorSummary);

    /// `VectorSummary { items_root }.tree_hash_root()` must exactly equal `items_root` itself: a
    /// 1-field container merkleizes to its single field's root with no padding or extra hashing
    /// (a 1-leaf tree's root is that leaf), which is bit-for-bit the same as a real SSZ
    /// `Vector`'s `hash_tree_root`.
    #[test]
    fn equals_items_root() {
        for items_root in [
            Hash256::ZERO,
            Hash256::repeat_byte(0xab),
            Hash256::repeat_byte(0xff),
        ] {
            let summary = VectorSummary { items_root };
            assert_eq!(summary.tree_hash_root(), items_root);
        }
    }
}
