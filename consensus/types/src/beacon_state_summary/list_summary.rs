use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::core::Hash256;

/// Summary of an SSZ `List[T, N]` field: its merkleization root and length.
///
/// Used by `BeaconStateSummary` to stand in for `List` fields of `BeaconState` while preserving
/// the same `hash_tree_root`.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Hash, Serialize, Deserialize, Encode, Decode,
    TreeHash,
)]
pub struct ListSummary {
    pub items_root: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub num_items: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_hash::TreeHash;

    ssz_and_tree_hash_tests!(ListSummary);

    /// `ListSummary { items_root, num_items }.tree_hash_root()` must exactly equal
    /// `mix_in_length(items_root, num_items)` — the same final step every real SSZ `List`'s
    /// `hash_tree_root` uses. This is the mathematical claim `ListSummary` depends on: a 2-field
    /// container merkleizes as `hash(field0_root, field1_root)`, which is bit-for-bit the same
    /// computation as `mix_in_length`'s `hash(items_root, length_as_a_chunk)`.
    #[test]
    fn matches_mix_in_length() {
        let cases = [
            (Hash256::ZERO, 0u64),
            (Hash256::repeat_byte(0xab), 1),
            (Hash256::repeat_byte(0xff), 12_345),
            (Hash256::repeat_byte(0x11), u64::MAX),
        ];

        for (items_root, num_items) in cases {
            let summary = ListSummary {
                items_root,
                num_items,
            };
            let expected = tree_hash::mix_in_length(&items_root, num_items as usize);
            assert_eq!(
                summary.tree_hash_root(),
                expected,
                "items_root={items_root:?}, num_items={num_items}"
            );
        }
    }
}
