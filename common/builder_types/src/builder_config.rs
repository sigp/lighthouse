use crate::{BuilderEntry, MaxBuilderEntries};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash_derive::TreeHash;

/// The resolved builder config the validator client sends on a block-production request, per
/// [beacon-APIs #630](https://github.com/ethereum/beacon-APIs/pull/630).
///
/// `builders` are the direct bid requests, each fully resolved. The top-level `min_bid` and
/// `builder_boost_factor` govern any bid that matches no entry — in practice, a bid received over
/// p2p.
///
/// SSZ container (field order per the spec — SSZ and tree-hash depend on it):
/// ```text
/// class BuilderConfig(Container):
///     min_bid: Gwei
///     builder_boost_factor: uint64
///     builders: List[BuilderEntry, MAX_BUILDER_ENTRIES]
/// ```
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct BuilderConfig {
    /// Minimum total payment (Gwei) accepted from a bid that matches no entry (a p2p bid).
    #[serde(with = "serde_utils::quoted_u64")]
    pub min_bid: u64,
    /// Percentage multiplier applied to a bid that matches no entry (a p2p bid).
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_boost_factor: u64,
    /// The builders to request bids from directly. Empty means only p2p bids are considered.
    pub builders: VariableList<BuilderEntry, MaxBuilderEntries>,
}

impl BuilderConfig {
    /// An empty config: no direct builders, with the documented compatibility defaults for the
    /// p2p bid policy (`min_bid = 0`, `builder_boost_factor = 100`).
    ///
    /// Sent when the validator has no builder support configured, so a Gloas proposal still falls
    /// back to local and p2p payloads.
    pub fn empty() -> Self {
        Self {
            min_bid: 0,
            builder_boost_factor: 100,
            builders: VariableList::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(BuilderConfig);

    #[test]
    fn json_shape() {
        let config = BuilderConfig {
            min_bid: 5,
            builder_boost_factor: 100,
            builders: VariableList::default(),
        };
        let json = serde_json::to_value(&config).unwrap();
        let obj = json.as_object().unwrap();
        // `builders` is a JSON array; the Gwei/uint64 fields are quoted strings.
        assert!(obj["builders"].is_array());
        assert_eq!(obj["min_bid"], "5");
        assert_eq!(obj["builder_boost_factor"], "100");

        assert_eq!(
            serde_json::from_value::<BuilderConfig>(json).unwrap(),
            config
        );
    }
}
