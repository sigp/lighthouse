use crate::{Address, ForkName, Hash256, SignedRoot, Slot};
use bls::Signature;
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

#[derive(Default, Debug, Clone, Serialize, Encode, Decode, Deserialize, TreeHash, Educe)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[educe(PartialEq, Hash)]
#[context_deserialize(ForkName)]
// https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/p2p-interface.md#new-proposerpreferences
pub struct ProposerPreferences {
    pub dependent_root: Hash256,
    pub proposal_slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub fee_recipient: Address,
    #[serde(with = "serde_utils::quoted_u64")]
    pub target_gas_limit: u64,
}

impl SignedRoot for ProposerPreferences {}

#[derive(TreeHash, Debug, Clone, Encode, Decode, Serialize, Deserialize, Educe)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[educe(PartialEq, Hash)]
#[context_deserialize(ForkName)]
// https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/p2p-interface.md#new-signedproposerpreferences
pub struct SignedProposerPreferences {
    pub message: ProposerPreferences,
    pub signature: Signature,
}

impl SignedProposerPreferences {
    pub fn empty() -> Self {
        Self {
            message: ProposerPreferences::default(),
            signature: Signature::empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(ProposerPreferences);

    /// `validator_index` and `target_gas_limit` must serialize as quoted JSON strings (Beacon API
    /// convention) and round-trip back to their numeric values.
    #[test]
    fn quoted_u64_json_serde() {
        let preferences = ProposerPreferences {
            dependent_root: Hash256::ZERO,
            proposal_slot: Slot::new(7),
            validator_index: 42,
            fee_recipient: Address::ZERO,
            target_gas_limit: 30_000_000,
        };

        let value = serde_json::to_value(&preferences).unwrap();
        assert_eq!(value["validator_index"], serde_json::json!("42"));
        assert_eq!(value["target_gas_limit"], serde_json::json!("30000000"));

        let decoded: ProposerPreferences = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, preferences);
    }
}
