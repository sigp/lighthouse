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
    pub validator_index: u64,
    pub fee_recipient: Address,
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
}
