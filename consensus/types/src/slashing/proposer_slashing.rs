use context_deserialize::{ContextDeserialize, context_deserialize};
use serde::{Deserialize, Deserializer, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use crate::{
    block::{SignedBeaconBlockHeaderBase, SignedBeaconBlockHeaderPq},
    fork::{ForkName, ForkVersionDecode},
};

/// Two conflicting proposals from the same proposer (validator).
#[superstruct(
    variants(Base, Pq),
    variant_attributes(
        derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            Hash,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash
        ),
        context_deserialize(ForkName),
        cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary)),
    )
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, TreeHash)]
#[serde(untagged)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct ProposerSlashing {
    #[superstruct(only(Base))]
    pub signed_header_1: SignedBeaconBlockHeaderBase,
    #[superstruct(only(Pq), partial_getter(rename = "signed_header_1_pq"))]
    pub signed_header_1: SignedBeaconBlockHeaderPq,
    #[superstruct(only(Base))]
    pub signed_header_2: SignedBeaconBlockHeaderBase,
    #[superstruct(only(Pq), partial_getter(rename = "signed_header_2_pq"))]
    pub signed_header_2: SignedBeaconBlockHeaderPq,
}

impl ProposerSlashing {
    /// Get proposer index, assuming slashing validity has already been checked.
    pub fn proposer_index(&self) -> u64 {
        match self {
            Self::Base(slashing) => slashing.proposer_index(),
            Self::Pq(slashing) => slashing.signed_header_1.message.proposer_index,
        }
    }
}

impl ProposerSlashingBase {
    /// Get proposer index, assuming slashing validity has already been checked.
    pub fn proposer_index(&self) -> u64 {
        self.signed_header_1.message.proposer_index
    }
}

impl ForkVersionDecode for ProposerSlashing {
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork: ForkName) -> Result<Self, ssz::DecodeError> {
        if fork == ForkName::Pq {
            ProposerSlashingPq::from_ssz_bytes(bytes).map(Self::Pq)
        } else {
            ProposerSlashingBase::from_ssz_bytes(bytes).map(Self::Base)
        }
    }
}

impl<'de> ContextDeserialize<'de, ForkName> for ProposerSlashing {
    fn context_deserialize<D: Deserializer<'de>>(
        deserializer: D,
        fork: ForkName,
    ) -> Result<Self, D::Error> {
        if fork == ForkName::Pq {
            ProposerSlashingPq::deserialize(deserializer).map(Self::Pq)
        } else {
            ProposerSlashingBase::deserialize(deserializer).map(Self::Base)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod base {
        use super::*;
        ssz_and_tree_hash_tests!(ProposerSlashingBase);
    }

    mod pq {
        use super::*;
        ssz_and_tree_hash_tests!(ProposerSlashingPq);
    }
}
