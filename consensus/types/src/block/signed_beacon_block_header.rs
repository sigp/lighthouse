use bls::{PublicKey, Signature};
use context_deserialize::{ContextDeserialize, context_deserialize};
use serde::{Deserialize, Deserializer, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use crate::{
    block::BeaconBlockHeader,
    core::{ChainSpec, Domain, EthSpec, Hash256, SignedRoot},
    fork::{Fork, ForkName, ForkVersionDecode},
    pq::XmssSignature,
    state::BeaconStateError,
};

/// A signed header of a `BeaconBlock`.
///
/// Spec v0.12.1
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
    ),
    cast_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    )
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, TreeHash)]
#[serde(untagged)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    #[superstruct(only(Base))]
    pub signature: Signature,
    #[superstruct(only(Pq), partial_getter(rename = "signature_pq"))]
    pub signature: XmssSignature,
}

impl ForkVersionDecode for SignedBeaconBlockHeader {
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork: ForkName) -> Result<Self, ssz::DecodeError> {
        if fork == ForkName::Pq {
            SignedBeaconBlockHeaderPq::from_ssz_bytes(bytes).map(Self::Pq)
        } else {
            SignedBeaconBlockHeaderBase::from_ssz_bytes(bytes).map(Self::Base)
        }
    }
}

impl<'de> ContextDeserialize<'de, ForkName> for SignedBeaconBlockHeader {
    fn context_deserialize<D: Deserializer<'de>>(
        deserializer: D,
        fork: ForkName,
    ) -> Result<Self, D::Error> {
        if fork == ForkName::Pq {
            SignedBeaconBlockHeaderPq::deserialize(deserializer).map(Self::Pq)
        } else {
            SignedBeaconBlockHeaderBase::deserialize(deserializer).map(Self::Base)
        }
    }
}

impl SignedBeaconBlockHeaderBase {
    /// Verify that this block header was signed by `pubkey`.
    pub fn verify_signature<E: EthSpec>(
        &self,
        pubkey: &PublicKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> bool {
        let domain = spec.get_domain(
            self.message.slot.epoch(E::slots_per_epoch()),
            Domain::BeaconProposer,
            fork,
            genesis_validators_root,
        );

        let message = self.message.signing_root(domain);

        self.signature.verify(pubkey, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod base {
        use super::*;
        ssz_and_tree_hash_tests!(SignedBeaconBlockHeaderBase);
    }

    mod pq {
        use super::*;
        ssz_and_tree_hash_tests!(SignedBeaconBlockHeaderPq);
    }
}
