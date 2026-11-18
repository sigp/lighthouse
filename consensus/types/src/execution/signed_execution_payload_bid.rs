use crate::execution::{ExecutionPayloadBidGloas, ExecutionPayloadBidHeze, ExecutionPayloadBidRef};
use crate::{
    ChainSpec, Epoch, EthSpec, ForkName, ForkVersionDecode, InconsistentFork, Slot, XmssSignature,
};
use bls::Signature;
use context_deserialize::{ContextDeserialize, context_deserialize};
use educe::Educe;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

/// An `ExecutionPayloadBid` and a signature from its builder.
#[superstruct(
    variants(Gloas, Pq, Heze),
    variant_attributes(
        derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, Educe),
        educe(PartialEq, Hash(bound(E: EthSpec))),
        serde(bound = "E: EthSpec"),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec"),
        ),
        context_deserialize(ForkName),
    )
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Encode, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[serde(bound = "E: EthSpec", untagged)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
// https://github.com/ethereum/consensus-specs/blob/master/specs/heze/beacon-chain.md#signedexecutionpayloadbid
pub struct SignedExecutionPayloadBid<E: EthSpec> {
    #[superstruct(only(Gloas), partial_getter(rename = "message_gloas"))]
    pub message: ExecutionPayloadBidGloas<E>,
    // The PQ spec modifies `SignedExecutionPayloadBid` (signature type) but not the inner bid.
    #[superstruct(only(Pq), partial_getter(rename = "message_pq"))]
    pub message: ExecutionPayloadBidGloas<E>,
    #[superstruct(only(Heze), partial_getter(rename = "message_heze"))]
    pub message: ExecutionPayloadBidHeze<E>,
    #[superstruct(only(Gloas, Heze))]
    pub signature: Signature,
    #[superstruct(only(Pq), partial_getter(rename = "signature_pq"))]
    pub signature: XmssSignature,
}

impl<E: EthSpec> SignedExecutionPayloadBid<E> {
    /// The bid message as a fork-agnostic reference.
    pub fn message(&self) -> ExecutionPayloadBidRef<'_, E> {
        match self {
            Self::Gloas(inner) => ExecutionPayloadBidRef::Gloas(&inner.message),
            Self::Pq(inner) => ExecutionPayloadBidRef::Gloas(&inner.message),
            Self::Heze(inner) => ExecutionPayloadBidRef::Heze(&inner.message),
        }
    }

    /// Returns the name of the fork pertaining to `self`.
    ///
    /// Will return an `Err` if `self` has been instantiated to a variant conflicting with the fork
    /// dictated by `self.slot()`.
    pub fn fork_name(&self, spec: &ChainSpec) -> Result<ForkName, InconsistentFork> {
        self.to_ref().fork_name(spec)
    }

    /// Returns the name of the fork pertaining to `self`.
    /// Does not check that the fork is consistent with the slot.
    pub fn fork_name_unchecked(&self) -> ForkName {
        self.to_ref().fork_name_unchecked()
    }

    pub fn slot(&self) -> crate::Slot {
        self.message().slot()
    }

    pub fn epoch(&self) -> crate::Epoch {
        self.slot().epoch(E::slots_per_epoch())
    }

    pub fn num_blobs_expected(&self) -> usize {
        self.message().blob_kzg_commitments().len()
    }
}

impl<E: EthSpec> SignedExecutionPayloadBidGloas<E> {
    pub fn empty() -> Self {
        Self {
            message: ExecutionPayloadBidGloas::default(),
            signature: Signature::empty(),
        }
    }
}

impl<E: EthSpec> SignedExecutionPayloadBidPq<E> {
    pub fn empty() -> Self {
        Self {
            message: ExecutionPayloadBidGloas::default(),
            signature: XmssSignature::empty(),
        }
    }
}

impl<E: EthSpec> SignedExecutionPayloadBidHeze<E> {
    pub fn empty() -> Self {
        Self {
            message: ExecutionPayloadBidHeze::default(),
            signature: Signature::empty(),
        }
    }
}

impl<'a, E: EthSpec> SignedExecutionPayloadBidRef<'a, E> {
    /// Returns the name of the fork pertaining to `self`.
    ///
    /// Will return an `Err` if `self` has been instantiated to a variant conflicting with the fork
    /// dictated by `self.slot()`.
    ///
    /// The check is made on the signed container's variant: the Pq variant wraps the same inner
    /// `ExecutionPayloadBidGloas` as the Gloas variant, so the inner bid alone cannot tell the two
    /// forks apart.
    pub fn fork_name(&self, spec: &ChainSpec) -> Result<ForkName, InconsistentFork> {
        let fork_at_slot = spec.fork_name_at_slot::<E>(self.slot());
        let object_fork = self.fork_name_unchecked();

        if fork_at_slot == object_fork {
            Ok(object_fork)
        } else {
            Err(InconsistentFork {
                fork_at_slot,
                object_fork,
            })
        }
    }

    /// Returns the name of the fork pertaining to `self`.
    /// Does not check that the fork is consistent with the slot.
    pub fn fork_name_unchecked(&self) -> ForkName {
        match self {
            SignedExecutionPayloadBidRef::Gloas(_) => ForkName::Gloas,
            SignedExecutionPayloadBidRef::Pq(_) => ForkName::Pq,
            SignedExecutionPayloadBidRef::Heze(_) => ForkName::Heze,
        }
    }

    pub fn slot(&self) -> Slot {
        self.message().slot()
    }

    pub fn epoch(&self) -> Epoch {
        self.slot().epoch(E::slots_per_epoch())
    }

    pub fn num_blobs_expected(&self) -> usize {
        self.message().blob_kzg_commitments().len()
    }

    /// The bid message as a fork-agnostic reference.
    pub fn message(&self) -> ExecutionPayloadBidRef<'a, E> {
        match self {
            SignedExecutionPayloadBidRef::Gloas(inner) => {
                ExecutionPayloadBidRef::Gloas(&inner.message)
            }
            SignedExecutionPayloadBidRef::Pq(inner) => {
                ExecutionPayloadBidRef::Gloas(&inner.message)
            }
            SignedExecutionPayloadBidRef::Heze(inner) => {
                ExecutionPayloadBidRef::Heze(&inner.message)
            }
        }
    }

    /// Clone this reference into an owned `SignedExecutionPayloadBid`.
    pub fn clone_as_signed_execution_payload_bid(self) -> SignedExecutionPayloadBid<E> {
        match self {
            SignedExecutionPayloadBidRef::Gloas(bid) => {
                SignedExecutionPayloadBid::Gloas(bid.clone())
            }
            SignedExecutionPayloadBidRef::Pq(bid) => SignedExecutionPayloadBid::Pq(bid.clone()),
            SignedExecutionPayloadBidRef::Heze(bid) => SignedExecutionPayloadBid::Heze(bid.clone()),
        }
    }
}

impl<E: EthSpec> ForkVersionDecode for SignedExecutionPayloadBid<E> {
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Base
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra
            | ForkName::Fulu => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for SignedExecutionPayloadBid: {fork_name}"
            ))),
            ForkName::Gloas => {
                SignedExecutionPayloadBidGloas::from_ssz_bytes(bytes).map(Self::Gloas)
            }
            ForkName::Pq => SignedExecutionPayloadBidPq::from_ssz_bytes(bytes).map(Self::Pq),
            ForkName::Heze => SignedExecutionPayloadBidHeze::from_ssz_bytes(bytes).map(Self::Heze),
        }
    }
}

impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for SignedExecutionPayloadBid<E> {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let convert_err = |e| {
            serde::de::Error::custom(format!(
                "SignedExecutionPayloadBid failed to deserialize: {:?}",
                e
            ))
        };
        Ok(match context {
            ForkName::Base
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra
            | ForkName::Fulu => {
                return Err(serde::de::Error::custom(format!(
                    "SignedExecutionPayloadBid failed to deserialize: unsupported fork '{}'",
                    context
                )));
            }
            ForkName::Gloas => {
                Self::Gloas(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Pq => Self::Pq(Deserialize::deserialize(deserializer).map_err(convert_err)?),
            ForkName::Heze => {
                Self::Heze(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
        })
    }
}

#[cfg(test)]
mod gloas_tests {
    use super::*;
    use crate::Spec;

    ssz_and_tree_hash_tests!(SignedExecutionPayloadBidGloas<Spec>);
}

#[cfg(test)]
mod pq_tests {
    use super::*;
    use crate::Spec;

    ssz_and_tree_hash_tests!(SignedExecutionPayloadBidPq<Spec>);
}

#[cfg(test)]
mod heze_tests {
    use super::*;
    use crate::Spec;

    ssz_and_tree_hash_tests!(SignedExecutionPayloadBidHeze<Spec>);
}
