use crate::execution::{ExecutionPayloadBidGloas, ExecutionPayloadBidHeze, ExecutionPayloadBidRef};
use crate::{EthSpec, ForkName, ForkVersionDecode};
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
    variants(Gloas, Heze),
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
#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[serde(bound = "E: EthSpec", untagged)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
// https://github.com/ethereum/consensus-specs/blob/master/specs/heze/beacon-chain.md#signedexecutionpayloadbid
pub struct SignedExecutionPayloadBid<E: EthSpec> {
    #[superstruct(only(Gloas), partial_getter(rename = "message_gloas"))]
    pub message: ExecutionPayloadBidGloas<E>,
    #[superstruct(only(Heze), partial_getter(rename = "message_heze"))]
    pub message: ExecutionPayloadBidHeze<E>,
    pub signature: Signature,
}

impl<E: EthSpec> SignedExecutionPayloadBid<E> {
    /// The bid message as a fork-agnostic reference.
    pub fn message(&self) -> ExecutionPayloadBidRef<'_, E> {
        match self {
            Self::Gloas(inner) => ExecutionPayloadBidRef::Gloas(&inner.message),
            Self::Heze(inner) => ExecutionPayloadBidRef::Heze(&inner.message),
        }
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

impl<E: EthSpec> SignedExecutionPayloadBidHeze<E> {
    pub fn empty() -> Self {
        Self {
            message: ExecutionPayloadBidHeze::default(),
            signature: Signature::empty(),
        }
    }
}

impl<'a, E: EthSpec> SignedExecutionPayloadBidRef<'a, E> {
    /// The bid message as a fork-agnostic reference.
    pub fn message(&self) -> ExecutionPayloadBidRef<'a, E> {
        match self {
            SignedExecutionPayloadBidRef::Gloas(inner) => {
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
            SignedExecutionPayloadBidRef::Heze(bid) => SignedExecutionPayloadBid::Heze(bid.clone()),
        }
    }
}

impl<E: EthSpec> ForkVersionDecode for SignedExecutionPayloadBid<E> {
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Gloas => {
                SignedExecutionPayloadBidGloas::from_ssz_bytes(bytes).map(Self::Gloas)
            }
            ForkName::Heze => SignedExecutionPayloadBidHeze::from_ssz_bytes(bytes).map(Self::Heze),
            _ => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for SignedExecutionPayloadBid: {fork_name}"
            ))),
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
            ForkName::Gloas => {
                Self::Gloas(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Heze => {
                Self::Heze(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            _ => {
                return Err(serde::de::Error::custom(format!(
                    "SignedExecutionPayloadBid failed to deserialize: unsupported fork '{}'",
                    context
                )));
            }
        })
    }
}

#[cfg(test)]
mod gloas_tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(SignedExecutionPayloadBidGloas<MainnetEthSpec>);
}

#[cfg(test)]
mod heze_tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(SignedExecutionPayloadBidHeze<MainnetEthSpec>);
}
