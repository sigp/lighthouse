use crate::execution::{ExecutionPayloadBidGloas, ExecutionPayloadBidHeze, ExecutionPayloadBidRef};
use crate::fork::ForkVersionDecode;
use crate::state::BeaconStateError;
use crate::{Epoch, EthSpec, ForkName};
use bls::Signature;
use context_deserialize::{ContextDeserialize, context_deserialize};
use educe::Educe;
use serde::{Deserialize, Deserializer, Serialize};
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

#[superstruct(
    variants(Gloas, Heze),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            Educe,
        ),
        educe(PartialEq, Hash(bound(E: EthSpec))),
        context_deserialize(ForkName),
        serde(bound = "E: EthSpec"),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec"),
        ),
    ),
    cast_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    map_ref_into(ExecutionPayloadBidRef)
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, TreeHash)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
pub struct SignedExecutionPayloadBid<E: EthSpec> {
    #[superstruct(flatten)]
    pub message: ExecutionPayloadBid<E>,
    pub signature: Signature,
}

impl<E: EthSpec> SignedExecutionPayloadBid<E> {
    pub fn message(&self) -> ExecutionPayloadBidRef<'_, E> {
        match self {
            Self::Gloas(inner) => ExecutionPayloadBidRef::Gloas(&inner.message),
            Self::Heze(inner) => ExecutionPayloadBidRef::Heze(&inner.message),
        }
    }

    pub fn epoch(&self) -> Epoch {
        self.message().slot().epoch(E::slots_per_epoch())
    }

    pub fn empty_gloas() -> Self {
        Self::Gloas(SignedExecutionPayloadBidGloas {
            message: ExecutionPayloadBidGloas::default(),
            signature: Signature::empty(),
        })
    }

    pub fn empty_heze() -> Self {
        Self::Heze(SignedExecutionPayloadBidHeze {
            message: ExecutionPayloadBidHeze::default(),
            signature: Signature::empty(),
        })
    }
}

impl<'a, E: EthSpec> SignedExecutionPayloadBidRef<'a, E> {
    pub fn message(&self) -> ExecutionPayloadBidRef<'a, E> {
        map_signed_execution_payload_bid_ref_into_execution_payload_bid_ref!(
            &'a _,
            *self,
            |inner, cons| { cons(&inner.message) }
        )
    }

    pub fn epoch(&self) -> Epoch {
        self.message().slot().epoch(E::slots_per_epoch())
    }

    pub fn to_owned(&self) -> SignedExecutionPayloadBid<E> {
        match self {
            Self::Gloas(inner) => SignedExecutionPayloadBid::Gloas((*inner).clone()),
            Self::Heze(inner) => SignedExecutionPayloadBid::Heze((*inner).clone()),
        }
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

impl<E: EthSpec> ForkVersionDecode for SignedExecutionPayloadBid<E> {
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Gloas => {
                <SignedExecutionPayloadBidGloas<E> as ssz::Decode>::from_ssz_bytes(bytes)
                    .map(Self::Gloas)
            }
            ForkName::Heze => {
                <SignedExecutionPayloadBidHeze<E> as ssz::Decode>::from_ssz_bytes(bytes)
                    .map(Self::Heze)
            }
            _ => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for SignedExecutionPayloadBid: {fork_name}",
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
        match context {
            ForkName::Heze => Ok(Self::Heze(
                Deserialize::deserialize(deserializer).map_err(convert_err)?,
            )),
            ForkName::Gloas => Ok(Self::Gloas(
                Deserialize::deserialize(deserializer).map_err(convert_err)?,
            )),
            _ => Err(serde::de::Error::custom(format!(
                "SignedExecutionPayloadBid failed to deserialize: unsupported fork '{}'",
                context
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    mod gloas {
        use super::*;
        ssz_and_tree_hash_tests!(SignedExecutionPayloadBidGloas<MainnetEthSpec>);
    }
    mod heze {
        use super::*;
        ssz_and_tree_hash_tests!(SignedExecutionPayloadBidHeze<MainnetEthSpec>);
    }
}
