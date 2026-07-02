use crate::{BlindedExecutionPayloadEnvelope, EthSpec, ForkName};
use bls::Signature;
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

/// Signed form of [`BlindedExecutionPayloadEnvelope`].
///
/// The signature is produced over the hash tree root of the message, which matches the hash tree
/// root of the corresponding full `ExecutionPayloadEnvelope` by construction.
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Encode, Decode, Deserialize, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[serde(bound = "E: EthSpec")]
#[context_deserialize(ForkName)]
pub struct SignedBlindedExecutionPayloadEnvelope<E: EthSpec> {
    pub message: BlindedExecutionPayloadEnvelope<E>,
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(SignedBlindedExecutionPayloadEnvelope<MainnetEthSpec>);
}
