use crate::execution::ExecutionRequests;
use crate::{EthSpec, ExecutionPayloadEnvelope, ForkName, Hash256, SignedRoot};
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

/// Blinded form of [`ExecutionPayloadEnvelope`] with the `payload` field replaced by its hash
/// tree root.
///
/// The field order mirrors the full envelope, so both forms have the same hash tree root and a
/// signature over one form is valid over the other.
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Encode, Decode, Deserialize, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[context_deserialize(ForkName)]
#[serde(bound = "E: EthSpec")]
pub struct BlindedExecutionPayloadEnvelope<E: EthSpec> {
    pub payload_root: Hash256,
    pub execution_requests: ExecutionRequests<E>,
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_index: u64,
    pub beacon_block_root: Hash256,
    pub parent_beacon_block_root: Hash256,
}

impl<E: EthSpec> From<&ExecutionPayloadEnvelope<E>> for BlindedExecutionPayloadEnvelope<E> {
    fn from(envelope: &ExecutionPayloadEnvelope<E>) -> Self {
        Self {
            payload_root: envelope.payload.tree_hash_root(),
            execution_requests: envelope.execution_requests.clone(),
            builder_index: envelope.builder_index,
            beacon_block_root: envelope.beacon_block_root,
            parent_beacon_block_root: envelope.parent_beacon_block_root,
        }
    }
}

impl<E: EthSpec> SignedRoot for BlindedExecutionPayloadEnvelope<E> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExecutionPayloadGloas, MainnetEthSpec, Slot};

    ssz_and_tree_hash_tests!(BlindedExecutionPayloadEnvelope<MainnetEthSpec>);

    #[test]
    fn blinded_root_matches_full_root() {
        let envelope = ExecutionPayloadEnvelope::<MainnetEthSpec> {
            payload: ExecutionPayloadGloas {
                slot_number: Slot::new(42),
                ..ExecutionPayloadGloas::default()
            },
            execution_requests: ExecutionRequests::default(),
            builder_index: 7,
            beacon_block_root: Hash256::repeat_byte(1),
            parent_beacon_block_root: Hash256::repeat_byte(2),
        };
        let blinded = BlindedExecutionPayloadEnvelope::from(&envelope);

        assert_eq!(blinded.payload_root, envelope.payload.tree_hash_root());
        assert_eq!(blinded.tree_hash_root(), envelope.tree_hash_root());
    }
}
