use crate::test_utils::TestRandom;
use crate::{
    ChainSpec, Domain, Epoch, EthSpec, ExecutionBlockHash, ExecutionPayloadEnvelope, Fork, Hash256,
    SignedRoot, Slot,
};
use bls::{PublicKey, Signature};
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(Debug, Clone, Serialize, Encode, Decode, Deserialize, TestRandom, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[serde(bound = "E: EthSpec")]
pub struct SignedExecutionPayloadEnvelope<E: EthSpec> {
    pub message: ExecutionPayloadEnvelope<E>,
    pub signature: Signature,
}

impl<E: EthSpec> SignedExecutionPayloadEnvelope<E> {
    pub fn slot(&self) -> Slot {
        self.message.slot
    }

    pub fn epoch(&self) -> Epoch {
        self.slot().epoch(E::slots_per_epoch())
    }

    pub fn beacon_block_root(&self) -> Hash256 {
        self.message.beacon_block_root
    }

    pub fn block_hash(&self) -> ExecutionBlockHash {
        self.message.payload.block_hash
    }

    /// Verify `self.signature`.
    pub fn verify_signature(
        &self,
        pubkey: &PublicKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> bool {
        // Signed envelopes using the new BeaconBuilder domain per the spec:
        // https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/beacon-chain.md#new-verify_execution_payload_envelope_signature
        let domain = spec.get_domain(
            self.epoch(),
            Domain::BeaconBuilder,
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
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(SignedExecutionPayloadEnvelope<MainnetEthSpec>);
}
