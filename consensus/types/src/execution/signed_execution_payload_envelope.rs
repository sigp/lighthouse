use crate::test_utils::TestRandom;
use crate::{
    BeaconState, BeaconStateError, ChainSpec, Domain, Epoch, EthSpec, ExecutionBlockHash,
    ExecutionPayloadEnvelope, Fork, Hash256, SignedRoot, Slot,
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
    ///
    /// The `parent_state` is the post-state of the beacon block with
    /// block_root = self.message.beacon_block_root
    /// TODO(EIP-7732): maybe delete this function later (it is inefficient)
    pub fn verify_signature_with_state(
        &self,
        parent_state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<bool, BeaconStateError> {
        let proposer_index = parent_state.latest_block_header().proposer_index;
        let builder_index = self.message.builder_index(proposer_index) as usize;
        let domain = spec.get_domain(
            parent_state.current_epoch(),
            Domain::BeaconBuilder,
            &parent_state.fork(),
            parent_state.genesis_validators_root(),
        );
        let pubkey = parent_state
            .validators()
            .get(builder_index)
            .and_then(|v| {
                let pk: Option<PublicKey> = v.pubkey.decompress().ok();
                pk
            })
            .ok_or(BeaconStateError::UnknownValidator(builder_index))?;
        let message = self.message.signing_root(domain);

        Ok(self.signature.verify(&pubkey, message))
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
