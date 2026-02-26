use crate::test_utils::TestRandom;
use crate::{
    BeaconState, BeaconStateError, ChainSpec, Domain, Epoch, EthSpec, ExecutionBlockHash,
    ExecutionPayloadEnvelope, Fork, ForkName, Hash256, SignedRoot, Slot,
    consts::gloas::BUILDER_INDEX_SELF_BUILD,
};
use bls::{PublicKey, Signature};
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(Debug, Clone, Serialize, Encode, Decode, Deserialize, TestRandom, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[serde(bound = "E: EthSpec")]
#[context_deserialize(ForkName)]
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

    /// Verify `self.signature` using keys drawn from the beacon state.
    pub fn verify_signature_with_state(
        &self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<bool, BeaconStateError> {
        let builder_index = self.message.builder_index;

        let pubkey_bytes = if builder_index == BUILDER_INDEX_SELF_BUILD {
            let validator_index = state.latest_block_header().proposer_index;
            state.get_validator(validator_index as usize)?.pubkey
        } else {
            state.get_builder(builder_index)?.pubkey
        };

        // TODO(gloas): Could use pubkey cache on state here, but it probably isn't worth
        // it because this function is rarely used. Almost always the envelope should be signature
        // verified prior to consensus code running.
        let pubkey = pubkey_bytes.decompress()?;

        // Ensure the state's epoch matches the message's epoch before determining the Fork.
        if self.epoch() != state.current_epoch() {
            return Err(BeaconStateError::SignedEnvelopeIncorrectEpoch {
                state_epoch: state.current_epoch(),
                envelope_epoch: self.epoch(),
            });
        }

        Ok(self.verify_signature(
            &pubkey,
            &state.fork(),
            state.genesis_validators_root(),
            spec,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(SignedExecutionPayloadEnvelope<MainnetEthSpec>);
}
