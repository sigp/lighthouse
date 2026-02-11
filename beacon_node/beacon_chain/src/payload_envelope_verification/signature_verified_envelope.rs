use std::sync::Arc;

use state_processing::ConsensusContext;
use types::{BeaconState, Hash256, SignedExecutionPayloadEnvelope};

use crate::{BeaconChain, BeaconChainTypes, payload_envelope_verification::{EnvelopeError, MaybeAvailableEnvelope}};


/// A wrapper around a `SignedExecutionPayloadEnvelope` that indicates that all signatures (except the deposit
/// signatures) have been verified.
pub struct SignatureVerifiedEnvelope<T: BeaconChainTypes> {
    envelope: SignedExecutionPayloadEnvelope<T::EthSpec>,
    block_root: Hash256,
    state: Option<BeaconState<T::EthSpec>>,
    consensus_context: ConsensusContext<T::EthSpec>,
}


impl<T: BeaconChainTypes> SignatureVerifiedEnvelope<T> {
     pub fn new(
        envelope: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
        state: &mut BeaconState<T::EthSpec>,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Result<Self, EnvelopeError> {
        let is_signature_valid = envelope.verify_signature_with_state(state, &chain.spec)?;

        if !is_signature_valid {
            return Err(EnvelopeError::BadSignature)
        }

        Self {
            envelope,
            block_root,
            state
        }

        todo!()
    }
}