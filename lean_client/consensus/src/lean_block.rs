use crate::attestation::{Attestation, Slot};
use crate::lean_state::LeanState;
use crate::validator::ValidatorIndex;
use lean_crypto::Signature;
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use types::{EthSpec, Hash256};

#[derive(Debug, Clone, Encode, Decode, TreeHash)]
pub struct LeanBlock<E: EthSpec> {
    pub slot: Slot,
    pub proposer_index: u64,
    pub parent_root: Hash256,
    pub state_root: Hash256,
    pub body: LeanBlockBody<E>,
}

#[derive(Debug, Clone, Encode, Decode, TreeHash)]
pub struct LeanBlockBody<E: EthSpec> {
    pub attestations: VariableList<Attestation, E::ValidatorRegistryLimit>,
}

#[derive(Debug, Clone, Encode, Decode, TreeHash)]
pub struct LeanBlockHeader {
    pub slot: Slot,
    pub proposer_index: ValidatorIndex,
    pub parent_root: Hash256,
    pub state_root: Hash256,
    pub body_root: Hash256,
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct LeanBlockWithAttestation<E: EthSpec> {
    pub block: LeanBlock<E>,
    pub proposer_attestation: Attestation,
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct SignedLeanBlockWithAttestation<E: EthSpec> {
    pub message: LeanBlockWithAttestation<E>,
    pub signature: VariableList<Signature, E::ValidatorRegistryLimit>,
}

impl<E: EthSpec> SignedLeanBlockWithAttestation<E> {
    /// Verify all XMSS signatures in this signed block.
    ///
    /// This function ensures that every attestation included in the block
    /// (both on-chain attestations from the block body and the proposer's
    /// own attestation) is properly signed by the claimed validator using
    /// their registered XMSS public key.
    ///
    /// # Parameters
    /// - `parent_state`: The state at the parent block, used to retrieve
    ///   validator public keys and verify signatures.
    ///
    /// # Returns
    /// - `Ok(())` if all signatures are cryptographically valid
    /// - `Err(String)` if signature verification fails
    pub fn verify_signatures(&self, parent_state: &LeanState<E>) -> Result<(), String> {
        let block = &self.message.block;
        let signatures = &self.signature;

        // Combine all attestations that need verification:
        // 1. Block body attestations (from other validators)
        // 2. Proposer attestation (from the block producer)
        let mut all_attestations = Vec::new();
        all_attestations.extend(block.body.attestations.iter().cloned());
        all_attestations.push(self.message.proposer_attestation.clone());

        // Verify signature count matches attestation count
        if signatures.len() != all_attestations.len() {
            return Err(format!(
                "Number of signatures ({}) does not match number of attestations ({})",
                signatures.len(),
                all_attestations.len()
            ));
        }

        let validators = &parent_state.validators;

        // Verify each attestation signature
        for (attestation, _signature) in
            all_attestations.iter().zip(signatures.iter())
        {
            // Identify the validator who created this attestation
            let validator_id = attestation.validator_id as usize;

            // Ensure validator exists in the active set
            if validator_id >= validators.len() {
                return Err(format!(
                    "Validator index {} out of range (total validators: {})",
                    validator_id,
                    validators.len()
                ));
            }

            let validator = validators
                .get(validator_id)
                .ok_or_else(|| format!("Failed to get validator at index {}", validator_id))?;

            // Calculate the hash of the attestation message (this is what's signed)
            let message_hash = attestation.attestation_data.tree_hash_root();

            // Verify the signature
            let is_valid = lean_crypto::verify_signature(
                validator.get_pubkey(),
                message_hash.as_slice(),
                _signature,
                attestation.attestation_data.slot.0,
            )
            .map_err(|e| format!("Signature verification error: {}", e))?;

            if !is_valid {
                return Err(format!(
                    "Invalid signature for validator {} at slot {}",
                    validator_id, attestation.attestation_data.slot.0
                ));
            }
        }

        Ok(())
    }
}
