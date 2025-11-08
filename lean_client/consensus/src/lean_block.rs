use crate::attestation::{Attestation, Slot};
use lean_crypto::Signature;

use crate::lean_state::LeanState;
use milhouse::List;
use types::{EthSpec, VariableList};

use types::Hash256;
pub struct LeanBlock<E: EthSpec> {
    slot: Slot,
    proposer_index: u64,
    parent_root: Hash256,
    state_root: Hash256,
    body: LeanBlockBody<E>,
}

pub struct LeanBlockBody<E: EthSpec> {
    attestations: VariableList<Attestation, E::MaxAttestations>,
}

pub struct LeanBlockHeader {
    slot: Slot,
    proposer_index: u64,
    parent_root: Hash256,
    state_root: Hash256,
    body_root: Hash256,
}
pub struct LeanBlockWithAttestation<E: EthSpec> {
    block: Box<LeanBlock<E>>,
    proposer_attestation: Attestation,
}
pub struct SignedLeanBlockWithAttestation<E: EthSpec> {
    message: LeanBlockWithAttestation<E>,
    signature: List<Signature, E::ValidatorRegistryLimit>,
}

impl<E: EthSpec> SignedLeanBlockWithAttestation<E> {
    pub fn verify_signatures(self, parent_state: LeanState<E>) -> Result<(), String> {
        Ok(())
    }
}
