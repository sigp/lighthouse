use super::Error;
use crate::beacon_chain::BeaconStore;
use crate::canonical_head::CanonicalHead;
use crate::execution_proof_verification::observed_execution_proofs::{
    ObservedExecutionProofs, ProofObservation,
};
use crate::shuffling_cache::{ShufflingCache, with_cached_shuffling};
use crate::validator_pubkey_cache::ValidatorPubkeyCache;
use crate::{BeaconChain, BeaconChainTypes};
use parking_lot::RwLock;
use proof_engine::{ProofEngine, ProofVerificationOutcome};
use std::sync::Arc;
use tree_hash::TreeHash;
use types::execution::SignedExecutionProof;
use types::{ChainSpec, Domain, EthSpec, Hash256, SignedRoot, Slot};

pub struct GossipVerificationContext<'a, T: BeaconChainTypes> {
    pub canonical_head: &'a CanonicalHead<T>,
    pub observed_execution_proofs: &'a RwLock<ObservedExecutionProofs>,
    pub validator_pubkey_cache: &'a RwLock<ValidatorPubkeyCache<T>>,
    pub shuffling_cache: &'a RwLock<ShufflingCache<T::EthSpec>>,
    pub store: &'a BeaconStore<T>,
    pub proof_engine: &'a Option<Arc<ProofEngine>>,
    pub spec: &'a ChainSpec,
    pub genesis_validators_root: Hash256,
}

/// A `SignedExecutionProof` that has been verified for propagation on the gossip network.
pub struct GossipVerifiedExecutionProof {
    pub proof: Arc<SignedExecutionProof>,
    pub block_slot: Slot,
}

impl GossipVerifiedExecutionProof {
    pub async fn new<T: BeaconChainTypes>(
        proof: Arc<SignedExecutionProof>,
        ctx: &GossipVerificationContext<'_, T>,
    ) -> Result<Self, Error> {
        // [REJECT] `proof.proof_data` is non-empty. The `MAX_PROOF_SIZE` upper bound is enforced
        // structurally by the SSZ type at decode.
        if proof.message.proof_data.is_empty() {
            return Err(Error::EmptyProofData);
        }

        let proof_root = proof.message.tree_hash_root();
        let block_root = proof.beacon_block_root();
        let proof_type = proof.proof_type();
        let validator_index = proof.validator_index;

        // [IGNORE] The referenced beacon block is known. Its slot determines the fork for the
        // signing domain.
        let proto_block = ctx
            .canonical_head
            .fork_choice_read_lock()
            .get_block(&block_root)
            .ok_or(Error::UnknownBlockRoot {
                beacon_block_root: block_root,
            })?;
        let block_slot = proto_block.slot;

        // [IGNORE] Deduplication rules, checked before any expensive work.
        match ctx
            .observed_execution_proofs
            .read()
            .check(
                proof_root,
                block_root,
                proof_type,
                validator_index,
                block_slot,
            )
            .map_err(Error::from)?
        {
            ProofObservation::ProofAlreadySeen => return Err(Error::ProofAlreadySeen),
            ProofObservation::ValidProofAlreadyKnown => return Err(Error::ValidProofAlreadyKnown),
            ProofObservation::DuplicateFromValidator => {
                return Err(Error::DuplicateFromValidator { validator_index });
            }
            ProofObservation::New => {}
        }

        // [REJECT] The validator is active at the epoch of the referenced block. The committee
        // cache is keyed by the block's shuffling id, so proofs for blocks on non-canonical
        // forks are judged against their own fork's active set without loading a state.
        let block_epoch = block_slot.epoch(T::EthSpec::slots_per_epoch());
        let is_active = with_cached_shuffling(
            ctx.canonical_head,
            ctx.shuffling_cache,
            ctx.store,
            ctx.spec,
            block_root,
            block_epoch,
            |cached_shuffling, _| {
                Ok::<_, Error>(
                    cached_shuffling
                        .committee_cache
                        .shuffled_position(validator_index as usize)
                        .is_some(),
                )
            },
        )?;
        if !is_active {
            return Err(Error::ValidatorNotActive { validator_index });
        }

        // [REJECT] The signature is valid with respect to the validator's public key.
        let fork_name = ctx.spec.fork_name_at_slot::<T::EthSpec>(block_slot);
        let domain = ctx.spec.compute_domain(
            Domain::ExecutionProof,
            ctx.spec.fork_version_for_name(fork_name),
            ctx.genesis_validators_root,
        );
        let signing_root = proof.message.signing_root(domain);
        {
            let pubkey_cache = ctx.validator_pubkey_cache.read();
            let pubkey = pubkey_cache
                .get(validator_index as usize)
                .ok_or(Error::UnknownValidatorIndex(validator_index))?;
            if !proof.signature.verify(pubkey, signing_root) {
                return Err(Error::InvalidSignature);
            }
        }

        // Only record the validator's attempt after the signature binds `validator_index`;
        // recording earlier would let unauthenticated messages suppress honest provers.
        if !ctx
            .observed_execution_proofs
            .write()
            .observe_signature_verified_proof(
                proof_root,
                block_root,
                proof_type,
                validator_index,
                block_slot,
            )
            .map_err(Error::from)?
        {
            // Lost a race against a concurrent copy of the same proof.
            return Err(Error::ProofAlreadySeen);
        }

        // [REJECT] The proof verifies via the proof engine.
        //
        // Proof verification is a fast crypto check against a localhost sidecar (and may be
        // embedded in-process in the future), so awaiting it here does not hold up the processor
        // significantly.
        let proof_engine = ctx.proof_engine.as_ref().ok_or(Error::ProofEngineMissing)?;
        match proof_engine
            .verify_execution_proof(&proof.message)
            .await
            .map_err(Error::ProofEngine)?
        {
            ProofVerificationOutcome::Invalid => return Err(Error::InvalidProof),
            ProofVerificationOutcome::Valid => {}
        }

        ctx.observed_execution_proofs
            .write()
            .observe_valid_proof(block_root, proof_type);
        Ok(Self { proof, block_slot })
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn execution_proof_gossip_verification_context(&self) -> GossipVerificationContext<'_, T> {
        GossipVerificationContext {
            canonical_head: &self.canonical_head,
            observed_execution_proofs: &self.observed_execution_proofs,
            validator_pubkey_cache: &self.validator_pubkey_cache,
            shuffling_cache: &self.shuffling_cache,
            store: &self.store,
            proof_engine: &self.proof_engine,
            spec: &self.spec,
            genesis_validators_root: self.genesis_validators_root,
        }
    }

    pub async fn verify_execution_proof_for_gossip(
        &self,
        proof: Arc<SignedExecutionProof>,
    ) -> Result<GossipVerifiedExecutionProof, Error> {
        GossipVerifiedExecutionProof::new(
            proof,
            &self.execution_proof_gossip_verification_context(),
        )
        .await
    }
}
