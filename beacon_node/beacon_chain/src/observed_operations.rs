use derivative::Derivative;
use smallvec::SmallVec;
use state_processing::{SigVerifiedOp, VerifyOperation};
use std::collections::HashSet;
use std::marker::PhantomData;
use types::{
    AttesterSlashing, BeaconState, ChainSpec, EthSpec, ProposerSlashing, SignedVoluntaryExit,
};

/// Number of validator indices to store on the stack in `observed_validators`.
pub const SMALL_VEC_SIZE: usize = 8;

/// Stateful tracker for exit/slashing operations seen on the network.
///
/// Implements the conditions for gossip verification of exits and slashings from the P2P spec.
#[derive(Debug, Derivative)]
#[derivative(Default(bound = "T: ObservableOperation<E>, E: EthSpec"))]
pub struct ObservedOperations<T: ObservableOperation<E>, E: EthSpec> {
    /// Indices of validators for whom we have already seen an instance of an operation `T`.
    ///
    /// For voluntary exits, this is the set of all `signed_voluntary_exit.message.validator_index`.
    /// For proposer slashings, this is the set of all `proposer_slashing.index`.
    /// For attester slashings, this is the set of all validators who would be slashed by
    /// previously seen attester slashings, i.e. those validators in the intersection of
    /// `attestation_1.attester_indices` and `attestation_2.attester_indices`.
    observed_validator_indices: HashSet<u64>,
    _phantom: PhantomData<(T, E)>,
}

/// Was the observed operation new and valid for further processing, or a useless duplicate?
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ObservationOutcome<T> {
    New(SigVerifiedOp<T>),
    AlreadyKnown,
}

/// Trait for exits and slashings which can be observed using `ObservedOperations`.
pub trait ObservableOperation<E: EthSpec>: VerifyOperation<E> + Sized {
    /// The set of validator indices involved in this operation.
    ///
    /// See the comment on `observed_validator_indices` above for detail.
    fn observed_validators(&self) -> SmallVec<[u64; SMALL_VEC_SIZE]>;
}

impl<E: EthSpec> ObservableOperation<E> for SignedVoluntaryExit {
    fn observed_validators(&self) -> SmallVec<[u64; SMALL_VEC_SIZE]> {
        std::iter::once(self.message.validator_index).collect()
    }
}

impl<E: EthSpec> ObservableOperation<E> for ProposerSlashing {
    fn observed_validators(&self) -> SmallVec<[u64; SMALL_VEC_SIZE]> {
        std::iter::once(self.signed_header_1.message.proposer_index).collect()
    }
}

impl<E: EthSpec> ObservableOperation<E> for AttesterSlashing<E> {
    fn observed_validators(&self) -> SmallVec<[u64; SMALL_VEC_SIZE]> {
        let attestation_1_indices = self
            .attestation_1
            .attesting_indices
            .iter()
            .copied()
            .collect::<HashSet<u64>>();
        let attestation_2_indices = self
            .attestation_2
            .attesting_indices
            .iter()
            .copied()
            .collect::<HashSet<u64>>();
        attestation_1_indices
            .intersection(&attestation_2_indices)
            .copied()
            .collect()
    }
}

impl<T: ObservableOperation<E>, E: EthSpec> ObservedOperations<T, E> {
    pub fn verify_and_observe(
        &mut self,
        op: T,
        head_state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<ObservationOutcome<T>, T::Error> {
        let observed_validator_indices = &mut self.observed_validator_indices;
        let new_validator_indices = op.observed_validators();

        // If all of the new validator indices have been previously observed, short-circuit
        // the validation. This implements the uniqueness check part of the spec, which for attester
        // slashings reads:
        //
        // At least one index in the intersection of the attesting indices of each attestation has
        // not yet been seen in any prior attester_slashing.
        if new_validator_indices
            .iter()
            .all(|index| observed_validator_indices.contains(index))
        {
            return Ok(ObservationOutcome::AlreadyKnown);
        }

        // Validate the op using operation-specific logic (`verify_attester_slashing`, etc).
        let verified_op = op.validate(head_state, spec)?;

        // Add the relevant indices to the set of known indices to prevent processing of duplicates
        // in the future.
        observed_validator_indices.extend(new_validator_indices);

        Ok(ObservationOutcome::New(verified_op))
    }
}
