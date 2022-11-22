use derivative::Derivative;
use smallvec::{smallvec, SmallVec};
use ssz::{Decode, Encode};
use state_processing::{SigVerifiedOp, VerifyOperation};
use std::collections::HashSet;
use std::marker::PhantomData;
use types::{
    AttesterSlashing, BeaconState, ChainSpec, EthSpec, ForkName, ProposerSlashing,
    SignedVoluntaryExit, Slot,
};

#[cfg(feature = "withdrawals-processing")]
use types::SignedBlsToExecutionChange;

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
    /// The name of the current fork. The default will be overwritten on first use.
    #[derivative(Default(value = "ForkName::Base"))]
    current_fork: ForkName,
    _phantom: PhantomData<(T, E)>,
}

/// Was the observed operation new and valid for further processing, or a useless duplicate?
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ObservationOutcome<T: Encode + Decode, E: EthSpec> {
    New(SigVerifiedOp<T, E>),
    AlreadyKnown,
}

/// Trait for operations which can be observed using `ObservedOperations`.
pub trait ObservableOperation<E: EthSpec>: VerifyOperation<E> + Sized {
    /// The set of validator indices involved in this operation.
    ///
    /// See the comment on `observed_validator_indices` above for detail.
    fn observed_validators(&self) -> SmallVec<[u64; SMALL_VEC_SIZE]>;
}

impl<E: EthSpec> ObservableOperation<E> for SignedVoluntaryExit {
    fn observed_validators(&self) -> SmallVec<[u64; SMALL_VEC_SIZE]> {
        smallvec![self.message.validator_index]
    }
}

impl<E: EthSpec> ObservableOperation<E> for ProposerSlashing {
    fn observed_validators(&self) -> SmallVec<[u64; SMALL_VEC_SIZE]> {
        smallvec![self.signed_header_1.message.proposer_index]
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

#[cfg(feature = "withdrawals-processing")]
impl<E: EthSpec> ObservableOperation<E> for SignedBlsToExecutionChange {
    fn observed_validators(&self) -> SmallVec<[u64; SMALL_VEC_SIZE]> {
        smallvec![self.message.validator_index]
    }
}

impl<T: ObservableOperation<E>, E: EthSpec> ObservedOperations<T, E> {
    pub fn verify_and_observe(
        &mut self,
        op: T,
        head_state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<ObservationOutcome<T, E>, T::Error> {
        self.reset_at_fork_boundary(head_state.slot(), spec);

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

    /// Reset the cache when crossing a fork boundary.
    ///
    /// This prevents an attacker from crafting a self-slashing which is only valid before the fork
    /// (e.g. using the Altair fork domain at a Bellatrix epoch), in order to prevent propagation of
    /// all other slashings due to the duplicate check.
    ///
    /// It doesn't matter if this cache gets reset too often, as we reset it on restart anyway and a
    /// false negative just results in propagation of messages which should have been ignored.
    ///
    /// In future we could check slashing relevance against the op pool itself, but that would
    /// require indexing the attester slashings in the op pool by validator index.
    fn reset_at_fork_boundary(&mut self, head_slot: Slot, spec: &ChainSpec) {
        let head_fork = spec.fork_name_at_slot::<E>(head_slot);
        if head_fork != self.current_fork {
            self.observed_validator_indices.clear();
            self.current_fork = head_fork;
        }
    }
}
