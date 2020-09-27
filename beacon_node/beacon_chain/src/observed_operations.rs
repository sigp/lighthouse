use derivative::Derivative;
use parking_lot::Mutex;
use smallvec::SmallVec;
use ssz_derive::{Decode, Encode};
use state_processing::{SigVerifiedOp, VerifyOperation};
use std::collections::HashSet;
use std::iter::FromIterator;
use std::marker::PhantomData;
use types::{
    AttesterSlashing, BeaconState, ChainSpec, EthSpec, ProposerSlashing, SignedVoluntaryExit,
};

/// Number of validator indices to store on the stack in `observed_validators`.
pub const SMALL_VEC_SIZE: usize = 8;

#[derive(Encode, Decode)]
pub struct SszObservedOperations {
    observed_validator_indices: Vec<u64>,
}

#[derive(PartialEq, Debug)]
pub enum Error {} //to conform with other to/from_ssz_container routines in seen caches

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
    observed_validator_indices: Mutex<HashSet<u64>>,
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
        let attestation_1_indices =
            HashSet::<u64>::from_iter(self.attestation_1.attesting_indices.iter().copied());
        let attestation_2_indices =
            HashSet::<u64>::from_iter(self.attestation_2.attesting_indices.iter().copied());
        attestation_1_indices
            .intersection(&attestation_2_indices)
            .copied()
            .collect()
    }
}

impl<T: ObservableOperation<E>, E: EthSpec> ObservedOperations<T, E> {
    pub fn verify_and_observe(
        &self,
        op: T,
        head_state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<ObservationOutcome<T>, T::Error> {
        let mut observed_validator_indices = self.observed_validator_indices.lock();
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

    /// Returns a `SszObservedOperations`, which contains all necessary information to restore the state
    /// of `Self` at some later point.
    pub fn to_ssz_container(&self) -> SszObservedOperations {
        let cloned_set = (*self.observed_validator_indices.lock()).clone();

        let observed_validator_indices: Vec<u64> = Vec::from_iter(cloned_set);

        SszObservedOperations {
            observed_validator_indices,
        }
    }

    /// Creates a new `Self` from the given `SszObservedOperations`, restoring `Self` to the same state of
    /// the `Self` that created the `SszObservedOperations`.
    pub fn from_ssz_container(ssz_container: &SszObservedOperations) -> Result<Self, Error> {
        let observed_validator_indices =
            HashSet::from_iter(ssz_container.observed_validator_indices.clone());

        Ok(Self {
            observed_validator_indices: Mutex::new(observed_validator_indices),
            _phantom: PhantomData,
        })
    }
}

impl<T: ObservableOperation<E>, E: EthSpec> PartialEq<ObservedOperations<T, E>>
    for ObservedOperations<T, E>
{
    fn eq(&self, other: &ObservedOperations<T, E>) -> bool {
        (*self.observed_validator_indices.lock()).len()
            == (*other.observed_validator_indices.lock()).len()
    }
}

#[cfg(test)]
//#[cfg(not(debug_assertions))]
mod tests {
    use super::*;
    use crate::test_utils::BeaconChainHarness;
    use ssz::{Decode, Encode};
    use types::test_utils::TestingVoluntaryExitBuilder;
    use types::{MinimalEthSpec, Slot};

    #[test]
    fn store_round_trip() {
        let keys = types::test_utils::generate_deterministic_keypairs(1);
        let sk = keys[0].sk.clone();
        let mut harness = BeaconChainHarness::new(MinimalEthSpec, keys);

        let state = harness.get_current_state();
        let slots: Vec<Slot> = (1..2080 as usize).map(Into::into).collect();
        harness.add_attested_blocks_at_slots(state, &slots, &[0]);

        let state = harness.get_current_state();
        let spec = harness.chain.spec.clone();
        let operation = TestingVoluntaryExitBuilder::new(state.current_epoch(), 0).build(
            &sk,
            &state.fork,
            state.genesis_validators_root,
            &spec,
        );

        let store = ObservedOperations::default();
        store
            .verify_and_observe(operation, &state, &spec)
            .expect("accept the validator's exit");

        let bytes = store.to_ssz_container().as_ssz_bytes();

        assert_eq!(
            Ok(store),
            ObservedOperations::from_ssz_container(
                &SszObservedOperations::from_ssz_bytes(&bytes).expect("should decode")
            ),
            "store should encode/decode to/from SSZ container"
        )
    }
}
