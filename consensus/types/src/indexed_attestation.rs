use crate::{test_utils::TestRandom, AggregateSignature, AttestationData, EthSpec, VariableList};
use core::slice::Iter;
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use std::hash::{Hash, Hasher};
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Details an attestation that can be slashable.
///
/// To be included in an `AttesterSlashing`.
///
/// Spec v0.12.1
#[superstruct(
    variants(Base, Electra),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Decode,
            Encode,
            TestRandom,
            Derivative,
            arbitrary::Arbitrary,
            TreeHash,
        ),
        derivative(PartialEq, Hash(bound = "E: EthSpec")),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec"),
    )
)]
#[derive(
    Debug,
    Clone,
    Serialize,
    TreeHash,
    Encode,
    Derivative,
    Deserialize,
    arbitrary::Arbitrary,
    PartialEq,
)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
#[arbitrary(bound = "E: EthSpec")]
pub struct IndexedAttestation<E: EthSpec> {
    /// Lists validator registry indices, not committee indices.
    #[superstruct(only(Base), partial_getter(rename = "attesting_indices_base"))]
    #[serde(with = "ssz_types::serde_utils::quoted_u64_var_list")]
    pub attesting_indices: VariableList<u64, E::MaxValidatorsPerCommittee>,
    #[superstruct(only(Electra), partial_getter(rename = "attesting_indices_electra"))]
    #[serde(with = "ssz_types::serde_utils::quoted_u64_var_list")]
    pub attesting_indices: VariableList<u64, E::MaxValidatorsPerSlot>,
    pub data: AttestationData,
    pub signature: AggregateSignature,
}

impl<E: EthSpec> IndexedAttestation<E> {
    /// Check if ``attestation_data_1`` and ``attestation_data_2`` have the same target.
    ///
    /// Spec v0.12.1
    pub fn is_double_vote(&self, other: &Self) -> bool {
        // reuse the ref implementation to ensure logic is the same
        self.to_ref().is_double_vote(other.to_ref())
    }

    /// Check if ``attestation_data_1`` surrounds ``attestation_data_2``.
    ///
    /// Spec v0.12.1
    pub fn is_surround_vote(&self, other: &Self) -> bool {
        // reuse the ref implementation to ensure logic is the same
        self.to_ref().is_surround_vote(other.to_ref())
    }

    pub fn attesting_indices_len(&self) -> usize {
        match self {
            IndexedAttestation::Base(att) => att.attesting_indices.len(),
            IndexedAttestation::Electra(att) => att.attesting_indices.len(),
        }
    }

    pub fn attesting_indices_to_vec(&self) -> Vec<u64> {
        match self {
            IndexedAttestation::Base(att) => att.attesting_indices.to_vec(),
            IndexedAttestation::Electra(att) => att.attesting_indices.to_vec(),
        }
    }

    pub fn attesting_indices_is_empty(&self) -> bool {
        match self {
            IndexedAttestation::Base(att) => att.attesting_indices.is_empty(),
            IndexedAttestation::Electra(att) => att.attesting_indices.is_empty(),
        }
    }

    pub fn attesting_indices_iter(&self) -> Iter<'_, u64> {
        match self {
            IndexedAttestation::Base(att) => att.attesting_indices.iter(),
            IndexedAttestation::Electra(att) => att.attesting_indices.iter(),
        }
    }

    pub fn attesting_indices_first(&self) -> Option<&u64> {
        match self {
            IndexedAttestation::Base(att) => att.attesting_indices.first(),
            IndexedAttestation::Electra(att) => att.attesting_indices.first(),
        }
    }

    pub fn to_electra(self) -> IndexedAttestationElectra<E> {
        match self {
            Self::Base(att) => {
                let extended_attesting_indices: VariableList<u64, E::MaxValidatorsPerSlot> =
                    VariableList::new(att.attesting_indices.to_vec())
                        .expect("MaxValidatorsPerSlot must be >= MaxValidatorsPerCommittee");
                // Note a unit test in consensus/types/src/eth_spec.rs asserts this invariant for
                // all known specs

                IndexedAttestationElectra {
                    attesting_indices: extended_attesting_indices,
                    data: att.data,
                    signature: att.signature,
                }
            }
            Self::Electra(att) => att,
        }
    }
}

impl<'a, E: EthSpec> IndexedAttestationRef<'a, E> {
    pub fn is_double_vote(&self, other: Self) -> bool {
        self.data().target.epoch == other.data().target.epoch && self.data() != other.data()
    }

    pub fn is_surround_vote(&self, other: Self) -> bool {
        self.data().source.epoch < other.data().source.epoch
            && other.data().target.epoch < self.data().target.epoch
    }

    pub fn attesting_indices_len(&self) -> usize {
        match self {
            IndexedAttestationRef::Base(att) => att.attesting_indices.len(),
            IndexedAttestationRef::Electra(att) => att.attesting_indices.len(),
        }
    }

    pub fn attesting_indices_to_vec(&self) -> Vec<u64> {
        match self {
            IndexedAttestationRef::Base(att) => att.attesting_indices.to_vec(),
            IndexedAttestationRef::Electra(att) => att.attesting_indices.to_vec(),
        }
    }

    pub fn attesting_indices_is_empty(&self) -> bool {
        match self {
            IndexedAttestationRef::Base(att) => att.attesting_indices.is_empty(),
            IndexedAttestationRef::Electra(att) => att.attesting_indices.is_empty(),
        }
    }

    pub fn attesting_indices_iter(&self) -> Iter<'_, u64> {
        match self {
            IndexedAttestationRef::Base(att) => att.attesting_indices.iter(),
            IndexedAttestationRef::Electra(att) => att.attesting_indices.iter(),
        }
    }

    pub fn attesting_indices_first(&self) -> Option<&u64> {
        match self {
            IndexedAttestationRef::Base(att) => att.attesting_indices.first(),
            IndexedAttestationRef::Electra(att) => att.attesting_indices.first(),
        }
    }

    pub fn clone_as_indexed_attestation(self) -> IndexedAttestation<E> {
        match self {
            IndexedAttestationRef::Base(att) => IndexedAttestation::Base(att.clone()),
            IndexedAttestationRef::Electra(att) => IndexedAttestation::Electra(att.clone()),
        }
    }
}

/// Implementation of non-crypto-secure `Hash`, for use with `HashMap` and `HashSet`.
///
/// Guarantees `att1 == att2 -> hash(att1) == hash(att2)`.
///
/// Used in the operation pool.
impl<E: EthSpec> Hash for IndexedAttestation<E> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            IndexedAttestation::Base(att) => att.attesting_indices.hash(state),
            IndexedAttestation::Electra(att) => att.attesting_indices.hash(state),
        };
        self.data().hash(state);
        self.signature().as_ssz_bytes().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slot_epoch::Epoch;
    use crate::test_utils::{SeedableRng, XorShiftRng};
    use crate::MainnetEthSpec;

    #[test]
    pub fn test_is_double_vote_true() {
        let indexed_vote_first = create_indexed_attestation(3, 1);
        let indexed_vote_second = create_indexed_attestation(3, 2);

        assert!(indexed_vote_first.is_double_vote(&indexed_vote_second))
    }

    #[test]
    pub fn test_is_double_vote_false() {
        let indexed_vote_first = create_indexed_attestation(1, 1);
        let indexed_vote_second = create_indexed_attestation(2, 1);

        assert!(!indexed_vote_first.is_double_vote(&indexed_vote_second));
    }

    #[test]
    pub fn test_is_surround_vote_true() {
        let indexed_vote_first = create_indexed_attestation(2, 1);
        let indexed_vote_second = create_indexed_attestation(1, 2);

        assert!(indexed_vote_first.is_surround_vote(&indexed_vote_second));
    }

    #[test]
    pub fn test_is_surround_vote_true_realistic() {
        let indexed_vote_first = create_indexed_attestation(4, 1);
        let indexed_vote_second = create_indexed_attestation(3, 2);

        assert!(indexed_vote_first.is_surround_vote(&indexed_vote_second));
    }

    #[test]
    pub fn test_is_surround_vote_false_source_epoch_fails() {
        let indexed_vote_first = create_indexed_attestation(2, 2);
        let indexed_vote_second = create_indexed_attestation(1, 1);

        assert!(!indexed_vote_first.is_surround_vote(&indexed_vote_second));
    }

    #[test]
    pub fn test_is_surround_vote_false_target_epoch_fails() {
        let indexed_vote_first = create_indexed_attestation(1, 1);
        let indexed_vote_second = create_indexed_attestation(2, 2);

        assert!(!indexed_vote_first.is_surround_vote(&indexed_vote_second));
    }

    mod base {
        use super::*;
        ssz_and_tree_hash_tests!(IndexedAttestationBase<MainnetEthSpec>);
    }
    mod electra {
        use super::*;
        ssz_and_tree_hash_tests!(IndexedAttestationElectra<MainnetEthSpec>);
    }

    fn create_indexed_attestation(
        target_epoch: u64,
        source_epoch: u64,
    ) -> IndexedAttestation<MainnetEthSpec> {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let mut indexed_vote =
            IndexedAttestation::Base(IndexedAttestationBase::random_for_test(&mut rng));

        indexed_vote.data_mut().source.epoch = Epoch::new(source_epoch);
        indexed_vote.data_mut().target.epoch = Epoch::new(target_epoch);
        indexed_vote
    }
}
