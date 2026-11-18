use std::{
    hash::{Hash, Hasher},
    slice::Iter,
};

use bls::AggregateSignature;
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::{ProgressiveVariableList, VariableList};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use crate::{
    attestation::{AttestationData, AttestationError},
    core::EthSpec,
    fork::ForkName,
    pq::AttestationProof,
};

/// Details an attestation that can be slashable.
///
/// To be included in an `AttesterSlashing`.
///
/// Spec v0.12.1
#[superstruct(
    variants(Base, Electra, Gloas, Pq),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Decode,
            Encode,
            Educe,
            TreeHash,
        ),
        context_deserialize(ForkName),
        educe(PartialEq, Hash(bound(E: EthSpec))),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec"),
        ),
    ),
    specific_variant_attributes(
        Gloas(tree_hash(
            struct_behaviour = "progressive_container",
            active_fields(1, 1, 1)
        )),
        // [Modified in Pq] `proof` takes the place of `signature`, so there is no gap.
        Pq(tree_hash(
            struct_behaviour = "progressive_container",
            active_fields(1, 1, 1)
        ))
    ),
    cast_error(
        ty = "AttestationError",
        expr = "AttestationError::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "AttestationError",
        expr = "AttestationError::IncorrectStateVariant"
    )
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, TreeHash, Encode, Educe, Deserialize)]
#[educe(PartialEq)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
pub struct IndexedAttestation<E: EthSpec> {
    /// Lists validator registry indices, not committee indices.
    #[superstruct(only(Base), partial_getter(rename = "attesting_indices_base"))]
    #[serde(with = "ssz_types::serde_utils::quoted_u64_var_list")]
    pub attesting_indices: VariableList<u64, E::MaxValidatorsPerCommittee>,
    #[superstruct(only(Electra), partial_getter(rename = "attesting_indices_electra"))]
    #[serde(with = "ssz_types::serde_utils::quoted_u64_var_list")]
    pub attesting_indices: VariableList<u64, E::MaxValidatorsPerSlot>,
    // [Modified in Gloas:EIP7688]
    #[superstruct(only(Gloas, Pq), partial_getter(rename = "attesting_indices_gloas"))]
    #[serde(with = "ssz_types::serde_utils::quoted_u64_var_list")]
    pub attesting_indices: ProgressiveVariableList<u64, E::MaxValidatorsPerSlot>,
    pub data: AttestationData,
    // [Modified in Pq] Removed `signature`.
    #[superstruct(only(Base, Electra, Gloas))]
    pub signature: AggregateSignature,
    // [New in Pq] A STARK proof of the XMSS signatures of the attesting indices.
    #[superstruct(only(Pq))]
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub proof: AttestationProof<E>,
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
        self.to_ref().attesting_indices_len()
    }

    pub fn attesting_indices_to_vec(&self) -> Vec<u64> {
        self.to_ref().attesting_indices_to_vec()
    }

    pub fn attesting_indices_is_empty(&self) -> bool {
        self.to_ref().attesting_indices_is_empty()
    }

    pub fn attesting_indices_iter(&self) -> Iter<'_, u64> {
        self.to_ref().attesting_indices_iter()
    }

    pub fn attesting_indices_first(&self) -> Option<&u64> {
        self.to_ref().attesting_indices_first()
    }

    /// Convert to the Electra variant. Errors for a Pq attestation, which has no BLS signature.
    pub fn to_electra(self) -> Result<IndexedAttestationElectra<E>, AttestationError> {
        match self {
            Self::Base(att) => {
                let extended_attesting_indices: VariableList<u64, E::MaxValidatorsPerSlot> =
                    VariableList::new(att.attesting_indices.to_vec())
                        .expect("MaxValidatorsPerSlot must be >= MaxValidatorsPerCommittee");
                // Note a unit test in consensus/types/src/eth_spec.rs asserts this invariant for
                // all known specs

                Ok(IndexedAttestationElectra {
                    attesting_indices: extended_attesting_indices,
                    data: att.data,
                    signature: att.signature,
                })
            }
            Self::Electra(att) => Ok(att),
            Self::Gloas(att) => {
                let attesting_indices: VariableList<u64, E::MaxValidatorsPerSlot> =
                    VariableList::new(att.attesting_indices.to_vec())?;

                Ok(IndexedAttestationElectra {
                    attesting_indices,
                    data: att.data,
                    signature: att.signature,
                })
            }
            Self::Pq(_) => Err(AttestationError::PqUnsupported(
                "a Pq IndexedAttestation has no BLS signature",
            )),
        }
    }

    /// Convert to the Gloas variant. Errors for a Pq attestation, which has no BLS signature.
    pub fn to_gloas(self) -> Result<IndexedAttestationGloas<E>, AttestationError> {
        let attesting_indices = ProgressiveVariableList::new(self.attesting_indices_to_vec())?;
        let (data, signature) = match self {
            Self::Base(att) => (att.data, att.signature),
            Self::Electra(att) => (att.data, att.signature),
            Self::Gloas(att) => return Ok(att),
            Self::Pq(_) => {
                return Err(AttestationError::PqUnsupported(
                    "a Pq IndexedAttestation has no BLS signature",
                ));
            }
        };
        Ok(IndexedAttestationGloas {
            attesting_indices,
            data,
            signature,
        })
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
        map_indexed_attestation_ref!(&'a _, self, |attestation, cons| {
            cons(attestation);
            attestation.attesting_indices.len()
        })
    }

    pub fn attesting_indices_to_vec(&self) -> Vec<u64> {
        map_indexed_attestation_ref!(&'a _, self, |attestation, cons| {
            cons(attestation);
            attestation.attesting_indices.to_vec()
        })
    }

    pub fn attesting_indices_is_empty(&self) -> bool {
        map_indexed_attestation_ref!(&'a _, self, |attestation, cons| {
            cons(attestation);
            attestation.attesting_indices.is_empty()
        })
    }

    pub fn attesting_indices_iter(&self) -> Iter<'a, u64> {
        map_indexed_attestation_ref!(&'a _, self, |attestation, cons| {
            cons(attestation);
            attestation.attesting_indices.iter()
        })
    }

    pub fn attesting_indices_first(&self) -> Option<&'a u64> {
        map_indexed_attestation_ref!(&'a _, self, |attestation, cons| {
            cons(attestation);
            attestation.attesting_indices.first()
        })
    }

    pub fn clone_as_indexed_attestation(self) -> IndexedAttestation<E> {
        map_indexed_attestation_ref!(&'a _, self, |attestation, cons| {
            cons(attestation);
            attestation.clone().into()
        })
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
            IndexedAttestation::Gloas(att) => att.attesting_indices.hash(state),
            IndexedAttestation::Pq(att) => att.attesting_indices.hash(state),
        };
        self.data().hash(state);
        match self {
            IndexedAttestation::Base(att) => att.signature.as_ssz_bytes().hash(state),
            IndexedAttestation::Electra(att) => att.signature.as_ssz_bytes().hash(state),
            IndexedAttestation::Gloas(att) => att.signature.as_ssz_bytes().hash(state),
            IndexedAttestation::Pq(att) => att.proof.hash(state),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Epoch, Spec};
    use arbitrary::Arbitrary;

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
        ssz_and_tree_hash_tests!(IndexedAttestationBase<Spec>);
    }
    mod electra {
        use super::*;
        ssz_and_tree_hash_tests!(IndexedAttestationElectra<Spec>);
    }

    fn create_indexed_attestation(
        target_epoch: u64,
        source_epoch: u64,
    ) -> IndexedAttestation<Spec> {
        let mut u = crate::test_utils::test_unstructured();
        let mut indexed_vote =
            IndexedAttestation::Base(IndexedAttestationBase::arbitrary(&mut u).unwrap());

        indexed_vote.data_mut().source.epoch = Epoch::new(source_epoch);
        indexed_vote.data_mut().target.epoch = Epoch::new(target_epoch);
        indexed_vote
    }
}
