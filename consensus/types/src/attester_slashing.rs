use crate::indexed_attestation::{
    IndexedAttestationBase, IndexedAttestationElectra, IndexedAttestationRef,
};
use crate::{test_utils::TestRandom, EthSpec};
use derivative::Derivative;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[superstruct(
    variants(Base, Electra),
    variant_attributes(
        derive(
            Derivative,
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            TestRandom,
            arbitrary::Arbitrary
        ),
        derivative(PartialEq, Eq, Hash(bound = "E: EthSpec")),
        serde(bound = "E: EthSpec"),
        arbitrary(bound = "E: EthSpec")
    ),
    ref_attributes(derive(Debug))
)]
#[derive(
    Debug, Clone, Serialize, Encode, Deserialize, TreeHash, Derivative, arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Eq, Hash(bound = "E: EthSpec"))]
#[serde(bound = "E: EthSpec", untagged)]
#[arbitrary(bound = "E: EthSpec")]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct AttesterSlashing<E: EthSpec> {
    #[superstruct(flatten)]
    pub attestation_1: IndexedAttestation<E>,
    #[superstruct(flatten)]
    pub attestation_2: IndexedAttestation<E>,
}

/// This is a copy of the `AttesterSlashing` enum but with `Encode` and `Decode` derived
/// using the `union` behavior for the purposes of persistence on disk. We use a separate
/// type so that we don't accidentally use this non-spec encoding in consensus objects.
#[derive(Debug, Clone, Encode, Decode, Derivative)]
#[derivative(PartialEq, Eq, Hash(bound = "E: EthSpec"))]
#[ssz(enum_behaviour = "union")]
pub enum AttesterSlashingOnDisk<E: EthSpec> {
    Base(AttesterSlashingBase<E>),
    Electra(AttesterSlashingElectra<E>),
}

#[derive(Debug, Clone, Encode)]
#[ssz(enum_behaviour = "union")]
pub enum AttesterSlashingRefOnDisk<'a, E: EthSpec> {
    Base(&'a AttesterSlashingBase<E>),
    Electra(&'a AttesterSlashingElectra<E>),
}

impl<E: EthSpec> From<AttesterSlashing<E>> for AttesterSlashingOnDisk<E> {
    fn from(attester_slashing: AttesterSlashing<E>) -> Self {
        match attester_slashing {
            AttesterSlashing::Base(attester_slashing) => Self::Base(attester_slashing),
            AttesterSlashing::Electra(attester_slashing) => Self::Electra(attester_slashing),
        }
    }
}

impl<E: EthSpec> From<AttesterSlashingOnDisk<E>> for AttesterSlashing<E> {
    fn from(attester_slashing: AttesterSlashingOnDisk<E>) -> Self {
        match attester_slashing {
            AttesterSlashingOnDisk::Base(attester_slashing) => Self::Base(attester_slashing),
            AttesterSlashingOnDisk::Electra(attester_slashing) => Self::Electra(attester_slashing),
        }
    }
}

impl<'a, E: EthSpec> From<AttesterSlashingRefOnDisk<'a, E>> for AttesterSlashingRef<'a, E> {
    fn from(attester_slashing: AttesterSlashingRefOnDisk<'a, E>) -> Self {
        match attester_slashing {
            AttesterSlashingRefOnDisk::Base(attester_slashing) => Self::Base(attester_slashing),
            AttesterSlashingRefOnDisk::Electra(attester_slashing) => {
                Self::Electra(attester_slashing)
            }
        }
    }
}

impl<'a, E: EthSpec> From<AttesterSlashingRef<'a, E>> for AttesterSlashingRefOnDisk<'a, E> {
    fn from(attester_slashing: AttesterSlashingRef<'a, E>) -> Self {
        match attester_slashing {
            AttesterSlashingRef::Base(attester_slashing) => Self::Base(attester_slashing),
            AttesterSlashingRef::Electra(attester_slashing) => Self::Electra(attester_slashing),
        }
    }
}

impl<'a, E: EthSpec> AttesterSlashingRef<'a, E> {
    pub fn clone_as_attester_slashing(self) -> AttesterSlashing<E> {
        match self {
            AttesterSlashingRef::Base(attester_slashing) => {
                AttesterSlashing::Base(attester_slashing.clone())
            }
            AttesterSlashingRef::Electra(attester_slashing) => {
                AttesterSlashing::Electra(attester_slashing.clone())
            }
        }
    }

    pub fn attestation_1(&self) -> IndexedAttestationRef<'a, E> {
        match self {
            AttesterSlashingRef::Base(attester_slashing) => {
                IndexedAttestationRef::Base(&attester_slashing.attestation_1)
            }
            AttesterSlashingRef::Electra(attester_slashing) => {
                IndexedAttestationRef::Electra(&attester_slashing.attestation_1)
            }
        }
    }

    pub fn attestation_2(&self) -> IndexedAttestationRef<'a, E> {
        match self {
            AttesterSlashingRef::Base(attester_slashing) => {
                IndexedAttestationRef::Base(&attester_slashing.attestation_2)
            }
            AttesterSlashingRef::Electra(attester_slashing) => {
                IndexedAttestationRef::Electra(&attester_slashing.attestation_2)
            }
        }
    }
}

impl<E: EthSpec> AttesterSlashing<E> {
    pub fn attestation_1(&self) -> IndexedAttestationRef<E> {
        match self {
            AttesterSlashing::Base(attester_slashing) => {
                IndexedAttestationRef::Base(&attester_slashing.attestation_1)
            }
            AttesterSlashing::Electra(attester_slashing) => {
                IndexedAttestationRef::Electra(&attester_slashing.attestation_1)
            }
        }
    }

    pub fn attestation_2(&self) -> IndexedAttestationRef<E> {
        match self {
            AttesterSlashing::Base(attester_slashing) => {
                IndexedAttestationRef::Base(&attester_slashing.attestation_2)
            }
            AttesterSlashing::Electra(attester_slashing) => {
                IndexedAttestationRef::Electra(&attester_slashing.attestation_2)
            }
        }
    }
}

impl<E: EthSpec> TestRandom for AttesterSlashing<E> {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        if rng.gen_bool(0.5) {
            AttesterSlashing::Base(AttesterSlashingBase::random_for_test(rng))
        } else {
            AttesterSlashing::Electra(AttesterSlashingElectra::random_for_test(rng))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    mod base {
        use super::*;
        ssz_and_tree_hash_tests!(AttesterSlashingBase<MainnetEthSpec>);
    }
    mod electra {
        use super::*;
        ssz_and_tree_hash_tests!(AttesterSlashingElectra<MainnetEthSpec>);
    }
}
