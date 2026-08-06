use context_deserialize::{ContextDeserialize, context_deserialize};
use educe::Educe;
use serde::{Deserialize, Deserializer, Serialize};
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use crate::{
    attestation::{
        IndexedAttestationBase, IndexedAttestationElectra, IndexedAttestationGloas,
        IndexedAttestationRef,
    },
    fork::ForkName,
};

#[superstruct(
    variants(Base, Electra, Gloas),
    variant_attributes(
        derive(Educe, Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash,),
        context_deserialize(ForkName),
        educe(PartialEq, Eq, Hash),
        cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary),),
    ),
    ref_attributes(derive(Debug))
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Serialize, Encode, Deserialize, TreeHash, Educe)]
#[educe(PartialEq, Eq, Hash)]
#[serde(untagged)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct AttesterSlashing {
    #[superstruct(flatten)]
    pub attestation_1: IndexedAttestation,
    #[superstruct(flatten)]
    pub attestation_2: IndexedAttestation,
}

/// This is a copy of the `AttesterSlashing` enum but with `Encode` and `Decode` derived
/// using the `union` behavior for the purposes of persistence on disk. We use a separate
/// type so that we don't accidentally use this non-spec encoding in consensus objects.
#[derive(Debug, Clone, Encode, Decode, Educe)]
#[educe(PartialEq, Eq, Hash)]
#[ssz(enum_behaviour = "union")]
pub enum AttesterSlashingOnDisk {
    Base(AttesterSlashingBase),
    Electra(AttesterSlashingElectra),
    Gloas(AttesterSlashingGloas),
}

#[derive(Debug, Clone, Encode)]
#[ssz(enum_behaviour = "union")]
pub enum AttesterSlashingRefOnDisk<'a> {
    Base(&'a AttesterSlashingBase),
    Electra(&'a AttesterSlashingElectra),
    Gloas(&'a AttesterSlashingGloas),
}

impl From<AttesterSlashing> for AttesterSlashingOnDisk {
    fn from(attester_slashing: AttesterSlashing) -> Self {
        match attester_slashing {
            AttesterSlashing::Base(attester_slashing) => Self::Base(attester_slashing),
            AttesterSlashing::Electra(attester_slashing) => Self::Electra(attester_slashing),
            AttesterSlashing::Gloas(attester_slashing) => Self::Gloas(attester_slashing),
        }
    }
}

impl From<AttesterSlashingOnDisk> for AttesterSlashing {
    fn from(attester_slashing: AttesterSlashingOnDisk) -> Self {
        match attester_slashing {
            AttesterSlashingOnDisk::Base(attester_slashing) => Self::Base(attester_slashing),
            AttesterSlashingOnDisk::Electra(attester_slashing) => Self::Electra(attester_slashing),
            AttesterSlashingOnDisk::Gloas(attester_slashing) => Self::Gloas(attester_slashing),
        }
    }
}

impl<'a> From<AttesterSlashingRefOnDisk<'a>> for AttesterSlashingRef<'a> {
    fn from(attester_slashing: AttesterSlashingRefOnDisk<'a>) -> Self {
        match attester_slashing {
            AttesterSlashingRefOnDisk::Base(attester_slashing) => Self::Base(attester_slashing),
            AttesterSlashingRefOnDisk::Electra(attester_slashing) => {
                Self::Electra(attester_slashing)
            }
            AttesterSlashingRefOnDisk::Gloas(attester_slashing) => Self::Gloas(attester_slashing),
        }
    }
}

impl<'a> From<AttesterSlashingRef<'a>> for AttesterSlashingRefOnDisk<'a> {
    fn from(attester_slashing: AttesterSlashingRef<'a>) -> Self {
        match attester_slashing {
            AttesterSlashingRef::Base(attester_slashing) => Self::Base(attester_slashing),
            AttesterSlashingRef::Electra(attester_slashing) => Self::Electra(attester_slashing),
            AttesterSlashingRef::Gloas(attester_slashing) => Self::Gloas(attester_slashing),
        }
    }
}

impl<'a> AttesterSlashingRef<'a> {
    pub fn clone_as_attester_slashing(self) -> AttesterSlashing {
        match self {
            AttesterSlashingRef::Base(attester_slashing) => {
                AttesterSlashing::Base(attester_slashing.clone())
            }
            AttesterSlashingRef::Electra(attester_slashing) => {
                AttesterSlashing::Electra(attester_slashing.clone())
            }
            AttesterSlashingRef::Gloas(attester_slashing) => {
                AttesterSlashing::Gloas(attester_slashing.clone())
            }
        }
    }

    pub fn attestation_1(&self) -> IndexedAttestationRef<'a> {
        match self {
            AttesterSlashingRef::Base(attester_slashing) => {
                IndexedAttestationRef::Base(&attester_slashing.attestation_1)
            }
            AttesterSlashingRef::Electra(attester_slashing) => {
                IndexedAttestationRef::Electra(&attester_slashing.attestation_1)
            }
            AttesterSlashingRef::Gloas(attester_slashing) => {
                IndexedAttestationRef::Gloas(&attester_slashing.attestation_1)
            }
        }
    }

    pub fn attestation_2(&self) -> IndexedAttestationRef<'a> {
        match self {
            AttesterSlashingRef::Base(attester_slashing) => {
                IndexedAttestationRef::Base(&attester_slashing.attestation_2)
            }
            AttesterSlashingRef::Electra(attester_slashing) => {
                IndexedAttestationRef::Electra(&attester_slashing.attestation_2)
            }
            AttesterSlashingRef::Gloas(attester_slashing) => {
                IndexedAttestationRef::Gloas(&attester_slashing.attestation_2)
            }
        }
    }
}

impl AttesterSlashing {
    pub fn attestation_1(&self) -> IndexedAttestationRef<'_> {
        match self {
            AttesterSlashing::Base(attester_slashing) => {
                IndexedAttestationRef::Base(&attester_slashing.attestation_1)
            }
            AttesterSlashing::Electra(attester_slashing) => {
                IndexedAttestationRef::Electra(&attester_slashing.attestation_1)
            }
            AttesterSlashing::Gloas(attester_slashing) => {
                IndexedAttestationRef::Gloas(&attester_slashing.attestation_1)
            }
        }
    }

    pub fn attestation_2(&self) -> IndexedAttestationRef<'_> {
        match self {
            AttesterSlashing::Base(attester_slashing) => {
                IndexedAttestationRef::Base(&attester_slashing.attestation_2)
            }
            AttesterSlashing::Electra(attester_slashing) => {
                IndexedAttestationRef::Electra(&attester_slashing.attestation_2)
            }
            AttesterSlashing::Gloas(attester_slashing) => {
                IndexedAttestationRef::Gloas(&attester_slashing.attestation_2)
            }
        }
    }
}

impl<'de> ContextDeserialize<'de, ForkName> for AttesterSlashing {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if context.gloas_enabled() {
            AttesterSlashingGloas::deserialize(deserializer)
                .map_err(serde::de::Error::custom)
                .map(AttesterSlashing::Gloas)
        } else if context.electra_enabled() {
            AttesterSlashingElectra::deserialize(deserializer)
                .map_err(serde::de::Error::custom)
                .map(AttesterSlashing::Electra)
        } else {
            AttesterSlashingBase::deserialize(deserializer)
                .map_err(serde::de::Error::custom)
                .map(AttesterSlashing::Base)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    mod base {
        use super::*;
        ssz_and_tree_hash_tests!(AttesterSlashingBase);
    }
    mod electra {
        use super::*;
        ssz_and_tree_hash_tests!(AttesterSlashingElectra);
    }
}
