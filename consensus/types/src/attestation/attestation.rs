use std::{
    collections::HashSet,
    hash::{Hash, Hasher},
};

use bls::{AggregateSignature, SecretKey, Signature};
use context_deserialize::{ContextDeserialize, context_deserialize};
use serde::{Deserialize, Deserializer, Serialize};
use ssz::ProgressiveBitList;
use ssz_derive::{Decode, Encode};
use ssz_types::{BitList, BitVector, ProgressiveVariableList};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;
use typenum::U;

use crate::{
    attestation::{
        AttestationData, Checkpoint, IndexedAttestation, IndexedAttestationBase,
        IndexedAttestationElectra, IndexedAttestationGloas,
    },
    core::{ChainSpec, Domain, Hash256, SignedRoot, Slot, SlotData, Spec},
    fork::{Fork, ForkName},
};

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    SszTypesError(ssz_types::Error),
    BitfieldError(ssz::BitfieldError),
    AlreadySigned(usize),
    IncorrectStateVariant,
    InvalidCommitteeLength,
    InvalidCommitteeIndex,
}

impl From<ssz_types::Error> for Error {
    fn from(e: ssz_types::Error) -> Self {
        Error::SszTypesError(e)
    }
}

#[superstruct(
    variants(Base, Electra, Gloas),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Decode,
            Encode,
            PartialEq,
            Hash,
            TreeHash,
        ),
        context_deserialize(ForkName),
        serde(deny_unknown_fields),
        cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary),)
    ),
    specific_variant_attributes(Gloas(tree_hash(
        struct_behaviour = "progressive_container",
        active_fields(1, 1, 1, 1)
    ))),
    ref_attributes(derive(TreeHash), tree_hash(enum_behaviour = "transparent")),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Serialize, TreeHash, Encode, PartialEq, Deserialize)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    #[superstruct(only(Base), partial_getter(rename = "aggregation_bits_base"))]
    pub aggregation_bits: BitList<U<{ Spec::MAX_VALIDATORS_PER_COMMITTEE }>>,
    #[superstruct(only(Electra), partial_getter(rename = "aggregation_bits_electra"))]
    pub aggregation_bits: BitList<U<{ Spec::MAX_VALIDATORS_PER_SLOT }>>,
    // [Modified in Gloas:EIP7688]
    #[superstruct(only(Gloas), partial_getter(rename = "aggregation_bits_gloas"))]
    pub aggregation_bits: ProgressiveBitList,
    pub data: AttestationData,
    pub signature: AggregateSignature,
    #[superstruct(only(Electra, Gloas))]
    pub committee_bits: BitVector<U<{ Spec::MAX_COMMITTEES_PER_SLOT }>>,
}

impl Hash for Attestation {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        match self {
            Attestation::Base(att) => att.hash(state),
            Attestation::Electra(att) => att.hash(state),
            Attestation::Gloas(att) => att.hash(state),
        }
    }
}

impl Attestation {
    /// Produces an attestation with empty signature.
    #[allow(clippy::too_many_arguments)]
    pub fn empty_for_signing(
        committee_index: u64,
        committee_length: usize,
        slot: Slot,
        beacon_block_root: Hash256,
        source: Checkpoint,
        target: Checkpoint,
        payload_present: bool,
        spec: &ChainSpec,
    ) -> Result<Self, Error> {
        if spec.fork_name_at_slot(slot).gloas_enabled() {
            let mut committee_bits: BitVector<U<{ Spec::MAX_COMMITTEES_PER_SLOT }>> =
                BitVector::default();
            committee_bits
                .set(committee_index as usize, true)
                .map_err(|_| Error::InvalidCommitteeIndex)?;
            // Gloas attestation data index now indicates payload presence.
            let index = if payload_present { 1u64 } else { 0u64 };
            Ok(Attestation::Gloas(AttestationGloas {
                // [Modified in Gloas:EIP7688]
                aggregation_bits: ProgressiveBitList::with_capacity(committee_length),
                data: AttestationData {
                    slot,
                    index,
                    beacon_block_root,
                    source,
                    target,
                },
                committee_bits,
                signature: AggregateSignature::infinity(),
            }))
        } else if spec.fork_name_at_slot(slot).electra_enabled() {
            let mut committee_bits: BitVector<U<{ Spec::MAX_COMMITTEES_PER_SLOT }>> =
                BitVector::default();
            committee_bits
                .set(committee_index as usize, true)
                .map_err(|_| Error::InvalidCommitteeIndex)?;
            Ok(Attestation::Electra(AttestationElectra {
                aggregation_bits: BitList::with_capacity(committee_length)
                    .map_err(|_| Error::InvalidCommitteeLength)?,
                data: AttestationData {
                    slot,
                    index: 0,
                    beacon_block_root,
                    source,
                    target,
                },
                committee_bits,
                signature: AggregateSignature::infinity(),
            }))
        } else {
            Ok(Attestation::Base(AttestationBase {
                aggregation_bits: BitList::with_capacity(committee_length)
                    .map_err(|_| Error::InvalidCommitteeLength)?,
                data: AttestationData {
                    slot,
                    index: committee_index,
                    beacon_block_root,
                    source,
                    target,
                },
                signature: AggregateSignature::infinity(),
            }))
        }
    }

    /// Aggregate another Attestation into this one.
    ///
    /// The aggregation bitfields must be disjoint, and the data must be the same.
    pub fn aggregate(&mut self, other: AttestationRef) {
        match self {
            Attestation::Base(att) => match other {
                AttestationRef::Base(oth) => {
                    att.aggregate(oth);
                }
                AttestationRef::Electra(_) | AttestationRef::Gloas(_) => {
                    debug_assert!(false, "Cannot aggregate attestations from different forks");
                }
            },
            Attestation::Electra(att) => match other {
                AttestationRef::Electra(oth) => {
                    att.aggregate(oth);
                }
                AttestationRef::Base(_) | AttestationRef::Gloas(_) => {
                    debug_assert!(false, "Cannot aggregate attestations from different forks");
                }
            },
            Attestation::Gloas(att) => match other {
                AttestationRef::Gloas(oth) => {
                    att.aggregate(oth);
                }
                AttestationRef::Base(_) | AttestationRef::Electra(_) => {
                    debug_assert!(false, "Cannot aggregate attestations from different forks");
                }
            },
        }
    }

    /// Signs `self`, setting the `committee_position`'th bit of `aggregation_bits` to `true`.
    ///
    /// Returns an `AlreadySigned` error if the `committee_position`'th bit is already `true`.
    pub fn sign(
        &mut self,
        secret_key: &SecretKey,
        committee_position: usize,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        match self {
            Attestation::Base(att) => att.sign(
                secret_key,
                committee_position,
                fork,
                genesis_validators_root,
                spec,
            ),
            Attestation::Electra(att) => att.sign(
                secret_key,
                committee_position,
                fork,
                genesis_validators_root,
                spec,
            ),
            Attestation::Gloas(att) => att.sign(
                secret_key,
                committee_position,
                fork,
                genesis_validators_root,
                spec,
            ),
        }
    }

    /// Returns an `AlreadySigned` error if the `committee_position`'th bit is already `true`.
    pub fn add_signature(
        &mut self,
        signature: &Signature,
        committee_position: usize,
    ) -> Result<(), Error> {
        match self {
            Attestation::Base(att) => att.add_signature(signature, committee_position),
            Attestation::Electra(att) => att.add_signature(signature, committee_position),
            Attestation::Gloas(att) => att.add_signature(signature, committee_position),
        }
    }

    pub fn committee_index(&self) -> Option<u64> {
        match self {
            Attestation::Base(att) => Some(att.data.index),
            Attestation::Electra(att) => att.committee_index(),
            Attestation::Gloas(att) => att.committee_index(),
        }
    }

    pub fn get_committee_indices_map(&self) -> HashSet<u64> {
        match self {
            Attestation::Base(att) => HashSet::from([att.data.index]),
            Attestation::Electra(att) => att.get_committee_indices().into_iter().collect(),
            Attestation::Gloas(att) => att.get_committee_indices().into_iter().collect(),
        }
    }

    pub fn is_aggregation_bits_zero(&self) -> bool {
        match self {
            Attestation::Base(att) => att.aggregation_bits.is_zero(),
            Attestation::Electra(att) => att.aggregation_bits.is_zero(),
            Attestation::Gloas(att) => att.aggregation_bits.is_zero(),
        }
    }

    pub fn num_set_aggregation_bits(&self) -> usize {
        match self {
            Attestation::Base(att) => att.aggregation_bits.num_set_bits(),
            Attestation::Electra(att) => att.aggregation_bits.num_set_bits(),
            Attestation::Gloas(att) => att.aggregation_bits.num_set_bits(),
        }
    }

    pub fn get_aggregation_bit(&self, index: usize) -> Result<bool, ssz::BitfieldError> {
        match self {
            Attestation::Base(att) => att.aggregation_bits.get(index),
            Attestation::Electra(att) => att.aggregation_bits.get(index),
            Attestation::Gloas(att) => att.aggregation_bits.get(index),
        }
    }

    pub fn set_aggregation_bit(
        &mut self,
        index: usize,
        value: bool,
    ) -> Result<(), ssz::BitfieldError> {
        match self {
            Attestation::Base(att) => att.aggregation_bits.set(index, value),
            Attestation::Electra(att) => att.aggregation_bits.set(index, value),
            Attestation::Gloas(att) => att.aggregation_bits.set(index, value),
        }
    }

    pub fn to_single_attestation_with_attester_index(
        &self,
        attester_index: u64,
    ) -> Result<SingleAttestation, Error> {
        match self {
            Self::Base(attn) => attn.to_single_attestation_with_attester_index(attester_index),
            Self::Electra(attn) => attn.to_single_attestation_with_attester_index(attester_index),
            Self::Gloas(attn) => attn.to_single_attestation_with_attester_index(attester_index),
        }
    }

    pub fn get_aggregation_bits(&self) -> Vec<u64> {
        match self {
            Self::Base(attn) => attn.get_aggregation_bits(),
            Self::Electra(attn) => attn.get_aggregation_bits(),
            Self::Gloas(attn) => attn.get_aggregation_bits(),
        }
    }
}

impl<'a> AttestationRefMut<'a> {
    /// Consuming variant of `data_mut` that ties the returned reference to the underlying
    /// attestation rather than to `self`, making it usable from closures.
    pub fn into_data_mut(self) -> &'a mut AttestationData {
        match self {
            Self::Base(att) => &mut att.data,
            Self::Electra(att) => &mut att.data,
            Self::Gloas(att) => &mut att.data,
        }
    }

    /// Consuming variant of `signature_mut`, see [`Self::into_data_mut`].
    pub fn into_signature_mut(self) -> &'a mut AggregateSignature {
        match self {
            Self::Base(att) => &mut att.signature,
            Self::Electra(att) => &mut att.signature,
            Self::Gloas(att) => &mut att.signature,
        }
    }
}

impl AttestationRef<'_> {
    pub fn clone_as_attestation(self) -> Attestation {
        match self {
            Self::Base(att) => Attestation::Base(att.clone()),
            Self::Electra(att) => Attestation::Electra(att.clone()),
            Self::Gloas(att) => Attestation::Gloas(att.clone()),
        }
    }

    pub fn is_aggregation_bits_zero(self) -> bool {
        match self {
            Self::Base(att) => att.aggregation_bits.is_zero(),
            Self::Electra(att) => att.aggregation_bits.is_zero(),
            Self::Gloas(att) => att.aggregation_bits.is_zero(),
        }
    }

    pub fn num_set_aggregation_bits(&self) -> usize {
        match self {
            Self::Base(att) => att.aggregation_bits.num_set_bits(),
            Self::Electra(att) => att.aggregation_bits.num_set_bits(),
            Self::Gloas(att) => att.aggregation_bits.num_set_bits(),
        }
    }

    pub fn committee_index(&self) -> Option<u64> {
        match self {
            AttestationRef::Base(att) => Some(att.data.index),
            AttestationRef::Electra(att) => att.committee_index(),
            AttestationRef::Gloas(att) => att.committee_index(),
        }
    }

    pub fn set_aggregation_bits(&self) -> Vec<usize> {
        match self {
            Self::Base(att) => att
                .aggregation_bits
                .iter()
                .enumerate()
                .filter(|(_i, bit)| *bit)
                .map(|(i, _bit)| i)
                .collect::<Vec<_>>(),
            Self::Electra(att) => att
                .aggregation_bits
                .iter()
                .enumerate()
                .filter(|(_i, bit)| *bit)
                .map(|(i, _bit)| i)
                .collect::<Vec<_>>(),
            Self::Gloas(att) => att
                .aggregation_bits
                .iter()
                .enumerate()
                .filter(|(_i, bit)| *bit)
                .map(|(i, _bit)| i)
                .collect::<Vec<_>>(),
        }
    }
}

impl AttestationElectra {
    pub fn committee_index(&self) -> Option<u64> {
        self.committee_bits
            .iter()
            .enumerate()
            .find(|&(_, bit)| bit)
            .map(|(index, _)| index as u64)
    }

    pub fn get_aggregation_bits(&self) -> Vec<u64> {
        self.aggregation_bits
            .iter()
            .enumerate()
            .filter_map(|(index, bit)| if bit { Some(index as u64) } else { None })
            .collect()
    }

    pub fn get_committee_indices(&self) -> Vec<u64> {
        self.committee_bits
            .iter()
            .enumerate()
            .filter_map(|(index, bit)| if bit { Some(index as u64) } else { None })
            .collect()
    }

    /// Aggregate another Attestation into this one.
    ///
    /// The aggregation bitfields must be disjoint, and the data must be the same.
    pub fn aggregate(&mut self, other: &Self) {
        debug_assert_eq!(self.data, other.data);
        self.aggregation_bits = self.aggregation_bits.union(&other.aggregation_bits);
        self.signature.add_assign_aggregate(&other.signature);
    }

    /// Signs `self`, setting the `committee_position`'th bit of `aggregation_bits` to `true`.
    ///
    /// Returns an `AlreadySigned` error if the `committee_position`'th bit is already `true`.
    pub fn sign(
        &mut self,
        secret_key: &SecretKey,
        committee_position: usize,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let domain = spec.get_domain(
            self.data.target.epoch,
            Domain::BeaconAttester,
            fork,
            genesis_validators_root,
        );
        let message = self.data.signing_root(domain);

        self.add_signature(&secret_key.sign(message), committee_position)
    }

    /// Adds `signature` to `self` and sets the `committee_position`'th bit of `aggregation_bits` to `true`.
    ///
    /// Returns an `AlreadySigned` error if the `committee_position`'th bit is already `true`.
    pub fn add_signature(
        &mut self,
        signature: &Signature,
        committee_position: usize,
    ) -> Result<(), Error> {
        if self
            .aggregation_bits
            .get(committee_position)
            .map_err(Error::BitfieldError)?
        {
            Err(Error::AlreadySigned(committee_position))
        } else {
            self.aggregation_bits
                .set(committee_position, true)
                .map_err(Error::BitfieldError)?;

            self.signature.add_assign(signature);

            Ok(())
        }
    }

    pub fn to_single_attestation_with_attester_index(
        &self,
        attester_index: u64,
    ) -> Result<SingleAttestation, Error> {
        let Some(committee_index) = self.committee_index() else {
            return Err(Error::InvalidCommitteeIndex);
        };

        Ok(SingleAttestation {
            committee_index,
            attester_index,
            data: self.data.clone(),
            signature: self.signature.clone(),
        })
    }
}

impl AttestationGloas {
    pub fn committee_index(&self) -> Option<u64> {
        self.committee_bits
            .iter()
            .enumerate()
            .find(|&(_, bit)| bit)
            .map(|(index, _)| index as u64)
    }

    pub fn get_aggregation_bits(&self) -> Vec<u64> {
        self.aggregation_bits
            .iter()
            .enumerate()
            .filter_map(|(index, bit)| if bit { Some(index as u64) } else { None })
            .collect()
    }

    pub fn get_committee_indices(&self) -> Vec<u64> {
        self.committee_bits
            .iter()
            .enumerate()
            .filter_map(|(index, bit)| if bit { Some(index as u64) } else { None })
            .collect()
    }

    /// Aggregate another Attestation into this one.
    ///
    /// The aggregation bitfields must be disjoint, and the data must be the same.
    pub fn aggregate(&mut self, other: &Self) {
        debug_assert_eq!(self.data, other.data);
        self.aggregation_bits = self.aggregation_bits.union(&other.aggregation_bits);
        self.signature.add_assign_aggregate(&other.signature);
    }

    /// Signs `self`, setting the `committee_position`'th bit of `aggregation_bits` to `true`.
    ///
    /// Returns an `AlreadySigned` error if the `committee_position`'th bit is already `true`.
    pub fn sign(
        &mut self,
        secret_key: &SecretKey,
        committee_position: usize,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let domain = spec.get_domain(
            self.data.target.epoch,
            Domain::BeaconAttester,
            fork,
            genesis_validators_root,
        );
        let message = self.data.signing_root(domain);

        self.add_signature(&secret_key.sign(message), committee_position)
    }

    /// Adds `signature` to `self` and sets the `committee_position`'th bit of `aggregation_bits`
    /// to `true`.
    ///
    /// Returns an `AlreadySigned` error if the `committee_position`'th bit is already `true`.
    pub fn add_signature(
        &mut self,
        signature: &Signature,
        committee_position: usize,
    ) -> Result<(), Error> {
        if self
            .aggregation_bits
            .get(committee_position)
            .map_err(Error::BitfieldError)?
        {
            Err(Error::AlreadySigned(committee_position))
        } else {
            self.aggregation_bits
                .set(committee_position, true)
                .map_err(Error::BitfieldError)?;

            self.signature.add_assign(signature);

            Ok(())
        }
    }

    pub fn to_single_attestation_with_attester_index(
        &self,
        attester_index: u64,
    ) -> Result<SingleAttestation, Error> {
        let Some(committee_index) = self.committee_index() else {
            return Err(Error::InvalidCommitteeIndex);
        };

        Ok(SingleAttestation {
            committee_index,
            attester_index,
            data: self.data.clone(),
            signature: self.signature.clone(),
        })
    }
}

impl AttestationBase {
    /// Aggregate another Attestation into this one.
    ///
    /// The aggregation bitfields must be disjoint, and the data must be the same.
    pub fn aggregate(&mut self, other: &Self) {
        debug_assert_eq!(self.data, other.data);
        self.aggregation_bits = self.aggregation_bits.union(&other.aggregation_bits);
        self.signature.add_assign_aggregate(&other.signature);
    }

    /// Signs `self`, setting the `committee_position`'th bit of `aggregation_bits` to `true`.
    ///
    /// Returns an `AlreadySigned` error if the `committee_position`'th bit is already `true`.
    pub fn sign(
        &mut self,
        secret_key: &SecretKey,
        committee_position: usize,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let domain = spec.get_domain(
            self.data.target.epoch,
            Domain::BeaconAttester,
            fork,
            genesis_validators_root,
        );
        let message = self.data.signing_root(domain);

        self.add_signature(&secret_key.sign(message), committee_position)
    }

    /// Adds `signature` to `self` and sets the `committee_position`'th bit of `aggregation_bits` to `true`.
    ///
    /// Returns an `AlreadySigned` error if the `committee_position`'th bit is already `true`.
    pub fn add_signature(
        &mut self,
        signature: &Signature,
        committee_position: usize,
    ) -> Result<(), Error> {
        if self
            .aggregation_bits
            .get(committee_position)
            .map_err(Error::BitfieldError)?
        {
            Err(Error::AlreadySigned(committee_position))
        } else {
            self.aggregation_bits
                .set(committee_position, true)
                .map_err(Error::BitfieldError)?;

            self.signature.add_assign(signature);

            Ok(())
        }
    }

    pub fn extend_aggregation_bits(
        &self,
    ) -> Result<BitList<U<{ Spec::MAX_VALIDATORS_PER_SLOT }>>, ssz::BitfieldError> {
        self.aggregation_bits
            .resize::<U<{ Spec::MAX_VALIDATORS_PER_SLOT }>>()
    }

    pub fn get_aggregation_bits(&self) -> Vec<u64> {
        self.aggregation_bits
            .iter()
            .enumerate()
            .filter_map(|(index, bit)| if bit { Some(index as u64) } else { None })
            .collect()
    }

    pub fn to_single_attestation_with_attester_index(
        &self,
        attester_index: u64,
    ) -> Result<SingleAttestation, Error> {
        Ok(SingleAttestation {
            committee_index: self.data.index,
            attester_index,
            data: self.data.clone(),
            signature: self.signature.clone(),
        })
    }
}

impl SlotData for Attestation {
    fn get_slot(&self) -> Slot {
        self.data().slot
    }
}

impl SlotData for AttestationRef<'_> {
    fn get_slot(&self) -> Slot {
        self.data().slot
    }
}

#[derive(Debug, Clone, Encode, Decode, PartialEq)]
#[ssz(enum_behaviour = "union")]
pub enum AttestationOnDisk {
    Base(AttestationBase),
    Electra(AttestationElectra),
    Gloas(AttestationGloas),
}

impl AttestationOnDisk {
    pub fn to_ref(&self) -> AttestationRefOnDisk<'_> {
        match self {
            AttestationOnDisk::Base(att) => AttestationRefOnDisk::Base(att),
            AttestationOnDisk::Electra(att) => AttestationRefOnDisk::Electra(att),
            AttestationOnDisk::Gloas(att) => AttestationRefOnDisk::Gloas(att),
        }
    }
}

#[derive(Debug, Clone, Encode)]
#[ssz(enum_behaviour = "union")]
pub enum AttestationRefOnDisk<'a> {
    Base(&'a AttestationBase),
    Electra(&'a AttestationElectra),
    Gloas(&'a AttestationGloas),
}

impl From<Attestation> for AttestationOnDisk {
    fn from(attestation: Attestation) -> Self {
        match attestation {
            Attestation::Base(attestation) => Self::Base(attestation),
            Attestation::Electra(attestation) => Self::Electra(attestation),
            Attestation::Gloas(attestation) => Self::Gloas(attestation),
        }
    }
}

impl From<AttestationOnDisk> for Attestation {
    fn from(attestation: AttestationOnDisk) -> Self {
        match attestation {
            AttestationOnDisk::Base(attestation) => Self::Base(attestation),
            AttestationOnDisk::Electra(attestation) => Self::Electra(attestation),
            AttestationOnDisk::Gloas(attestation) => Self::Gloas(attestation),
        }
    }
}

impl<'a> From<AttestationRef<'a>> for AttestationRefOnDisk<'a> {
    fn from(attestation: AttestationRef<'a>) -> Self {
        match attestation {
            AttestationRef::Base(attestation) => Self::Base(attestation),
            AttestationRef::Electra(attestation) => Self::Electra(attestation),
            AttestationRef::Gloas(attestation) => Self::Gloas(attestation),
        }
    }
}

impl<'a> From<AttestationRefOnDisk<'a>> for AttestationRef<'a> {
    fn from(attestation: AttestationRefOnDisk<'a>) -> Self {
        match attestation {
            AttestationRefOnDisk::Base(attestation) => Self::Base(attestation),
            AttestationRefOnDisk::Electra(attestation) => Self::Electra(attestation),
            AttestationRefOnDisk::Gloas(attestation) => Self::Gloas(attestation),
        }
    }
}

impl<'de> ContextDeserialize<'de, ForkName> for Attestation {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if context.gloas_enabled() {
            AttestationGloas::deserialize(deserializer)
                .map_err(serde::de::Error::custom)
                .map(Attestation::Gloas)
        } else if context.electra_enabled() {
            AttestationElectra::deserialize(deserializer)
                .map_err(serde::de::Error::custom)
                .map(Attestation::Electra)
        } else {
            AttestationBase::deserialize(deserializer)
                .map_err(serde::de::Error::custom)
                .map(Attestation::Base)
        }
    }
}

/*
impl<'de> ContextDeserialize<'de, ForkName> for Vec<Attestation> {
    fn context_deserialize<D>(
        deserializer: D,
        context: ForkName,
    ) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if context.electra_enabled() {
            <Vec<AttestationElectra>>::deserialize(deserializer)
                .map_err(serde::de::Error::custom)
                .map(|vec| vec.into_iter().map(Attestation::Electra).collect::<Vec<_>>())
        } else {
            <Vec<AttestationBase>>::deserialize(deserializer)
                .map_err(serde::de::Error::custom)
                .map(|vec| vec.into_iter().map(Attestation::Base).collect::<Vec<_>>())
        }
    }
}
*/

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Serialize, Deserialize, Decode, Encode, TreeHash, PartialEq)]
#[context_deserialize(ForkName)]
pub struct SingleAttestation {
    #[serde(with = "serde_utils::quoted_u64")]
    pub committee_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub attester_index: u64,
    pub data: AttestationData,
    pub signature: AggregateSignature,
}

impl SingleAttestation {
    pub fn to_indexed(&self, fork_name: ForkName) -> Result<IndexedAttestation, ssz_types::Error> {
        if fork_name.gloas_enabled() {
            Ok(IndexedAttestation::Gloas(IndexedAttestationGloas {
                attesting_indices: ProgressiveVariableList::new(vec![self.attester_index]),
                data: self.data.clone(),
                signature: self.signature.clone(),
            }))
        } else if fork_name.electra_enabled() {
            Ok(IndexedAttestation::Electra(IndexedAttestationElectra {
                attesting_indices: vec![self.attester_index].try_into()?,
                data: self.data.clone(),
                signature: self.signature.clone(),
            }))
        } else {
            Ok(IndexedAttestation::Base(IndexedAttestationBase {
                attesting_indices: vec![self.attester_index].try_into()?,
                data: self.data.clone(),
                signature: self.signature.clone(),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    // Check the in-memory size of an `Attestation`, which is useful for reasoning about memory
    // and preventing regressions.
    //
    // This test will only pass with `blst`, if we run these tests with another
    // BLS library in future we will have to make it generic.
    #[test]
    fn size_of_base() {
        use std::mem::size_of;

        let aggregation_bits = size_of::<BitList<U<{ Spec::MAX_VALIDATORS_PER_COMMITTEE }>>>();
        let attestation_data = size_of::<AttestationData>();
        let signature = size_of::<AggregateSignature>();

        assert_eq!(aggregation_bits, 144);
        assert_eq!(attestation_data, 128);
        assert_eq!(signature, 288 + 16);

        let attestation_expected = aggregation_bits + attestation_data + signature;
        assert_eq!(attestation_expected, 576);
        assert_eq!(size_of::<AttestationBase>(), attestation_expected);
    }

    #[test]
    fn size_of_electra() {
        use std::mem::size_of;

        let aggregation_bits = size_of::<BitList<U<{ Spec::MAX_VALIDATORS_PER_SLOT }>>>();
        let attestation_data = size_of::<AttestationData>();
        let committee_bits = size_of::<BitVector<U<{ Spec::MAX_COMMITTEES_PER_SLOT }>>>();
        let signature = size_of::<AggregateSignature>();

        assert_eq!(aggregation_bits, 144);
        assert_eq!(committee_bits, 144);
        assert_eq!(attestation_data, 128);
        assert_eq!(signature, 288 + 16);

        let attestation_expected = aggregation_bits + committee_bits + attestation_data + signature;
        assert_eq!(attestation_expected, 720);
        assert_eq!(size_of::<AttestationElectra>(), attestation_expected);
    }

    mod base {
        use super::*;
        ssz_and_tree_hash_tests!(AttestationBase);
    }
    mod electra {
        use super::*;
        ssz_and_tree_hash_tests!(AttestationElectra);
    }
}
