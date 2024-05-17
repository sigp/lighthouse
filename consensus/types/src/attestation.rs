use crate::slot_data::SlotData;
use crate::{test_utils::TestRandom, Hash256, Slot};
use derivative::Derivative;
use safe_arith::ArithError;
use serde::{Deserialize, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::BitVector;
use std::hash::{Hash, Hasher};
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

use super::{
    AggregateSignature, AttestationData, BitList, ChainSpec, Domain, EthSpec, Fork, SecretKey,
    Signature, SignedRoot,
};

#[derive(Debug, PartialEq)]
pub enum Error {
    SszTypesError(ssz_types::Error),
    AlreadySigned(usize),
    SubnetCountIsZero(ArithError),
    IncorrectStateVariant,
}

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
    ),
    ref_attributes(derive(TreeHash), tree_hash(enum_behaviour = "transparent")),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
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
pub struct Attestation<E: EthSpec> {
    #[superstruct(only(Base), partial_getter(rename = "aggregation_bits_base"))]
    pub aggregation_bits: BitList<E::MaxValidatorsPerCommittee>,
    #[superstruct(only(Electra), partial_getter(rename = "aggregation_bits_electra"))]
    pub aggregation_bits: BitList<E::MaxValidatorsPerSlot>,
    pub data: AttestationData,
    #[superstruct(only(Electra))]
    pub committee_bits: BitVector<E::MaxCommitteesPerSlot>,
    pub signature: AggregateSignature,
}

impl<E: EthSpec> Decode for Attestation<E> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        if let Ok(result) = AttestationBase::from_ssz_bytes(bytes) {
            return Ok(Attestation::Base(result));
        }

        if let Ok(result) = AttestationElectra::from_ssz_bytes(bytes) {
            return Ok(Attestation::Electra(result));
        }

        Err(ssz::DecodeError::BytesInvalid(String::from(
            "bytes not valid for any fork variant",
        )))
    }
}

impl<E: EthSpec> Hash for Attestation<E> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        match self {
            Attestation::Base(att) => att.hash(state),
            Attestation::Electra(att) => att.hash(state),
        }
    }
}

impl<E: EthSpec> Attestation<E> {
    /// Aggregate another Attestation into this one.
    ///
    /// The aggregation bitfields must be disjoint, and the data must be the same.
    pub fn aggregate(&mut self, other: AttestationRef<E>) {
        match self {
            Attestation::Base(att) => match other {
                AttestationRef::Base(oth) => {
                    att.aggregate(oth);
                }
                AttestationRef::Electra(_) => {
                    debug_assert!(false, "Cannot aggregate base and electra attestations");
                }
            },
            Attestation::Electra(att) => match other {
                AttestationRef::Base(_) => {
                    debug_assert!(false, "Cannot aggregate base and electra attestations");
                }
                AttestationRef::Electra(oth) => {
                    att.aggregate(oth);
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
        }
    }

    pub fn committee_index(&self) -> u64 {
        match self {
            Attestation::Base(att) => att.data.index,
            Attestation::Electra(att) => att.committee_index(),
        }
    }

    pub fn is_aggregation_bits_zero(&self) -> bool {
        match self {
            Attestation::Base(att) => att.aggregation_bits.is_zero(),
            Attestation::Electra(att) => att.aggregation_bits.is_zero(),
        }
    }

    pub fn num_set_aggregation_bits(&self) -> usize {
        match self {
            Attestation::Base(att) => att.aggregation_bits.num_set_bits(),
            Attestation::Electra(att) => att.aggregation_bits.num_set_bits(),
        }
    }

    pub fn get_aggregation_bit(&self, index: usize) -> Result<bool, ssz_types::Error> {
        match self {
            Attestation::Base(att) => att.aggregation_bits.get(index),
            Attestation::Electra(att) => att.aggregation_bits.get(index),
        }
    }
}

impl<'a, E: EthSpec> AttestationRef<'a, E> {
    pub fn clone_as_attestation(self) -> Attestation<E> {
        match self {
            Self::Base(att) => Attestation::Base(att.clone()),
            Self::Electra(att) => Attestation::Electra(att.clone()),
        }
    }

    pub fn is_aggregation_bits_zero(self) -> bool {
        match self {
            Self::Base(att) => att.aggregation_bits.is_zero(),
            Self::Electra(att) => att.aggregation_bits.is_zero(),
        }
    }

    pub fn num_set_aggregation_bits(&self) -> usize {
        match self {
            Self::Base(att) => att.aggregation_bits.num_set_bits(),
            Self::Electra(att) => att.aggregation_bits.num_set_bits(),
        }
    }

    pub fn committee_index(&self) -> u64 {
        match self {
            AttestationRef::Base(att) => att.data.index,
            AttestationRef::Electra(att) => att.committee_index(),
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
        }
    }
}

impl<E: EthSpec> AttestationElectra<E> {
    /// Are the aggregation bitfields of these attestations disjoint?
    // TODO(electra): check whether the definition from CompactIndexedAttestation::should_aggregate
    // is useful where this is used, i.e. only consider attestations disjoint when their committees
    // match AND their aggregation bits do not intersect.
    pub fn signers_disjoint_from(&self, other: &Self) -> bool {
        self.aggregation_bits
            .intersection(&other.aggregation_bits)
            .is_zero()
    }

    pub fn committee_index(&self) -> u64 {
        *self.get_committee_indices().first().unwrap_or(&0u64)
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
        debug_assert!(self.signers_disjoint_from(other));
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
            .map_err(Error::SszTypesError)?
        {
            Err(Error::AlreadySigned(committee_position))
        } else {
            self.aggregation_bits
                .set(committee_position, true)
                .map_err(Error::SszTypesError)?;

            self.signature.add_assign(signature);

            Ok(())
        }
    }
}

impl<E: EthSpec> AttestationBase<E> {
    /// Are the aggregation bitfields of these attestations disjoint?
    pub fn signers_disjoint_from(&self, other: &Self) -> bool {
        self.aggregation_bits
            .intersection(&other.aggregation_bits)
            .is_zero()
    }

    /// Aggregate another Attestation into this one.
    ///
    /// The aggregation bitfields must be disjoint, and the data must be the same.
    pub fn aggregate(&mut self, other: &Self) {
        debug_assert_eq!(self.data, other.data);
        debug_assert!(self.signers_disjoint_from(other));
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
            .map_err(Error::SszTypesError)?
        {
            Err(Error::AlreadySigned(committee_position))
        } else {
            self.aggregation_bits
                .set(committee_position, true)
                .map_err(Error::SszTypesError)?;

            self.signature.add_assign(signature);

            Ok(())
        }
    }

    pub fn extend_aggregation_bits(
        &self,
    ) -> Result<BitList<E::MaxValidatorsPerSlot>, ssz_types::Error> {
        let mut extended_aggregation_bits: BitList<E::MaxValidatorsPerSlot> =
            BitList::with_capacity(self.aggregation_bits.len())?;

        for (i, bit) in self.aggregation_bits.iter().enumerate() {
            extended_aggregation_bits.set(i, bit)?;
        }
        Ok(extended_aggregation_bits)
    }
}

impl<E: EthSpec> SlotData for Attestation<E> {
    fn get_slot(&self) -> Slot {
        self.data().slot
    }
}

impl<'a, E: EthSpec> SlotData for AttestationRef<'a, E> {
    fn get_slot(&self) -> Slot {
        self.data().slot
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
    fn size_of() {
        use std::mem::size_of;

        let aggregation_bits =
            size_of::<BitList<<MainnetEthSpec as EthSpec>::MaxValidatorsPerCommittee>>();
        let attestation_data = size_of::<AttestationData>();
        let signature = size_of::<AggregateSignature>();

        assert_eq!(aggregation_bits, 56);
        assert_eq!(attestation_data, 128);
        assert_eq!(signature, 288 + 16);

        let attestation_expected = aggregation_bits + attestation_data + signature;
        // TODO(electra) since we've removed attestation aggregation for electra variant
        // i've updated the attestation value expected from 488 544
        // assert_eq!(attestation_expected, 488);
        assert_eq!(attestation_expected, 488);
        assert_eq!(
            size_of::<Attestation<MainnetEthSpec>>(),
            attestation_expected
        );
    }

    // TODO(electra): can we do this with both variants or should we?
    ssz_and_tree_hash_tests!(AttestationBase<MainnetEthSpec>);
}
