use crate::slot_data::SlotData;
use crate::{test_utils::TestRandom, Hash256, Slot};
use crate::{BeaconCommittee, Checkpoint, ForkVersionDeserialize};
use derivative::Derivative;
use safe_arith::ArithError;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::BitVector;
use std::hash::{Hash, Hasher};
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;
use ssz_types::typenum::Unsigned;

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
    InvalidCommitteeLength,
    InvalidCommitteeIndex,
    InvalidAggregationBit,
}

impl From<ssz_types::Error> for Error {
    fn from(e: ssz_types::Error) -> Self {
        Error::SszTypesError(e)
    }
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
    pub signature: AggregateSignature,
    #[superstruct(only(Electra))]
    pub committee_bits: BitVector<E::MaxCommitteesPerSlot>,
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
    /// Produces an attestation with empty signature.
    pub fn empty_for_signing(
        committee_index: u64,
        committee_length: usize,
        slot: Slot,
        beacon_block_root: Hash256,
        source: Checkpoint,
        target: Checkpoint,
        spec: &ChainSpec,
    ) -> Result<Self, Error> {
        if spec.fork_name_at_slot::<E>(slot).electra_enabled() {
            let mut committee_bits: BitVector<E::MaxCommitteesPerSlot> = BitVector::default();
            committee_bits
                .set(committee_index as usize, true)
                .map_err(|_| Error::InvalidCommitteeIndex)?;
            Ok(Attestation::Electra(AttestationElectra {
                aggregation_bits: BitList::with_capacity(committee_length)
                    .map_err(|_| Error::InvalidCommitteeLength)?,
                data: AttestationData {
                    slot,
                    index: 0u64,
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

    pub fn committee_index(&self) -> Option<u64> {
        match self {
            Attestation::Base(att) => Some(att.data.index),
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

    pub fn committee_index(&self) -> Option<u64> {
        match self {
            AttestationRef::Base(att) => Some(att.data.index),
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
    pub fn committee_index(&self) -> Option<u64> {
        self.get_committee_indices().first().cloned()
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

    pub fn from_single_attestation(single_attestation: SingleAttestation) -> Result<Self, Error> {
        let mut committee_bits = BitVector::new();
        committee_bits.set(single_attestation.committee_index, true)?;

        if committee_bits.num_set_bits() != 1 {
            return Err(Error::InvalidCommitteeIndex);
        }

        let mut aggregation_bits = BitList::with_capacity(E::MaxValidatorsPerSlot::to_usize())?;
        aggregation_bits.set(single_attestation.attester_index, true)?;

        if aggregation_bits.num_set_bits() != 1 {
            return Err(Error::InvalidAggregationBit);
        }

        Ok(Self {
            data: single_attestation.data,
            signature: single_attestation.signature,
            committee_bits,
            aggregation_bits,
        })
    }
}

impl<E: EthSpec> AttestationBase<E> {
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
        self.aggregation_bits.resize::<E::MaxValidatorsPerSlot>()
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

#[derive(Debug, Clone, Encode, Decode, PartialEq)]
#[ssz(enum_behaviour = "union")]
pub enum AttestationOnDisk<E: EthSpec> {
    Base(AttestationBase<E>),
    Electra(AttestationElectra<E>),
}

impl<E: EthSpec> AttestationOnDisk<E> {
    pub fn to_ref(&self) -> AttestationRefOnDisk<E> {
        match self {
            AttestationOnDisk::Base(att) => AttestationRefOnDisk::Base(att),
            AttestationOnDisk::Electra(att) => AttestationRefOnDisk::Electra(att),
        }
    }
}

#[derive(Debug, Clone, Encode)]
#[ssz(enum_behaviour = "union")]
pub enum AttestationRefOnDisk<'a, E: EthSpec> {
    Base(&'a AttestationBase<E>),
    Electra(&'a AttestationElectra<E>),
}

impl<E: EthSpec> From<Attestation<E>> for AttestationOnDisk<E> {
    fn from(attestation: Attestation<E>) -> Self {
        match attestation {
            Attestation::Base(attestation) => Self::Base(attestation),
            Attestation::Electra(attestation) => Self::Electra(attestation),
        }
    }
}

impl<E: EthSpec> From<AttestationOnDisk<E>> for Attestation<E> {
    fn from(attestation: AttestationOnDisk<E>) -> Self {
        match attestation {
            AttestationOnDisk::Base(attestation) => Self::Base(attestation),
            AttestationOnDisk::Electra(attestation) => Self::Electra(attestation),
        }
    }
}

impl<'a, E: EthSpec> From<AttestationRef<'a, E>> for AttestationRefOnDisk<'a, E> {
    fn from(attestation: AttestationRef<'a, E>) -> Self {
        match attestation {
            AttestationRef::Base(attestation) => Self::Base(attestation),
            AttestationRef::Electra(attestation) => Self::Electra(attestation),
        }
    }
}

impl<'a, E: EthSpec> From<AttestationRefOnDisk<'a, E>> for AttestationRef<'a, E> {
    fn from(attestation: AttestationRefOnDisk<'a, E>) -> Self {
        match attestation {
            AttestationRefOnDisk::Base(attestation) => Self::Base(attestation),
            AttestationRefOnDisk::Electra(attestation) => Self::Electra(attestation),
        }
    }
}

impl<E: EthSpec> ForkVersionDeserialize for Attestation<E> {
    fn deserialize_by_fork<'de, D: serde::Deserializer<'de>>(
        value: serde_json::Value,
        fork_name: crate::ForkName,
    ) -> Result<Self, D::Error> {
        if fork_name.electra_enabled() {
            let attestation: AttestationElectra<E> =
                serde_json::from_value(value).map_err(serde::de::Error::custom)?;
            Ok(Attestation::Electra(attestation))
        } else {
            let attestation: AttestationBase<E> =
                serde_json::from_value(value).map_err(serde::de::Error::custom)?;
            Ok(Attestation::Base(attestation))
        }
    }
}

impl<E: EthSpec> ForkVersionDeserialize for Vec<Attestation<E>> {
    fn deserialize_by_fork<'de, D: serde::Deserializer<'de>>(
        value: serde_json::Value,
        fork_name: crate::ForkName,
    ) -> Result<Self, D::Error> {
        if fork_name.electra_enabled() {
            let attestations: Vec<AttestationElectra<E>> =
                serde_json::from_value(value).map_err(serde::de::Error::custom)?;
            Ok(attestations
                .into_iter()
                .map(Attestation::Electra)
                .collect::<Vec<_>>())
        } else {
            let attestations: Vec<AttestationBase<E>> =
                serde_json::from_value(value).map_err(serde::de::Error::custom)?;
            Ok(attestations
                .into_iter()
                .map(Attestation::Base)
                .collect::<Vec<_>>())
        }
    }
}

#[derive(
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
    PartialEq,
)]
pub struct SingleAttestation {
    pub committee_index: usize,
    pub attester_index: usize,
    pub data: AttestationData,
    pub signature: AggregateSignature,
}

impl SingleAttestation {
    /// Produces a `SingleAttestation` with empty signature and empty attester index.
    /// ONLY USE IN ELECTRA
    pub fn empty_for_signing(
        committee_index: usize,
        slot: Slot,
        beacon_block_root: Hash256,
        source: Checkpoint,
        target: Checkpoint,
    ) -> Self {
        Self {
            committee_index,
            attester_index: 0,
            data: AttestationData {
                slot,
                index: 0,
                beacon_block_root,
                source,
                target,
            },
            signature: AggregateSignature::infinity(),
        }
    }

    pub fn add_signature(&mut self, signature: &AggregateSignature, committee_position: usize) {
        self.attester_index = committee_position;
        self.signature = signature.clone();
    }

    //  /// Shortcut for getting the attesting indices while fetching the committee from the state's cache.
    //  pub fn get_attesting_indices_from_state<E: EthSpec>(
    //     state: &BeaconState<E>,
    //     att: &AttestationElectra<E>,
    // ) -> Result<Vec<u64>, BeaconStateError> {
    //     let committees = state.get_beacon_committees_at_slot(att.data.slot)?;
    //     get_attesting_indices::<E>(&committees, &att.aggregation_bits, &att.committee_bits)
    // }

    // /// Returns validator indices which participated in the attestation, sorted by increasing index.
    // ///
    // /// Committees must be sorted by ascending order 0..committees_per_slot
    // pub fn get_attesting_indices<E: EthSpec>(
    //     committees: &[BeaconCommittee],
    //     aggregation_bits: &BitList<E::MaxValidatorsPerSlot>,
    //     committee_bits: &BitVector<E::MaxCommitteesPerSlot>,
    // ) -> Result<Vec<u64>, BeaconStateError> {
    //     let mut attesting_indices = vec![];

    //     let committee_indices = get_committee_indices::<E>(committee_bits);

    //     let mut committee_offset = 0;

    //     let committee_count_per_slot = committees.len() as u64;
    //     let mut participant_count = 0;
    //     for index in committee_indices {
    //         let beacon_committee = committees
    //             .get(index as usize)
    //             .ok_or(Error::NoCommitteeFound(index))?;

    //         // This check is new to the spec's `process_attestation` in Electra.
    //         if index >= committee_count_per_slot {
    //             return Err(BeaconStateError::InvalidCommitteeIndex(index));
    //         }
    //         participant_count.safe_add_assign(beacon_committee.committee.len() as u64)?;
    //         let committee_attesters = beacon_committee
    //             .committee
    //             .iter()
    //             .enumerate()
    //             .filter_map(|(i, &index)| {
    //                 if let Ok(aggregation_bit_index) = committee_offset.safe_add(i) {
    //                     if aggregation_bits.get(aggregation_bit_index).unwrap_or(false) {
    //                         return Some(index as u64);
    //                     }
    //                 }
    //                 None
    //             })
    //             .collect::<HashSet<u64>>();

    //         attesting_indices.extend(committee_attesters);
    //         committee_offset.safe_add_assign(beacon_committee.committee.len())?;
    //     }

    //     // This check is new to the spec's `process_attestation` in Electra.
    //     if participant_count as usize != aggregation_bits.len() {
    //         return Err(BeaconStateError::InvalidBitfield);
    //     }

    //     attesting_indices.sort_unstable();

    //     Ok(attesting_indices)
    // }

    pub fn to_attestation(&self, _committees: &[BeaconCommittee]) -> Result<(), Error> {
        // let beacon_committee = committees.get(self.committee_index).unwrap();
        // let mut participant_count = 0;
        // beacon_committee
        //     .committee
        //     .iter()
        //     .enumerate()
        //     .filter_map(|(i, &beacon_committee)| {
        //         todo!()
        //     });

        Ok(())

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

        let aggregation_bits =
            size_of::<BitList<<MainnetEthSpec as EthSpec>::MaxValidatorsPerCommittee>>();
        let attestation_data = size_of::<AttestationData>();
        let signature = size_of::<AggregateSignature>();

        assert_eq!(aggregation_bits, 56);
        assert_eq!(attestation_data, 128);
        assert_eq!(signature, 288 + 16);

        let attestation_expected = aggregation_bits + attestation_data + signature;
        assert_eq!(attestation_expected, 488);
        assert_eq!(
            size_of::<AttestationBase<MainnetEthSpec>>(),
            attestation_expected
        );
    }

    #[test]
    fn size_of_electra() {
        use std::mem::size_of;

        let aggregation_bits =
            size_of::<BitList<<MainnetEthSpec as EthSpec>::MaxValidatorsPerSlot>>();
        let attestation_data = size_of::<AttestationData>();
        let committee_bits =
            size_of::<BitList<<MainnetEthSpec as EthSpec>::MaxCommitteesPerSlot>>();
        let signature = size_of::<AggregateSignature>();

        assert_eq!(aggregation_bits, 56);
        assert_eq!(committee_bits, 56);
        assert_eq!(attestation_data, 128);
        assert_eq!(signature, 288 + 16);

        let attestation_expected = aggregation_bits + committee_bits + attestation_data + signature;
        assert_eq!(attestation_expected, 544);
        assert_eq!(
            size_of::<AttestationElectra<MainnetEthSpec>>(),
            attestation_expected
        );
    }

    mod base {
        use super::*;
        ssz_and_tree_hash_tests!(AttestationBase<MainnetEthSpec>);
    }
    mod electra {
        use super::*;
        ssz_and_tree_hash_tests!(AttestationElectra<MainnetEthSpec>);
    }
}
