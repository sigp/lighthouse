use crate::context_deserialize;
use crate::slot_data::SlotData;
use crate::{test_utils::TestRandom, Hash256, Slot};
use crate::{Checkpoint, ContextDeserialize, ForkName};
use derivative::Derivative;
use serde::{Deserialize, Deserializer, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::BitVector;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

use super::{
    AggregateSignature, AttestationData, BitList, ChainSpec, Domain, EthSpec, Fork, SecretKey,
    Signature, SignedRoot,
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
        context_deserialize(ForkName),
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

    pub fn get_committee_indices_map(&self) -> HashSet<u64> {
        match self {
            Attestation::Base(att) => HashSet::from([att.data.index]),
            Attestation::Electra(att) => att.get_committee_indices().into_iter().collect(),
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

    pub fn get_aggregation_bit(&self, index: usize) -> Result<bool, ssz::BitfieldError> {
        match self {
            Attestation::Base(att) => att.aggregation_bits.get(index),
            Attestation::Electra(att) => att.aggregation_bits.get(index),
        }
    }

    pub fn to_single_attestation_with_attester_index(
        &self,
        attester_index: u64,
    ) -> Result<SingleAttestation, Error> {
        match self {
            Self::Base(_) => Err(Error::IncorrectStateVariant),
            Self::Electra(attn) => attn.to_single_attestation_with_attester_index(attester_index),
        }
    }
}

impl<E: EthSpec> AttestationRef<'_, E> {
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
    ) -> Result<BitList<E::MaxValidatorsPerSlot>, ssz::BitfieldError> {
        self.aggregation_bits.resize::<E::MaxValidatorsPerSlot>()
    }
}

impl<E: EthSpec> SlotData for Attestation<E> {
    fn get_slot(&self) -> Slot {
        self.data().slot
    }
}

impl<E: EthSpec> SlotData for AttestationRef<'_, E> {
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

impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for Attestation<E> {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if context.electra_enabled() {
            AttestationElectra::<E>::deserialize(deserializer)
                .map_err(serde::de::Error::custom)
                .map(Attestation::Electra)
        } else {
            AttestationBase::<E>::deserialize(deserializer)
                .map_err(serde::de::Error::custom)
                .map(Attestation::Base)
        }
    }
}

/*
impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for Vec<Attestation<E>> {
    fn context_deserialize<D>(
        deserializer: D,
        context: ForkName,
    ) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if context.electra_enabled() {
            <Vec<AttestationElectra<E>>>::deserialize(deserializer)
                .map_err(serde::de::Error::custom)
                .map(|vec| vec.into_iter().map(Attestation::Electra).collect::<Vec<_>>())
        } else {
            <Vec<AttestationBase<E>>>::deserialize(deserializer)
                .map_err(serde::de::Error::custom)
                .map(|vec| vec.into_iter().map(Attestation::Base).collect::<Vec<_>>())
        }
    }
}
*/

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
#[context_deserialize(ForkName)]
pub struct SingleAttestation {
    #[serde(with = "serde_utils::quoted_u64")]
    pub committee_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub attester_index: u64,
    pub data: AttestationData,
    pub signature: AggregateSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    // Specify the type parameter
    type E = MainnetEthSpec;

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

        assert_eq!(aggregation_bits, 152);
        assert_eq!(attestation_data, 128);
        assert_eq!(signature, 288 + 16);

        let attestation_expected = aggregation_bits + attestation_data + signature;
        assert_eq!(attestation_expected, 584);
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

        assert_eq!(aggregation_bits, 152);
        assert_eq!(committee_bits, 152);
        assert_eq!(attestation_data, 128);
        assert_eq!(signature, 288 + 16);

        let attestation_expected = aggregation_bits + committee_bits + attestation_data + signature;
        assert_eq!(attestation_expected, 736);
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

    fn create_test_data() -> AttestationData {
        AttestationData {
            slot: Slot::new(1),
            index: 0,
            beacon_block_root: Hash256::zero(),
            source: Checkpoint {
                epoch: Epoch::new(0),
                root: Hash256::zero(),
            },
            target: Checkpoint {
                epoch: Epoch::new(1),
                root: Hash256::zero(),
            },
        }
    }

    #[test]
    fn test_creation_equivalence() {
        let data = create_test_data();

        // Use fully-qualified syntax for associated types
        let committee_length = <MainnetEthSpec as EthSpec>::MaxValidatorsPerCommittee::to_usize();
        let validators_per_slot = <MainnetEthSpec as EthSpec>::MaxValidatorsPerSlot::to_usize();

        // Create Base attestation - validator 0 in committee 0 voting
        let mut base_bits = BitList::with_capacity(committee_length).unwrap();
        // Set bit for validator at index 0
        base_bits.set(0, true).unwrap();
        let base = Attestation::Base(AttestationBase::<E> {
            aggregation_bits: base_bits,
            data: data.clone(),
            signature: AggregateSignature::infinity(),
        });

        // Create Electra attestation - can track all committees
        let mut committee_bits =
            BitVector::<<MainnetEthSpec as EthSpec>::MaxCommitteesPerSlot>::new();
        committee_bits.set(0, true).unwrap();

        let mut electra_bits = BitList::with_capacity(validators_per_slot).unwrap();
        // Set bit for validator at index 0 overall
        electra_bits.set(0, true).unwrap();

        let electra = Attestation::Electra(AttestationElectra::<E> {
            aggregation_bits: electra_bits,
            data: data.clone(),
            signature: AggregateSignature::infinity(),
            committee_bits,
        });

        // Verify basic properties are equivalent
        assert_eq!(base.data(), electra.data());
        assert_eq!(base.is_aggregation_bits_zero(), false);
        assert_eq!(
            base.is_aggregation_bits_zero(),
            electra.is_aggregation_bits_zero()
        );
        assert_eq!(base.num_set_aggregation_bits(), 1);
        assert_eq!(
            base.num_set_aggregation_bits(),
            electra.num_set_aggregation_bits()
        );
        assert_eq!(base.committee_index(), Some(0));
        assert_eq!(base.committee_index(), electra.committee_index());
    }

    #[test]
    fn test_signature_equivalence() {
        let data = create_test_data();
        let committee_position = 0;
        let secret_key = SecretKey::random();
        let fork = Fork::default();
        let genesis_validators_root = Hash256::zero();
        let spec = ChainSpec::mainnet();

        // Use fully-qualified syntax for associated types
        let committee_length = <MainnetEthSpec as EthSpec>::MaxValidatorsPerCommittee::to_usize();
        let validators_per_slot = <MainnetEthSpec as EthSpec>::MaxValidatorsPerSlot::to_usize();

        // Create Base attestation - validator 0 in committee 0 voting
        let base_bits = BitList::with_capacity(committee_length).unwrap();

        // Create and sign Base attestation
        let mut base = Attestation::Base(AttestationBase::<E> {
            aggregation_bits: base_bits,
            data: data.clone(),
            signature: AggregateSignature::infinity(),
        });
        base.sign(
            &secret_key,
            committee_position,
            &fork,
            genesis_validators_root,
            &spec,
        )
        .unwrap();

        // Create and sign Electra attestation
        let mut committee_bits = BitVector::default();
        committee_bits.set(0, true).unwrap();

        let electra_bits = BitList::with_capacity(validators_per_slot).unwrap();

        let mut electra = Attestation::Electra(AttestationElectra::<E> {
            aggregation_bits: electra_bits,
            data: data.clone(),
            signature: AggregateSignature::infinity(),
            committee_bits,
        });
        electra
            .sign(
                &secret_key,
                committee_position,
                &fork,
                genesis_validators_root,
                &spec,
            )
            .unwrap();

        // Verify signatures are equivalent
        assert_eq!(base.signature(), electra.signature());
        assert_eq!(base.is_aggregation_bits_zero(), false);
        assert_eq!(
            base.is_aggregation_bits_zero(),
            electra.is_aggregation_bits_zero()
        );
        assert_eq!(base.num_set_aggregation_bits(), 1);
        assert_eq!(
            base.num_set_aggregation_bits(),
            electra.num_set_aggregation_bits()
        );
        assert_eq!(base.committee_index(), Some(0));
        assert_eq!(base.committee_index(), electra.committee_index());
    }

    #[test]
    fn test_aggregation_equivalence() {
        let data = create_test_data();
        // Use fully-qualified syntax for associated types
        let committee_length = <MainnetEthSpec as EthSpec>::MaxValidatorsPerCommittee::to_usize();
        let validators_per_slot = <MainnetEthSpec as EthSpec>::MaxValidatorsPerSlot::to_usize();

        // Create two Base attestations with different bits set
        let mut base1 = Attestation::Base(AttestationBase::<E> {
            aggregation_bits: BitList::with_capacity(committee_length).unwrap(),
            data: data.clone(),
            signature: AggregateSignature::infinity(),
        });
        base1.add_signature(&Signature::empty(), 0).unwrap();

        let mut base2 = base1.clone();
        base2.add_signature(&Signature::empty(), 1).unwrap();

        // Create equivalent Electra attestations
        let mut electra1 = Attestation::Electra(AttestationElectra::<E> {
            aggregation_bits: BitList::with_capacity(validators_per_slot).unwrap(),
            data: data.clone(),
            signature: AggregateSignature::infinity(),
            committee_bits: BitVector::default(),
        });
        electra1.add_signature(&Signature::empty(), 0).unwrap();

        let mut electra2 = Attestation::Electra(AttestationElectra::<E> {
            aggregation_bits: BitList::with_capacity(validators_per_slot).unwrap(),
            data: data.clone(),
            signature: AggregateSignature::infinity(),
            committee_bits: BitVector::default(),
        });
        electra2.add_signature(&Signature::empty(), 1).unwrap();

        // Aggregate both pairs
        let mut base_agg = base1.clone();
        base_agg.aggregate((&base2).into());

        let mut electra_agg = electra1.clone();
        electra_agg.aggregate((&electra2).into());

        // Verify aggregation results are equivalent
        assert_eq!(base_agg.is_aggregation_bits_zero(), false);
        assert_eq!(
            base_agg.is_aggregation_bits_zero(),
            electra_agg.is_aggregation_bits_zero()
        );
        assert_eq!(base_agg.num_set_aggregation_bits(), 2);
        assert_eq!(
            base_agg.num_set_aggregation_bits(),
            electra_agg.num_set_aggregation_bits()
        );
        assert_eq!(base_agg.signature(), electra_agg.signature());
        let base_agg_ref: AttestationRef<'_, E> = (&base_agg).into();
        let electra_agg_ref: AttestationRef<'_, E> = (&electra_agg).into();
        assert_eq!(base_agg_ref.set_aggregation_bits(), vec![0, 1]);
        assert_eq!(
            base_agg_ref.set_aggregation_bits(),
            electra_agg_ref.set_aggregation_bits()
        );
    }

    #[test]
    fn test_error_handling_equivalence() {
        use super::Error as AttestationError;
        let data = create_test_data();
        let committee_length = <MainnetEthSpec as EthSpec>::MaxValidatorsPerCommittee::to_usize();
        let validators_per_slot = <MainnetEthSpec as EthSpec>::MaxValidatorsPerSlot::to_usize();

        // Test double signing same position
        let mut base = Attestation::Base(AttestationBase::<E> {
            aggregation_bits: BitList::with_capacity(committee_length).unwrap(),
            data: data.clone(),
            signature: AggregateSignature::infinity(),
        });
        base.add_signature(&Signature::empty(), 0).unwrap();
        let base_err = base.add_signature(&Signature::empty(), 0);

        let mut committee_bits = BitVector::default();
        committee_bits.set(0, true).unwrap();
        let mut electra = Attestation::Electra(AttestationElectra::<E> {
            aggregation_bits: BitList::with_capacity(validators_per_slot).unwrap(),
            data: data.clone(),
            signature: AggregateSignature::infinity(),
            committee_bits,
        });
        electra.add_signature(&Signature::empty(), 0).unwrap();
        let electra_err = electra.add_signature(&Signature::empty(), 0);

        // Verify both variants handle errors the same way
        assert!(matches!(base_err, Err(AttestationError::AlreadySigned(0))));
        assert!(matches!(
            electra_err,
            Err(AttestationError::AlreadySigned(0))
        ));
    }

    #[test]
    fn test_multi_committee_aggregation() {
        let data = create_test_data();
        let secret_key = SecretKey::random();
        let fork = Fork::default();
        let genesis_validators_root = Hash256::zero();
        let spec = ChainSpec::mainnet();

        // Committee sizes
        let committee_length = <MainnetEthSpec as EthSpec>::MaxValidatorsPerCommittee::to_usize();
        let validators_per_slot = <MainnetEthSpec as EthSpec>::MaxValidatorsPerSlot::to_usize();

        // Base attestations - need one per committee
        let mut base1 = Attestation::Base(AttestationBase::<E> {
            aggregation_bits: BitList::with_capacity(committee_length).unwrap(),
            data: AttestationData {
                index: 0, // Committee 0
                ..data.clone()
            },
            signature: AggregateSignature::infinity(),
        });

        let mut base2 = Attestation::Base(AttestationBase::<E> {
            aggregation_bits: BitList::with_capacity(committee_length).unwrap(),
            data: AttestationData {
                index: 1, // Committee 1
                ..data.clone()
            },
            signature: AggregateSignature::infinity(),
        });

        // Electra attestation - can handle multiple committees
        let mut committee_bits = BitVector::default();
        committee_bits.set(0, true).unwrap(); // Committee 0
        committee_bits.set(1, true).unwrap(); // Committee 1

        let mut electra = Attestation::Electra(AttestationElectra::<E> {
            aggregation_bits: BitList::with_capacity(validators_per_slot).unwrap(),
            data: data.clone(),
            signature: AggregateSignature::infinity(),
            committee_bits,
        });

        // Sign with validator 0 in committee 0
        base1
            .sign(&secret_key, 0, &fork, genesis_validators_root, &spec)
            .unwrap();

        // Sign with validator 0 in committee 1
        base2
            .sign(&secret_key, 1, &fork, genesis_validators_root, &spec)
            .unwrap();

        // For Electra, we need to sign with both validators
        // This is where we might see issues with index translation
        electra
            .sign(&secret_key, 0, &fork, genesis_validators_root, &spec)
            .unwrap(); // Committee 0, validator 0
        electra
            .sign(&secret_key, 1, &fork, genesis_validators_root, &spec)
            .unwrap(); // Committee 1, validator 0

        // Verify committee indices
        assert_eq!(base1.committee_index(), Some(0));
        assert_eq!(base2.committee_index(), Some(1));

        // For Electra, get_committee_indices should return both committees
        assert_eq!(
            electra.as_electra().unwrap().get_committee_indices(),
            vec![0, 1]
        );

        // Check aggregation bits are set correctly
        assert!(base1.get_aggregation_bit(0).unwrap());
        assert!(base2.get_aggregation_bit(1).unwrap());

        // For Electra, both bits should be set at their respective committee offsets
        assert!(electra.get_aggregation_bit(0).unwrap()); // Committee 0, validator 0
        assert!(electra.get_aggregation_bit(1).unwrap()); // Committee 1, validator 0
    }
}
