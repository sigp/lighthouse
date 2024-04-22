use crate::slot_data::SlotData;
use crate::{test_utils::TestRandom, Hash256, Slot};
use derivative::Derivative;
use rand::RngCore;
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
pub struct Attestation<E: EthSpec> {
    pub aggregation_bits: BitList<E::MaxValidatorsPerCommitteePerSlot>,
    pub data: AttestationData,
    pub signature: AggregateSignature,
    #[superstruct(only(Electra))]
    pub committee_bits: BitVector<E::MaxCommitteesPerSlot>,
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

impl<E: EthSpec> TestRandom for Attestation<E> {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let aggregation_bits: BitList<E::MaxValidatorsPerCommitteePerSlot> =
            BitList::random_for_test(rng);
        // let committee_bits: BitList<E::MaxCommitteesPerSlot> = BitList::random_for_test(rng);
        let data = AttestationData::random_for_test(rng);
        let signature = AggregateSignature::random_for_test(rng);

        Self::Base(AttestationBase {
            aggregation_bits,
            // committee_bits,
            data,
            signature,
        })
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
    pub fn aggregate(&mut self, other: &Self) {
        match self {
            Attestation::Base(att) => {
                debug_assert!(other.as_base().is_ok());

                if let Ok(other) = other.as_base() {
                    att.aggregate(other)
                }
            }
            Attestation::Electra(att) => {
                debug_assert!(other.as_electra().is_ok());

                if let Ok(other) = other.as_electra() {
                    att.aggregate(other)
                }
            }
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
}

impl<E: EthSpec> AttestationElectra<E> {
    /// Are the aggregation bitfields of these attestations disjoint?
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
}

impl<E: EthSpec> SlotData for Attestation<E> {
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
        assert_eq!(attestation_expected, 488);
        assert_eq!(
            size_of::<Attestation<MainnetEthSpec>>(),
            attestation_expected
        );
    }

    ssz_and_tree_hash_tests!(Attestation<MainnetEthSpec>);
}
