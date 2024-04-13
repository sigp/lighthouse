use crate::slot_data::SlotData;
use crate::{test_utils::TestRandom, Hash256, Slot};
use derivative::Derivative;
use rand::RngCore;
use safe_arith::ArithError;
use serde::{Deserialize, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
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
    pub committee_bits: BitList<E::MaxCommitteesPerSlot>,
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
    fn random_for_test(_rng: &mut impl RngCore) -> Self {
        todo!()
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
    // pub fn aggregation_bits(&self) -> Vec<u8> {
    //     match self {
    //         Attestation::Base(att) => att.aggregation_bits.as_slice().to_owned(),
    //         Attestation::Electra(att) => att.aggregation_bits.as_slice().to_owned(),
    //     }
    // }

    // pub fn get_aggregation_bit(&self, index: usize) -> Result<bool, ssz_types::Error> {
    //     match self {
    //         Attestation::Base(att) => att.aggregation_bits.get(index),
    //         Attestation::Electra(att) => att.aggregation_bits.get(index),
    //     }
    // }

    // pub fn is_empty_aggregation_bits(&self) -> bool {
    //     match self {
    //         Attestation::Base(att) => att.aggregation_bits.is_zero(),
    //         Attestation::Electra(att) => att.aggregation_bits.is_zero(),
    //     }
    // }

    // pub fn aggregation_num_set_bits(&self) -> usize {
    //     match self {
    //         Attestation::Base(att) => att.aggregation_bits.num_set_bits(),
    //         Attestation::Electra(att) => att.aggregation_bits.num_set_bits(),
    //     }
    // }

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
}

impl<E: EthSpec> AttestationElectra<E> {
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
