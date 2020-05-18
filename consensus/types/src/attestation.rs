use super::{
    AggregateSignature, AttestationData, BitList, ChainSpec, Domain, EthSpec, Fork, SecretKey,
    Signature, SignedRoot, SubnetId,
};
use crate::{test_utils::TestRandom, Hash256};
use safe_arith::{ArithError, SafeArith};

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(Debug, PartialEq)]
pub enum Error {
    SszTypesError(ssz_types::Error),
    AlreadySigned(usize),
    SubnetCountIsZero(ArithError),
}

/// Details an attestation that can be slashable.
///
/// Spec v0.11.1
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
#[serde(bound = "T: EthSpec")]
pub struct Attestation<T: EthSpec> {
    pub aggregation_bits: BitList<T::MaxValidatorsPerCommittee>,
    pub data: AttestationData,
    pub signature: AggregateSignature,
}

impl<T: EthSpec> Attestation<T> {
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
        self.signature.add_aggregate(&other.signature);
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

            let domain = spec.get_domain(
                self.data.target.epoch,
                Domain::BeaconAttester,
                fork,
                genesis_validators_root,
            );
            let message = self.data.signing_root(domain);

            self.signature
                .add(&Signature::new(message.as_bytes(), secret_key));

            Ok(())
        }
    }

    /// Returns the subnet id associated with the attestation.
    ///
    /// Note, this will return the subnet id for an aggregated attestation. This is done
    /// to avoid checking aggregate bits every time we wish to get an id.
    pub fn subnet_id(&self, spec: &ChainSpec) -> Result<SubnetId, Error> {
        self.data
            .index
            .safe_rem(spec.attestation_subnet_count)
            .map(SubnetId::new)
            .map_err(Error::SubnetCountIsZero)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    ssz_and_tree_hash_tests!(Attestation<MainnetEthSpec>);
}
