use super::{
    AggregateSignature, AttestationData, BitList, ChainSpec, Domain, EthSpec, Fork, SecretKey,
    Signature,
};
use crate::test_utils::TestRandom;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::{SignedRoot, TreeHash};

#[derive(Debug, PartialEq)]
pub enum Error {
    SszTypesError(ssz_types::Error),
    AlreadySigned(usize),
}

/// Details an attestation that can be slashable.
///
/// Spec v0.9.1
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    SignedRoot,
)]
#[serde(bound = "T: EthSpec")]
pub struct Attestation<T: EthSpec> {
    pub aggregation_bits: BitList<T::MaxValidatorsPerCommittee>,
    pub data: AttestationData,
    #[signed_root(skip_hashing)]
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

            let message = self.data.tree_hash_root();
            let domain = spec.get_domain(self.data.target.epoch, Domain::BeaconAttester, fork);

            self.signature
                .add(&Signature::new(&message, domain, secret_key));

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    ssz_tests!(Attestation<MainnetEthSpec>);
}
