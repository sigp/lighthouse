use super::{AggregatePublicKey, AggregateSignature, AttestationData, Bitfield, Hash256};
use crate::test_utils::TestRandom;
use rand::RngCore;
use serde_derive::Serialize;
use ssz::TreeHash;
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

#[derive(Debug, Clone, PartialEq, Serialize, Encode, Decode, TreeHash, TestRandom)]
pub struct Attestation {
    pub aggregation_bitfield: Bitfield,
    pub data: AttestationData,
    pub custody_bitfield: Bitfield,
    pub aggregate_signature: AggregateSignature,
}

impl Attestation {
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from_slice(&self.hash_tree_root()[..])
    }

    pub fn signable_message(&self, custody_bit: bool) -> Vec<u8> {
        self.data.signable_message(custody_bit)
    }

    pub fn verify_signature(
        &self,
        group_public_key: &AggregatePublicKey,
        custody_bit: bool,
        domain: u64,
    ) -> bool {
        self.aggregate_signature.verify(
            &self.signable_message(custody_bit),
            domain,
            group_public_key,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(Attestation);
}
