use crate::test_utils::TestRandom;
use crate::*;
use ssz_types::typenum::U33;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

pub const DEPOSIT_TREE_DEPTH: usize = 32;

/// A deposit to potentially become a beacon chain validator.
///
/// Spec v0.11.1
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct Deposit {
    pub proof: FixedVector<Hash256, U33>,
    pub data: DepositData,
}

impl arbitrary::Arbitrary for Deposit {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut vec: Vec<Hash256> = Vec::with_capacity(33);
        for _ in 0..33 {
            vec.push(<Hash256>::arbitrary(u)?);
        }
        let proof: FixedVector<Hash256, U33> = FixedVector::new(vec).expect("valid capacity");
        let data = <DepositData>::arbitrary(u)?;
        Ok(Self { proof, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(Deposit);
}
