use super::AttestationData;
use crate::test_utils::TestRandom;
use rand::RngCore;
use serde_derive::Serialize;
use ssz_derive::{Decode, Encode, TreeHash};

/// Used for pairing an attestation with a proof-of-custody.
///
/// Spec v0.4.0
#[derive(Debug, Clone, PartialEq, Default, Serialize, Encode, Decode, TreeHash)]
pub struct AttestationDataAndCustodyBit {
    pub data: AttestationData,
    pub custody_bit: bool,
}

impl<T: RngCore> TestRandom<T> for AttestationDataAndCustodyBit {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            data: <_>::random_for_test(rng),
            custody_bit: <_>::random_for_test(rng),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    ssz_tests!(AttestationDataAndCustodyBit);
}
