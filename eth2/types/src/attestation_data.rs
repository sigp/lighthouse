use crate::test_utils::TestRandom;
use crate::{Crosslink, Epoch, Hash256, Slot};
use rand::RngCore;
use serde_derive::Serialize;
use ssz::TreeHash;
use ssz_derive::{Decode, Encode, SignedRoot, TreeHash};
use test_random_derive::TestRandom;

/// The data upon which an attestation is based.
///
/// Spec v0.4.0
#[derive(
    Debug,
    Clone,
    PartialEq,
    Default,
    Serialize,
    Hash,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    SignedRoot,
)]
pub struct AttestationData {
    pub slot: Slot,
    pub shard: u64,
    pub beacon_block_root: Hash256,
    pub epoch_boundary_root: Hash256,
    pub crosslink_data_root: Hash256,
    pub latest_crosslink: Crosslink,
    pub justified_epoch: Epoch,
    pub justified_block_root: Hash256,
}

impl Eq for AttestationData {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use ssz::{ssz_encode, Decodable, TreeHash};

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = AttestationData::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_hash_tree_root_internal() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = AttestationData::random_for_test(&mut rng);

        let result = original.hash_tree_root_internal();

        assert_eq!(result.len(), 32);
        // TODO: Add further tests
        // https://github.com/sigp/lighthouse/issues/170
    }
}
