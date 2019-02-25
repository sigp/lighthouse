use crate::test_utils::TestRandom;
use crate::{AttestationDataAndCustodyBit, Crosslink, Epoch, Hash256, Slot};
use rand::RngCore;
use serde_derive::Serialize;
use ssz::TreeHash;
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

pub const SSZ_ATTESTION_DATA_LENGTH: usize = {
    8 +             // slot
    8 +             // shard
    32 +            // beacon_block_hash
    32 +            // epoch_boundary_root
    32 +            // shard_block_hash
    32 +            // latest_crosslink_hash
    8 +             // justified_epoch
    32 // justified_block_root
};

#[derive(
    Debug, Clone, PartialEq, Default, Serialize, Hash, Encode, Decode, TreeHash, TestRandom,
)]
pub struct AttestationData {
    pub slot: Slot,
    pub shard: u64,
    pub beacon_block_root: Hash256,
    pub epoch_boundary_root: Hash256,
    pub shard_block_root: Hash256,
    pub latest_crosslink: Crosslink,
    pub justified_epoch: Epoch,
    pub justified_block_root: Hash256,
}

impl Eq for AttestationData {}

impl AttestationData {
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from(&self.hash_tree_root()[..])
    }

    pub fn signable_message(&self, custody_bit: bool) -> Vec<u8> {
        let attestation_data_and_custody_bit = AttestationDataAndCustodyBit {
            data: self.clone(),
            custody_bit,
        };
        attestation_data_and_custody_bit.hash_tree_root()
    }
}

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
