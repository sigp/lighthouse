use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use super::Hash256;
use crate::test_utils::TestRandom;
use rand::RngCore;

pub const SSZ_ATTESTION_DATA_LENGTH: usize = {
    8 +             // slot
    8 +             // shard
    32 +            // beacon_block_hash
    32 +            // epoch_boundary_hash
    32 +            // shard_block_hash
    32 +            // latest_crosslink_hash
    8 +             // justified_slot
    32 // justified_block_hash
};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AttestationData {
    pub slot: u64,
    pub shard: u64,
    pub beacon_block_hash: Hash256,
    pub epoch_boundary_hash: Hash256,
    pub shard_block_hash: Hash256,
    pub latest_crosslink_hash: Hash256,
    pub justified_slot: u64,
    pub justified_block_hash: Hash256,
}

impl AttestationData {
    pub fn zero() -> Self {
        Self {
            slot: 0,
            shard: 0,
            beacon_block_hash: Hash256::zero(),
            epoch_boundary_hash: Hash256::zero(),
            shard_block_hash: Hash256::zero(),
            latest_crosslink_hash: Hash256::zero(),
            justified_slot: 0,
            justified_block_hash: Hash256::zero(),
        }
    }

    // TODO: Implement this as a merkle root, once tree_ssz is implemented.
    // https://github.com/sigp/lighthouse/issues/92
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::zero()
    }
}

impl Encodable for AttestationData {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slot);
        s.append(&self.shard);
        s.append(&self.beacon_block_hash);
        s.append(&self.epoch_boundary_hash);
        s.append(&self.shard_block_hash);
        s.append(&self.latest_crosslink_hash);
        s.append(&self.justified_slot);
        s.append(&self.justified_block_hash);
    }
}

impl Decodable for AttestationData {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (slot, i) = u64::ssz_decode(bytes, i)?;
        let (shard, i) = u64::ssz_decode(bytes, i)?;
        let (beacon_block_hash, i) = Hash256::ssz_decode(bytes, i)?;
        let (epoch_boundary_hash, i) = Hash256::ssz_decode(bytes, i)?;
        let (shard_block_hash, i) = Hash256::ssz_decode(bytes, i)?;
        let (latest_crosslink_hash, i) = Hash256::ssz_decode(bytes, i)?;
        let (justified_slot, i) = u64::ssz_decode(bytes, i)?;
        let (justified_block_hash, i) = Hash256::ssz_decode(bytes, i)?;

        let attestation_data = AttestationData {
            slot,
            shard,
            beacon_block_hash,
            epoch_boundary_hash,
            shard_block_hash,
            latest_crosslink_hash,
            justified_slot,
            justified_block_hash,
        };
        Ok((attestation_data, i))
    }
}

impl<T: RngCore> TestRandom<T> for AttestationData {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            slot: <_>::random_for_test(rng),
            shard: <_>::random_for_test(rng),
            beacon_block_hash: <_>::random_for_test(rng),
            epoch_boundary_hash: <_>::random_for_test(rng),
            shard_block_hash: <_>::random_for_test(rng),
            latest_crosslink_hash: <_>::random_for_test(rng),
            justified_slot: <_>::random_for_test(rng),
            justified_block_hash: <_>::random_for_test(rng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::ssz::ssz_encode;
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};

    #[test]
    pub fn test_ssz_round_trip() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = AttestationData::random_for_test(&mut rng);

        let bytes = ssz_encode(&original);
        let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
