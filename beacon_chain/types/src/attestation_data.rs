use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use super::Hash256;

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

#[derive(Debug, Clone, PartialEq)]
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

#[cfg(test)]
mod tests {
    use super::super::ssz::ssz_encode;
    use super::*;

    #[test]
    pub fn test_attestation_record_ssz_round_trip() {
        let original = AttestationData {
            slot: 42,
            shard: 16,
            beacon_block_hash: Hash256::from("beacon".as_bytes()),
            epoch_boundary_hash: Hash256::from("epoch".as_bytes()),
            shard_block_hash: Hash256::from("shard".as_bytes()),
            latest_crosslink_hash: Hash256::from("xlink".as_bytes()),
            justified_slot: 8,
            justified_block_hash: Hash256::from("justified".as_bytes()),
        };

        let ssz = ssz_encode(&original);

        let (decoded, _) = AttestationData::ssz_decode(&ssz, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
