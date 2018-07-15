use super::utils::types::{ Sha256Digest, Bitfield };
use super::rlp::{ RlpStream, Encodable };

pub struct PartialCrosslinkRecord {
    pub shard_id: u16,
    pub shard_block_hash: Sha256Digest,
    pub voter_bitfield: Bitfield
}

impl PartialCrosslinkRecord {
    pub fn zero() -> Self {
        Self {
            shard_id: 0,
            shard_block_hash: Sha256Digest::zero(),
            voter_bitfield: Bitfield::new()
        }
    }
}

/*
 * RLP Encoding
 */
impl Encodable for PartialCrosslinkRecord {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&self.shard_id);
        s.append(&self.shard_block_hash);
        s.append(&self.voter_bitfield);
    }
}


#[cfg(test)]
mod tests {
    use super::super::rlp;
    use super::*;

    #[test]
    fn test_zero() {
        let p = PartialCrosslinkRecord::zero();
        assert_eq!(p.shard_id, 0);
        assert_eq!(p.shard_block_hash.is_zero(), true);
        assert_eq!(p.voter_bitfield.num_true_bits(), 0);
    }

    #[test]
    fn test_rlp_serialization() {
        let mut p = PartialCrosslinkRecord::zero();
        p.shard_id = 1;
        let e = rlp::encode(&p);
        assert_eq!(e.len(), 35);
        assert_eq!(e[0], 1);
        assert_eq!(e[1], 160);
        assert_eq!(e[2..34], [0; 32]);
        assert_eq!(e[34], 128);
    }
}
