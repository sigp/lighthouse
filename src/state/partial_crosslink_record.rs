use super::utils::types::{ Sha256Digest, Bitfield };
use super::rlp::{ RlpStream, Encodable };

pub struct PartialCrosslinkRecord {
    pub shard_id: u16,
    pub shard_block_hash: Sha256Digest,
    pub voter_bitfield: Bitfield
}

impl PartialCrosslinkRecord {
    pub fn new_for_shard(shard_id: u16, 
               shard_block_hash: Sha256Digest) -> PartialCrosslinkRecord {
        PartialCrosslinkRecord {
            shard_id: shard_id,
            shard_block_hash: shard_block_hash,
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
    fn test_new_for_shard() {
        let id = 1;
        let hash = Sha256Digest::random();
        let p = PartialCrosslinkRecord::new_for_shard(id, hash);
        assert_eq!(p.shard_id, id);
        assert_eq!(p.shard_block_hash, hash);
    }

    #[test]
    fn test_rlp_serialization() {
        let p = PartialCrosslinkRecord {
            shard_id: 1,
            shard_block_hash: Sha256Digest::zero(),
            voter_bitfield: Bitfield::new()
        };
        let e = rlp::encode(&p);
        assert_eq!(e.len(), 35);
        assert_eq!(e[0], 1);
        assert_eq!(e[1], 160);
        assert_eq!(e[2..34], [0; 32]);
        assert_eq!(e[34], 128);
    }
}
