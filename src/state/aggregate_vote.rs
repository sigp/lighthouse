use super::utils::types::*;
use super::utils::bls::AggregateSignature;
use super::rlp::{ RlpStream, Encodable };
use super::bytes::{ BytesMut, BufMut };

pub struct AggregateVote {
    pub shard_id: u16,
    pub shard_block_hash: Sha256Digest,
    pub notary_bitfield: Bitfield,
    pub aggregate_sig: AggregateSignature,
}

impl AggregateVote {
    pub fn zero() -> Self {
        Self {
            shard_id: 0,
            shard_block_hash: Sha256Digest::zero(),
            notary_bitfield: Bitfield::new(),
            aggregate_sig: AggregateSignature::new()
        }
    }

    pub fn vote_key(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(34);
        buf.extend_from_slice(&self.shard_block_hash.to_vec());
        buf.put_u16_be(self.shard_id);
        buf.to_vec()
    }
}

/*
 * RLP Encoding
 */
impl Encodable for AggregateVote {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&self.shard_id);
        s.append(&self.shard_block_hash);
        s.append(&self.notary_bitfield);
        // s.append(&self.aggregate_sig);   // TODO: represent this in RLP
    }
}


#[cfg(test)]
mod tests {
    use super::super::rlp;
    use super::*;

    #[test]
    fn test_zero_fn() {
        let v = AggregateVote::zero();
        // TODO: test this better
        assert_eq!(v.shard_id, 0);
    }
    
    #[test]
    fn test_rlp_serialization() {
        let a = AggregateVote {
            shard_id: 100,
            shard_block_hash: Sha256Digest::zero(),
            notary_bitfield: Bitfield::new(),
            aggregate_sig: AggregateSignature::new()
        };
        let e = rlp::encode(&a);
        assert_eq!(e.len(), 35);
        assert_eq!(e[0], 100);
        assert_eq!(e[1], 160);
        assert_eq!(e[2..34], [0; 32]);
        assert_eq!(e[34], 128);
    }
}
