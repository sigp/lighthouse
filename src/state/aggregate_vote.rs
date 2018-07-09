use super::utils::types::*;
use super::utils::bls::AggregateSignature;
use super::rlp::{ RlpStream, Encodable };

pub struct AggregateVote {
    pub shard_id: u16,
    pub shard_block_hash: Sha256Digest,
    pub notary_bitfield: Bitfield,
    pub aggregate_sig: AggregateSignature,
}

impl AggregateVote {
    pub fn new_for_shard(shard_id: u16, 
                         shard_block_hash: Sha256Digest) 
        -> AggregateVote {
        AggregateVote {
            shard_id: shard_id,
            shard_block_hash: shard_block_hash,
            notary_bitfield: Vec::new(),
            aggregate_sig: AggregateSignature::new()
        }
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
    fn test_new_for_shard() {
        let id = 1;
        let hash = Sha256Digest::random();
        let v = AggregateVote::new_for_shard(id, hash);
        assert_eq!(v.shard_id, id);
        assert_eq!(v.shard_block_hash, hash);
    }
    
    #[test]
    fn test_serialization() {
        let a = AggregateVote {
            shard_id: 100,
            shard_block_hash: Sha256Digest::zero(),
            notary_bitfield: Vec::new(),
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
