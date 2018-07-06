use super::utils::types::*;
use super::utils::bls::AggregateSignature;

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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_for_shard() {
        let id = 1;
        let hash = Sha256Digest::random();
        let v = AggregateVote::new_for_shard(id, hash);
        assert_eq!(v.shard_id, id);
        assert_eq!(v.shard_block_hash, hash);
    }
}
