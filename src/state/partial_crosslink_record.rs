use super::utils::types::{ Sha256Digest, Bitfield };

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
            voter_bitfield: Vec::new()
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
        let p = PartialCrosslinkRecord::new_for_shard(id, hash);
        assert_eq!(p.shard_id, id);
        assert_eq!(p.shard_block_hash, hash);
    }
}
