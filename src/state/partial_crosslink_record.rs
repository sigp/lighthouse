use std::io::Cursor;
use super::utils::types::{ Sha256Digest, Bitfield };
use super::rlp::{ RlpStream, Encodable };
use super::bytes::{ BytesMut, BufMut, Buf };

#[derive(Eq, Clone)]
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
    
    pub fn new_from_vote_key(vote_key: &Vec<u8>, voter_bitfield: Bitfield)
        -> Self 
    {
        let mut buf = Cursor::new(vote_key);
        let mut hash_bytes = [0_u8; 32];
        buf.copy_to_slice(&mut hash_bytes);
        let shard_id: u16 = buf.get_u16_be();
        let shard_block_hash = Sha256Digest::from_slice(&hash_bytes);
        Self {
            shard_id,
            shard_block_hash,
            voter_bitfield
        }
    }

    pub fn vote_key(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(34);
        buf.extend_from_slice(&self.shard_block_hash.to_vec());
        buf.put_u16_be(self.shard_id);
        buf.to_vec()
    }
}

impl PartialEq for PartialCrosslinkRecord {
    fn eq(&self, other: &PartialCrosslinkRecord) 
    -> bool
    {
        (self.shard_id == other.shard_id) & 
            (self.shard_block_hash == other.shard_block_hash)
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
    fn test_new_from_vote_key() {
        let mut p = PartialCrosslinkRecord::zero();
        p.shard_id = 223;
        p.shard_block_hash = Sha256Digest::random();

        let mut bitfield = Bitfield::new();
        bitfield.set_bit(&42, &true);

        let vk = p.vote_key();
        let np = PartialCrosslinkRecord::new_from_vote_key(
            &vk, bitfield.clone());

        assert_eq!(np.shard_id, p.shard_id);
        assert_eq!(np.shard_block_hash, p.shard_block_hash);
        assert!(np.voter_bitfield == bitfield);
    }
    
    #[test]
    fn test_vote_key_formatting() {
        let mut p = PartialCrosslinkRecord::zero();
        let vk = p.vote_key();
        assert_eq!(vk.len(), 34);
        assert_eq!(vk, vec![0; 34]);

        p.shard_id = 1; 
        let vk = p.vote_key();
        assert_eq!(vk.len(), 34);
        assert_eq!(vk[0..33].to_vec(), vec![0; 33]);
        assert_eq!(vk[33], 1);
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
