use super::rlp::{ RlpStream, Encodable };
use super::utils::types::*;

pub struct RecentPropserRecord {
    pub index: u32,     // TODO: make u24
    pub randao_commitment: Sha256Digest,
    pub balance_delta: u32, // TODO: make u24
}

impl RecentPropserRecord {
    pub fn new(index: u32, 
               randao_commitment: Sha256Digest, 
               balance_delta: u32) -> RecentPropserRecord {
        RecentPropserRecord {
            index: index,
            randao_commitment: randao_commitment,
            balance_delta: balance_delta
        }
    }
}

/*
 * RLP Encoding
 */
impl Encodable for RecentPropserRecord {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&self.index);
        s.append(&self.randao_commitment);
        s.append(&self.balance_delta);
    }
}


#[cfg(test)]
mod tests {
    use super::super::rlp;
    use super::*;

    #[test]
    fn test_serialization() {
        let index = 1;
        let randao_commitment = Sha256Digest::zero();
        let balance_delta = 99;
        let r = RecentPropserRecord::new(index, randao_commitment, balance_delta);
        let e = rlp::encode(&r);
        assert_eq!(e.len(), 35);
        assert_eq!(e[0], 1);
        assert_eq!(e[1], 160);
        assert_eq!(e[2..34], [0; 32]);
        assert_eq!(e[34], 99);
    }
}
