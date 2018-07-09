use super::utils::types::Sha256Digest;
use super::rlp::{ RlpStream, Encodable };

pub struct CrosslinkRecord {
    pub epoch: u64,
    pub hash: Sha256Digest
}

impl CrosslinkRecord {
    pub fn new(epoch: u64, hash: Sha256Digest) -> CrosslinkRecord {
        CrosslinkRecord {
            epoch: epoch,
            hash: hash
        }
    }
}

/*
 * RLP Encoding
 */
impl Encodable for CrosslinkRecord {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&self.epoch);
        s.append(&self.hash);
    }
}

#[cfg(test)]
mod tests {
    use super::super::rlp;
    use super::*;

    #[test]
    fn test_new() {
        let epoch = 1;
        let hash = Sha256Digest::random();
        let c = CrosslinkRecord::new(epoch, hash);
        assert_eq!(c.epoch, epoch);
        assert_eq!(c.hash, hash);
    }

    #[test]
    fn test_serialization() {
        let c = CrosslinkRecord {
            epoch: 100,
            hash: Sha256Digest::zero()
        };
        let e = rlp::encode(&c);
        assert_eq!(e.len(), 34);
        assert_eq!(e[0], 100);
        assert_eq!(e[1], 160);
        assert_eq!(e[2..34], [0; 32]);
    }
}
