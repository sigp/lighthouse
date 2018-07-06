use super::utils::types::Sha256Digest;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let epoch = 1;
        let hash = Sha256Digest::random();
        let c = CrosslinkRecord::new(epoch, hash);
        assert_eq!(c.epoch, epoch);
        assert_eq!(c.hash, hash);
    }
}
