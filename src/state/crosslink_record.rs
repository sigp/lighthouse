use super::utils::types::Hash256;

#[derive(Clone)]
pub struct CrosslinkRecord {
    pub dynasty: u64,
    pub hash: Hash256,
}

impl CrosslinkRecord {
    /// Generates a new instance where `dynasty` and `hash` are both zero.
    pub fn zero() -> Self {
        Self {
            dynasty: 0,
            hash: Hash256::zero(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::rlp;
    use super::*;

    #[test]
    fn test_crosslink_record_zero() {
        let c = CrosslinkRecord::zero();
        assert_eq!(c.dynasty, 0);
        assert!(c.hash.is_zero());
    }
}
