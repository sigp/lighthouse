use super::Hash256;

#[derive(Clone)]
pub struct CrosslinkRecord {
    pub recently_changed: bool,
    pub slot: u64,
    pub hash: Hash256,
}

impl CrosslinkRecord {
    /// Generates a new instance where `dynasty` and `hash` are both zero.
    pub fn zero() -> Self {
        Self {
            recently_changed: false,
            slot: 0,
            hash: Hash256::zero(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crosslink_record_zero() {
        let c = CrosslinkRecord::zero();
        assert_eq!(c.recently_changed, false);
        assert_eq!(c.slot, 0);
        assert!(c.hash.is_zero());
    }
}
