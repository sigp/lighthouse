use super::utils::types::Hash256;
use super::attestation_record::AttestationRecord;

pub struct ActiveState {
    pub pending_attestations: Vec<AttestationRecord>,
    pub recent_block_hashes: Vec<Hash256>,
}

impl ActiveState {
    /// Returns a new instance where all fields are empty vectors.
    pub fn zero() -> Self {
        Self {
            pending_attestations: vec![],
            recent_block_hashes: vec![],
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_act_state_zero() {
        let a = ActiveState::zero();
        assert_eq!(a.pending_attestations.len(), 0);
        assert_eq!(a.recent_block_hashes.len(), 0);
    }
}
