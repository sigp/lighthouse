use super::bls::{Keypair, PublicKey};
use super::{Hash256};

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ValidatorStatus {
    PendingActivation = 0,
    Active = 1,
    PendingExit = 2,
    PendingWithdraw = 3,
    Withdrawn = 5,
    Penalized = 127,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidatorRecord {
    pub pubkey: PublicKey,
    pub withdrawal_credentials: Hash256,
    pub randao_commitment: Hash256,
    pub randao_skips: u64,
    pub balance: u64,
    pub status: u64,
    pub latest_status_change_slot: u64,
    pub exit_count: u64
}

impl ValidatorRecord {
    /// Generates a new instance where the keypair is generated using
    /// `rand::thread_rng` entropy and all other fields are set to zero.
    ///
    /// Returns the new instance and new keypair.
    pub fn zero_with_thread_rand_keypair() -> (Self, Keypair) {
        let keypair = Keypair::random();
        let s = Self {
            pubkey: keypair.pk.clone(),
            withdrawal_credentials: Hash256::zero(),
            randao_commitment: Hash256::zero(),
            randao_skips: 0,
            balance: 0,
            status: 0,
            latest_status_change_slot: 0,
            exit_count: 0
        };
        (s, keypair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_record_zero_rand_keypair() {
        let (v, _kp) = ValidatorRecord::zero_with_thread_rand_keypair();
        assert!(v.withdrawal_credentials.is_zero());
        assert!(v.randao_commitment.is_zero());
        assert_eq!(v.randao_skips, 0);
        assert_eq!(v.balance, 0);
        assert_eq!(v.status, 0);
        assert_eq!(v.latest_status_change_slot, 0);
        assert_eq!(v.exit_count, 0);
    }
}
