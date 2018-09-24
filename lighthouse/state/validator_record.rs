extern crate rand;

use super::utils::types::{ Hash256, Address, U256 };
use super::bls::{ PublicKey, Keypair };

pub struct ValidatorRecord {
    pub pubkey: PublicKey,
    pub withdrawal_shard: u16,
    pub withdrawal_address: Address,
    pub randao_commitment: Hash256,
    pub balance: U256,
    pub start_dynasty: u64,
    pub end_dynasty: u64,
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
            withdrawal_shard: 0,
            withdrawal_address: Address::zero(),
            randao_commitment: Hash256::zero(),
            balance: U256::zero(),
            start_dynasty: 0,
            end_dynasty: 0,
        };
        (s, keypair)
    }
}

impl Clone for ValidatorRecord {
    fn clone(&self) -> ValidatorRecord {
        ValidatorRecord {
            pubkey: self.pubkey.clone(),
            ..*self

        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_record_zero_rand_keypair() {
        let (v, _kp) = ValidatorRecord::zero_with_thread_rand_keypair();
        // TODO: check keys
        assert_eq!(v.withdrawal_shard, 0);
        assert!(v.withdrawal_address.is_zero());
        assert!(v.randao_commitment.is_zero());
        assert!(v.balance.is_zero());
        assert_eq!(v.start_dynasty, 0);
        assert_eq!(v.end_dynasty, 0);
    }
}
