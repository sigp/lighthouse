use super::bls::{Keypair, PublicKey};
use super::ssz::TreeHash;
use super::{Address, Hash256};

pub const HASH_SSZ_VALIDATOR_RECORD_LENGTH: usize = {
    32 +                // pubkey.to_bytes(32, 'big')
    2 +                 // withdrawal_shard.to_bytes(2, 'big')
    20 +                // withdrawal_address
    32 +                // randao_commitment
    16 +                // balance.to_bytes(16, 'big')
    16 +                // start_dynasty.to_bytes(8, 'big')
    8 // end_dynasty.to_bytes(8, 'big')
};

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
    pub withdrawal_shard: u16,
    pub withdrawal_address: Address,
    pub randao_commitment: Hash256,
    pub randao_last_change: u64,
    pub balance: u64,
    pub status: u8,
    pub exit_slot: u64,
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
            randao_last_change: 0,
            balance: 0,
            status: 0,
            exit_slot: 0,
        };
        (s, keypair)
    }
}

impl TreeHash for ValidatorRecord {
    fn tree_hash(&self) -> Vec<u8> {
        let mut ssz = Vec::with_capacity(HASH_SSZ_VALIDATOR_RECORD_LENGTH);

        // From python sample: "val.pubkey.to_bytes(32, 'big')"
        // TODO:
        // Need to actually convert (szz) pubkey into a big-endian 32 byte
        // array.
        // Also, our ValidatorRecord seems to be missing the start_dynasty
        // and end_dynasty fields
        let pub_key_bytes = &mut self.pubkey.as_bytes();
        pub_key_bytes.resize(32, 0);
        ssz.append(pub_key_bytes);

        ssz.append(&mut self.withdrawal_shard.tree_hash());
        ssz.append(&mut self.withdrawal_address.tree_hash());
        ssz.append(&mut self.randao_commitment.tree_hash());

        let mut balance = self.balance.tree_hash();
        balance.resize(16, 0);
        ssz.append(&mut balance);

        ssz.tree_hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_record_zero_rand_keypair() {
        let (v, _kp) = ValidatorRecord::zero_with_thread_rand_keypair();
        assert_eq!(v.withdrawal_shard, 0);
        assert!(v.withdrawal_address.is_zero());
        assert!(v.randao_commitment.is_zero());
        assert_eq!(v.randao_last_change, 0);
        assert_eq!(v.balance, 0);
        assert_eq!(v.status, 0);
        assert_eq!(v.exit_slot, 0);
    }

    #[test]
    fn test_validator_record_ree_hash() {
        let (v, _kp) = ValidatorRecord::zero_with_thread_rand_keypair();
        let h = v.tree_hash();

        // TODO: should check a known hash result value
        assert_eq!(h.len(), 32);
    }
}
