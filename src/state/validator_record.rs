extern crate rand;

use super::utils::types::{ Sha256Digest, Address, U256 };
use super::utils::bls::{ PublicKey, Keypair };
use super::rlp::{ RlpStream, Encodable };

use self::rand::thread_rng;

pub struct ValidatorRecord {
    pub pubkey: PublicKey,
    pub withdrawal_shard: u16,
    pub withdrawal_address: Address,
    pub randao_commitment: Sha256Digest,
    pub balance: U256,
    pub switch_dynasty: u64
}

impl ValidatorRecord {
    pub fn new(pubkey: PublicKey,
               withdrawal_shard: u16,
               withdrawal_address: Address, 
               randao_commitment: Sha256Digest,
               balance: U256,
               switch_dynasty: u64) 
        -> Self 
    {
        Self {
            pubkey,
            withdrawal_shard,
            withdrawal_address,
            randao_commitment,
            balance,
            switch_dynasty
        }
    }

    pub fn zero_with_thread_rand_pub_key() -> Self {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        Self {
            pubkey: keypair.public,
            withdrawal_shard: 0,
            withdrawal_address: Address::zero(),
            randao_commitment: Sha256Digest::zero(),
            balance: U256::zero(),
            switch_dynasty: 0
        }
    }
    
    pub fn zero_with_thread_rand_keypair() -> (Self, Keypair) {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let s = Self {
            pubkey: keypair.public.clone(),
            withdrawal_shard: 0,
            withdrawal_address: Address::zero(),
            randao_commitment: Sha256Digest::zero(),
            balance: U256::zero(),
            switch_dynasty: 0
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

/*
 * RLP Encoding
 */
impl Encodable for ValidatorRecord {
    fn rlp_append(&self, s: &mut RlpStream) {
        // s.append(&self.pubkey);      // TODO: serialize this
        s.append(&self.withdrawal_shard);
        s.append(&self.withdrawal_address);
        s.append(&self.randao_commitment);
        s.append(&self.balance);
        s.append(&self.switch_dynasty);
    }
}


#[cfg(test)]
mod tests {
    use super::super::rlp;
    extern crate rand;

    use super::*;
    use super::super::
        utils::test_helpers::get_dangerous_test_keypair;

    #[test]
    fn test_new() {
        let keypair = get_dangerous_test_keypair();;
        let withdrawal_shard = 1;
        let withdrawal_address = Address::random();
        let randao_commitment = Sha256Digest::random();
        let balance = U256::from(100);
        let switch_dynasty = 10;

        let v = ValidatorRecord::new(
            keypair.public, 
            withdrawal_shard, 
            withdrawal_address, 
            randao_commitment, 
            balance, 
            switch_dynasty);
        // TODO: figure out how to compare keys
        // assert_eq!(v.pubkey, keypair.public);
        assert_eq!(v.withdrawal_shard, withdrawal_shard);
        assert_eq!(v.withdrawal_address, withdrawal_address);
        assert_eq!(v.randao_commitment, randao_commitment);
        assert_eq!(v.balance, balance);
        assert_eq!(v.switch_dynasty, switch_dynasty);
    }
    
    #[test]
    fn test_rlp_serialization() {
        let keypair = get_dangerous_test_keypair();
        let v = ValidatorRecord {
            pubkey: keypair.public,
            withdrawal_shard: 100,
            withdrawal_address: Address::zero(),
            randao_commitment: Sha256Digest::zero(),
            balance: U256::from(120),
            switch_dynasty: 30
        };
        let e = rlp::encode(&v);
        assert_eq!(e.len(), 57);    // TODO: fix when pubkey is serialized
        // TODO: test for serialized pubkey
        assert_eq!(e[0], 100);
        assert_eq!(e[1], 148);
        assert_eq!(e[2..22], [0; 20]);
        assert_eq!(e[22], 160);
        assert_eq!(e[23..55], [0; 32]);
        assert_eq!(e[55], 120);
        assert_eq!(e[56], 30);
    }
}
