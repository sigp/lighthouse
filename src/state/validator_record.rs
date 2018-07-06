use super::utils::types::{ Sha256Digest, Address };
use super::utils::bls::PublicKey;

pub struct ValidatorRecord {
    pub pubkey: PublicKey,
    pub withdrawal_shard: u16,
    pub withdrawal_address: Address,
    pub randao_commitment: Sha256Digest,
    pub balance: u64,
    pub switch_dynasty: u64
}

impl ValidatorRecord {
    pub fn new(pubkey: PublicKey,
               withdrawal_shard: u16,
               withdrawal_address: Address, 
               randao_commitment: Sha256Digest,
               balance: u64,
               switch_dynasty: u64) -> ValidatorRecord {
        ValidatorRecord {
            pubkey: pubkey,
            withdrawal_shard: withdrawal_shard,
            withdrawal_address: withdrawal_address,
            randao_commitment: randao_commitment,
            balance: balance,
            switch_dynasty: switch_dynasty
        }
    }
}


#[cfg(test)]
mod tests {
    extern crate rand;

    use super::*;
    use super::super::utils::bls::Keypair;
    use self::rand::{ SeedableRng, XorShiftRng };

    #[test]
    fn test_new() {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);
        let keypair = Keypair::generate(&mut rng);
        let withdrawal_shard = 1;
        let withdrawal_address = Address::random();
        let randao_commitment = Sha256Digest::random();
        let balance = 100;
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
}
