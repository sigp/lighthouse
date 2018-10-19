use bls::{
    PublicKey,
    Signature,
};
use types::{
    Address,
    Hash256,
    ValidatorRecord,
};

use super::proof_of_possession::verify_proof_of_possession;


/// The information gathered from the PoW chain validator registration function.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatorRegistration {
    pub pubkey: PublicKey,
    pub withdrawal_shard: u16,
    pub withdrawal_address: Address,
    pub randao_commitment: Hash256,
    pub proof_of_possession: Signature,
}

impl PartialEq<ValidatorRecord> for ValidatorRegistration {
    fn eq(&self, v: &ValidatorRecord) -> bool {
        (self.pubkey == v.pubkey) &
        (self.withdrawal_shard == v.withdrawal_shard) &
        (self.withdrawal_address == v.withdrawal_address) &
        (self.randao_commitment == v.randao_commitment) &
        (verify_proof_of_possession(&self.proof_of_possession, &v.pubkey))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bls::{
        Keypair,
        Signature,
    };
    use types::{
        Address,
        Hash256,
        ValidatorRecord,
    };
    use hashing::proof_of_possession_hash;

    fn get_proof_of_possession(kp: &Keypair) -> Signature {
        let pop_message = proof_of_possession_hash(&kp.pk.as_bytes());
        Signature::new_hashed(&pop_message, &kp.sk)
    }

    fn get_equal_validator_registrations_and_records()
        -> (ValidatorRegistration, ValidatorRecord)
    {
        let kp = Keypair::random();
        let rego = ValidatorRegistration {
            pubkey: kp.pk.clone(),
            withdrawal_shard: 0,
            withdrawal_address: Address::zero(),
            randao_commitment: Hash256::zero(),
            proof_of_possession: get_proof_of_possession(&kp),
        };
        let record = ValidatorRecord {
            pubkey: rego.pubkey.clone(),
            withdrawal_shard: rego.withdrawal_shard,
            withdrawal_address: rego.withdrawal_address.clone(),
            randao_commitment: rego.randao_commitment.clone(),
            randao_last_change: 0,
            balance: 0,
            status: 0,
            exit_slot: 0,
        };
        (rego, record)
    }

    #[test]
    fn test_validator_registration_and_record_partial_eq() {
        let (rego, record) = get_equal_validator_registrations_and_records();
        assert!(rego == record);

        let (mut rego, record) = get_equal_validator_registrations_and_records();
        let kp = Keypair::random();
        rego.pubkey = kp.pk.clone();
        assert!(rego != record);

        let (mut rego, record) = get_equal_validator_registrations_and_records();
        rego.withdrawal_shard = record.withdrawal_shard + 1;
        assert!(rego != record);

        let (mut rego, record) = get_equal_validator_registrations_and_records();
        rego.withdrawal_address = Address::from(42);
        assert!(rego != record);

        let (mut rego, record) = get_equal_validator_registrations_and_records();
        rego.randao_commitment = Hash256::from(42);
        assert!(rego != record);

        let (mut rego, record) = get_equal_validator_registrations_and_records();
        let kp = Keypair::random();
        rego.proof_of_possession = get_proof_of_possession(&kp);
        assert!(rego != record);
    }
}
