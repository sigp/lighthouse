use types::{
    ValidatorRecord,
    ValidatorStatus,
};

use super::proof_of_possession::verify_proof_of_possession;
use super::registration::ValidatorRegistration;

/// The size of a validators deposit in GWei.
pub const DEPOSIT_GWEI: u64 = 32_000_000_000;

/// Inducts validators into a `CrystallizedState`.
pub struct ValidatorInductor<'a> {
    pub current_slot: u64,
    pub shard_count: u16,
    validators: &'a mut Vec<ValidatorRecord>,
    empty_validator_start: usize,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ValidatorInductionError {
    InvalidShard,
    InvaidProofOfPossession,
}

impl<'a> ValidatorInductor<'a> {
    pub fn new(current_slot: u64, shard_count: u16, validators: &'a mut Vec<ValidatorRecord>)
        -> Self
    {
        Self {
            current_slot,
            shard_count,
            validators,
            empty_validator_start: 0,
        }
    }

    /// Attempt to induct a validator into the CrystallizedState.
    ///
    /// Returns an error if the registration is invalid, otherwise returns the index of the
    /// validator in `CrystallizedState.validators`.
    pub fn induct(&mut self, rego: &ValidatorRegistration)
        -> Result<usize, ValidatorInductionError>
    {
        let v = self.process_registration(rego)?;
        Ok(self.add_validator(v))
    }

    /// Verify a `ValidatorRegistration` and return a `ValidatorRecord` if valid.
    fn process_registration(&self, r: &ValidatorRegistration)
        -> Result<ValidatorRecord, ValidatorInductionError>
    {
        /*
         * Ensure withdrawal shard is not too high.
         */
        if r.withdrawal_shard > self.shard_count {
            return Err(ValidatorInductionError::InvalidShard)
        }

        /*
         * Prove validator has knowledge of their secret key.
         */
        if !verify_proof_of_possession(&r.proof_of_possession, &r.pubkey) {
            return Err(ValidatorInductionError::InvaidProofOfPossession)
        }

        Ok(ValidatorRecord {
            pubkey: r.pubkey.clone(),
            withdrawal_shard: r.withdrawal_shard,
            withdrawal_address: r.withdrawal_address,
            randao_commitment: r.randao_commitment,
            randao_last_change: self.current_slot,
            balance: DEPOSIT_GWEI,
            status: ValidatorStatus::PendingActivation as u8,
            exit_slot: 0,
        })
    }

    /// Returns the index of the first `ValidatorRecord` in the `CrystallizedState` where
    /// `validator.status == Withdrawn`. If no such record exists, `None` is returned.
    fn first_withdrawn_validator(&mut self)
        -> Option<usize>
    {
        for i in self.empty_validator_start..self.validators.len() {
            if self.validators[i].status == ValidatorStatus::Withdrawn as u8 {
                self.empty_validator_start = i + 1;
                return Some(i)
            }
        }
        None
    }

    /// Adds a `ValidatorRecord` to the `CrystallizedState` by replacing first validator where
    /// `validator.status == Withdraw`. If no such withdrawn validator exists, adds the new
    /// validator to the end of the list.
    fn add_validator(&mut self, v: ValidatorRecord)
        -> usize
    {
        match self.first_withdrawn_validator() {
            Some(i) => {
                self.validators[i] = v;
                i
            }
            None => {
                self.validators.push(v);
                self.validators.len() - 1
            }
        }
    }

    fn to_ref(self)
        -> &'a Vec<ValidatorRecord>
    {
        self.validators
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
    };
    use hashing::proof_of_possession_hash;

    /// Generate a proof of possession for some keypair.
    fn get_proof_of_possession(kp: &Keypair) -> Signature {
        let pop_message = proof_of_possession_hash(&kp.pk.as_bytes());
        Signature::new_hashed(&pop_message, &kp.sk)
    }

    /// Generate a basic working ValidatorRegistration for use in tests.
    fn get_registration() -> ValidatorRegistration {
        let kp = Keypair::random();
        ValidatorRegistration {
            pubkey: kp.pk.clone(),
            withdrawal_shard: 0,
            withdrawal_address: Address::zero(),
            randao_commitment: Hash256::zero(),
            proof_of_possession: get_proof_of_possession(&kp),
        }
    }

    /// Induct a validator using the ValidatorInductor, return the result.
    fn do_induction(validator_rego: &ValidatorRegistration,
                    validators: &mut Vec<ValidatorRecord>,
                    current_slot: u64,
                    shard_count: u16)
        -> Result<usize, ValidatorInductionError>
    {
        let mut inductor = ValidatorInductor::new(
            current_slot,
            shard_count,
            validators);
        inductor.induct(&validator_rego)
    }

    #[test]
    fn test_validator_inductor_valid_empty_validators() {
        let mut validators = vec![];

        let r = get_registration();

        let result = do_induction(&r, &mut validators, 0, 1024);

        assert_eq!(result.unwrap(), 0);
        assert_eq!(r, validators[0]);
        assert_eq!(validators.len(), 1);
    }

    #[test]
    fn test_validator_inductor_valid_all_active_validators() {
        let mut validators = vec![];
        for _ in 0..5 {
            let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
            v.status = ValidatorStatus::Active as u8;
            validators.push(v);
        }

        let r = get_registration();

        let result = do_induction(&r, &mut validators, 0, 1024);

        assert_eq!(result.unwrap(), 5);
        assert_eq!(r, validators[5]);
        assert_eq!(validators.len(), 6);
    }

    #[test]
    fn test_validator_inductor_valid_all_second_validator_withdrawn() {
        let mut validators = vec![];
        let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
        v.status = ValidatorStatus::Active as u8;
        validators.push(v);
        for _ in 0..4 {
            let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
            v.status = ValidatorStatus::Withdrawn as u8;
            validators.push(v);
        }

        let r = get_registration();

        let result = do_induction(&r, &mut validators, 0, 1024);

        assert_eq!(result.unwrap(), 1);
        assert_eq!(r, validators[1]);
        assert_eq!(validators.len(), 5);
    }

    #[test]
    fn test_validator_inductor_valid_all_withdrawn_validators() {
        let mut validators = vec![];
        for _ in 0..5 {
            let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
            v.status = ValidatorStatus::Withdrawn as u8;
            validators.push(v);
        }

        /*
         * Ensure the first validator gets the 0'th slot
         */
        let r = get_registration();
        let result = do_induction(&r, &mut validators, 0, 1024);
        assert_eq!(result.unwrap(), 0);
        assert_eq!(r, validators[0]);
        assert_eq!(validators.len(), 5);

        /*
         * Ensure the second validator gets the 1'st slot
         */
        let r_two = get_registration();
        let result = do_induction(&r_two, &mut validators, 0, 1024);
        assert_eq!(result.unwrap(), 1);
        assert_eq!(r_two, validators[1]);
        assert_eq!(validators.len(), 5);
    }

    #[test]
    fn test_validator_inductor_shard_too_high() {
        let mut validators = vec![];

        let mut r = get_registration();
        r.withdrawal_shard = 1025;

        let result = do_induction(&r, &mut validators, 0, 1024);

        assert_eq!(result, Err(ValidatorInductionError::InvalidShard));
        assert_eq!(validators.len(), 0);
    }

    #[test]
    fn test_validator_inductor_shard_proof_of_possession_failure() {
        let mut validators = vec![];

        let mut r = get_registration();
        let kp = Keypair::random();
        r.proof_of_possession = get_proof_of_possession(&kp);

        let result = do_induction(&r, &mut validators, 0, 1024);

        assert_eq!(result, Err(ValidatorInductionError::InvaidProofOfPossession));
        assert_eq!(validators.len(), 0);
    }
}
