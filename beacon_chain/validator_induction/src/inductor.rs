use bls::{PublicKey, verify_proof_of_possession};
use types::{BeaconState, Deposit, ValidatorRecord, ValidatorStatus};
use spec::ChainSpec;

/// The size of a validators deposit in GWei.
pub const DEPOSIT_GWEI: u64 = 32_000_000_000;

#[derive(Debug, PartialEq, Clone)]
pub enum ValidatorInductionError {
    InvalidShard,
    InvaidProofOfPossession,
    InvalidWithdrawalCredentials
}

pub fn process_deposit(
    state: &mut BeaconState,
    deposit: &Deposit,
    spec: &ChainSpec) 
-> Result<usize, ValidatorInductionError> {
    let deposit_input = &deposit.deposit_data.deposit_input;
    let validator_index = state.validator_registry.iter()
        .position(|validator| validator.pubkey == deposit_input.pubkey);
    
    match validator_index {
        // replace withdrawn validator
        Some(i) => {
            if state.validator_registry[i].withdrawal_credentials == deposit_input.withdrawal_credentials {
                state.validator_balances[i] += DEPOSIT_GWEI;
                return Ok(i);
            }
            
            Err(ValidatorInductionError::InvalidWithdrawalCredentials)
        },
        // no withdrawn validators; push a new one on
        None => {        
            let validator = ValidatorRecord {
                pubkey: deposit_input.pubkey.clone(),
                withdrawal_credentials: deposit_input.withdrawal_credentials,
                randao_commitment: deposit_input.randao_commitment,
                randao_layers: 0,
                status: ValidatorStatus::PendingActivation,
                latest_status_change_slot: state.validator_registry_latest_change_slot.clone(),
                exit_count: 0
            };
            
            match min_empty_validator_index(state, spec) {
                Some(i) => {
                    state.validator_registry[i] = validator;
                    state.validator_balances[i] = DEPOSIT_GWEI;
                    Ok(i)
                },
                None => {
                    state.validator_registry.push(validator);
                    state.validator_balances.push(DEPOSIT_GWEI);
                    Ok(state.validator_registry.len() - 1)
                }
            }
        }
    }
}

fn min_empty_validator_index(
    state: &BeaconState,
    spec: &ChainSpec
) -> Option<usize> {    
    for i in 0..state.validator_registry.len() {
        if state.validator_balances[i] == 0 
            && state.validator_registry[i].latest_status_change_slot 
                + spec.zero_balance_validator_ttl <= state.slot {
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    use bls::{Keypair, Signature};
    use hashing::proof_of_possession_hash;
    use types::{Hash256, DepositData, DepositInput};
    
    fn get_deposit() -> Deposit {  
        let kp = Keypair::random();
        let deposit_input = DepositInput {
            pubkey: kp.pk.clone(),
            withdrawal_credentials: Hash256::zero(),
            randao_commitment: Hash256::zero(),
            proof_of_possession: get_proof_of_possession(&kp)
        };
        let deposit_data = DepositData {
            deposit_input: deposit_input,
            value: 0,
            timestamp: 0
        };
        Deposit {
            merkle_branch: Vec::new(),
            merkle_tree_index: 0,
            deposit_data: deposit_data
        }
    }

    /// Generate a proof of possession for some keypair.
    fn get_proof_of_possession(kp: &Keypair) -> Signature {
        let pop_message = proof_of_possession_hash(&kp.pk.as_bytes());
        Signature::new_hashed(&pop_message, &kp.sk)
    }

    #[test]
    fn test_validator_inductor_valid_empty_validators() {
        let mut state = BeaconState::default();
        let deposit = get_deposit();
        let spec = ChainSpec::foundation();

        let result = process_deposit(&mut state, &deposit, &spec);

        assert_eq!(result.unwrap(), 0);
        //assert!(registration_equals_record(&r, &validators[0]));
        //assert_eq!(validators.len(), 1);
    }

    /*
    #[test]
    fn test_validator_inductor_status() {
        let validators = vec![];

        let r = get_registration();

        let mut inductor = ValidatorInductor::new(0, 1024, validators);
        let _ = inductor.induct(&r, ValidatorStatus::PendingActivation);
        let _ = inductor.induct(&r, ValidatorStatus::Active);
        let validators = inductor.to_vec();

        assert!(validators[0].status == ValidatorStatus::PendingActivation);
        assert!(validators[1].status == ValidatorStatus::Active);
        assert_eq!(validators.len(), 2);
    }

    #[test]
    fn test_validator_inductor_valid_all_active_validators() {
        let mut validators = vec![];
        for _ in 0..5 {
            let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
            v.status = ValidatorStatus::Active;
            validators.push(v);
        }

        let r = get_registration();

        let mut inductor = ValidatorInductor::new(0, 1024, validators);
        let result = inductor.induct(&r, ValidatorStatus::PendingActivation);
        let validators = inductor.to_vec();

        assert_eq!(result.unwrap(), 5);
        //assert!(registration_equals_record(&r, &validators[5]));
        assert_eq!(validators.len(), 6);
    }

    #[test]
    fn test_validator_inductor_valid_all_second_validator_withdrawn() {
        let mut validators = vec![];
        let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
        v.status = ValidatorStatus::Active;
        validators.push(v);
        for _ in 0..4 {
            let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
            v.status = ValidatorStatus::Withdrawn;
            validators.push(v);
        }

        let r = get_registration();

        let mut inductor = ValidatorInductor::new(0, 1024, validators);
        let result = inductor.induct(&r, ValidatorStatus::PendingActivation);
        let validators = inductor.to_vec();

        assert_eq!(result.unwrap(), 1);
        //assert!(registration_equals_record(&r, &validators[1]));
        assert_eq!(validators.len(), 5);
    }

    #[test]
    fn test_validator_inductor_valid_all_withdrawn_validators() {
        let mut validators = vec![];
        for _ in 0..5 {
            let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
            v.status = ValidatorStatus::Withdrawn;
            validators.push(v);
        }

        /*
         * Ensure the first validator gets the 0'th slot
         */
        let r = get_registration();
        let mut inductor = ValidatorInductor::new(0, 1024, validators);
        let result = inductor.induct(&r, ValidatorStatus::PendingActivation);
        let validators = inductor.to_vec();
        assert_eq!(result.unwrap(), 0);
        //assert!(registration_equals_record(&r, &validators[0]));

        /*
         * Ensure the second validator gets the 1'st slot
         */
        let r_two = get_registration();
        let mut inductor = ValidatorInductor::new(0, 1024, validators);
        let result = inductor.induct(&r_two, ValidatorStatus::PendingActivation);
        let validators = inductor.to_vec();
        assert_eq!(result.unwrap(), 1);
        //assert!(registration_equals_record(&r_two, &validators[1]));
        assert_eq!(validators.len(), 5);
    }

    #[test]
    fn test_validator_inductor_shard_too_high() {
        let validators = vec![];

        let mut r = get_registration();
        r.withdrawal_shard = 1025;

        let mut inductor = ValidatorInductor::new(0, 1024, validators);
        let result = inductor.induct(&r, ValidatorStatus::PendingActivation);
        let validators = inductor.to_vec();

        assert_eq!(result, Err(ValidatorInductionError::InvalidShard));
        assert_eq!(validators.len(), 0);
    }

    #[test]
    fn test_validator_inductor_shard_proof_of_possession_failure() {
        let validators = vec![];

        let mut r = get_registration();
        let kp = Keypair::random();
        r.proof_of_possession = get_proof_of_possession(&kp);

        let mut inductor = ValidatorInductor::new(0, 1024, validators);
        let result = inductor.induct(&r, ValidatorStatus::PendingActivation);
        let validators = inductor.to_vec();

        assert_eq!(
            result,
            Err(ValidatorInductionError::InvaidProofOfPossession)
        );
        assert_eq!(validators.len(), 0);
    }
    */
}
