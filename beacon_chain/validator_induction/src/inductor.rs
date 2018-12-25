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
    let deposit_data = &deposit.deposit_data;
        
    if !verify_proof_of_possession(&deposit_input.proof_of_possession, &deposit_input.pubkey) {
        return Err(ValidatorInductionError::InvaidProofOfPossession);
    }
    
    let validator_index = state.validator_registry.iter()
        .position(|validator| validator.pubkey == deposit_input.pubkey);
    
    match validator_index {
        Some(i) => {
            if state.validator_registry[i].withdrawal_credentials == deposit_input.withdrawal_credentials {
                state.validator_balances[i] += deposit_data.value;
                return Ok(i);
            }
            
            Err(ValidatorInductionError::InvalidWithdrawalCredentials)
        },
        None => {        
            let validator = ValidatorRecord {
                pubkey: deposit_input.pubkey.clone(),
                withdrawal_credentials: deposit_input.withdrawal_credentials,
                randao_commitment: deposit_input.randao_commitment,
                randao_layers: 0,
                status: ValidatorStatus::PendingActivation,
                latest_status_change_slot: state.validator_registry_latest_change_slot,
                exit_count: 0
            };
            
            match min_empty_validator_index(state, spec) {
                Some(i) => {
                    state.validator_registry[i] = validator;
                    state.validator_balances[i] = deposit_data.value;
                    Ok(i)
                },
                None => {
                    state.validator_registry.push(validator);
                    state.validator_balances.push(deposit_data.value);
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

    use bls::{Keypair, Signature, create_proof_of_possession};
    use hashing::canonical_hash;
    use types::{Hash256, DepositData, DepositInput};
    
    fn get_deposit() -> Deposit {  
        let kp = Keypair::random();
        let deposit_input = DepositInput {
            pubkey: kp.pk.clone(),
            withdrawal_credentials: Hash256::zero(),
            randao_commitment: Hash256::zero(),
            proof_of_possession: create_proof_of_possession(&kp)
        };
        let deposit_data = DepositData {
            deposit_input: deposit_input,
            value: DEPOSIT_GWEI,
            timestamp: 0
        };
        Deposit {
            merkle_branch: Vec::new(),
            merkle_tree_index: 0,
            deposit_data: deposit_data
        }
    }

    fn deposit_equals_record(dep: &Deposit, rec: &ValidatorRecord) -> bool {
        (dep.deposit_data.deposit_input.pubkey == rec.pubkey)
            & (dep.deposit_data.deposit_input.withdrawal_credentials == rec.withdrawal_credentials)
            & (dep.deposit_data.deposit_input.randao_commitment == rec.randao_commitment)
            //& (verify_proof_of_possession(&reg.proof_of_possession, &rec.pubkey))
    }

    #[test]
    fn test_process_deposit_valid_empty_validators() {
        let mut state = BeaconState::default();
        let deposit = get_deposit();
        let spec = ChainSpec::foundation();

        let result = process_deposit(&mut state, &deposit, &spec);

        assert_eq!(result.unwrap(), 0);
        assert!(deposit_equals_record(&deposit, &state.validator_registry[0]));
        assert_eq!(state.validator_registry.len(), 1);
        assert_eq!(state.validator_balances.len(), 1);
    }

    #[test]
    fn test_process_deposits_empty_validators() {
        let mut state = BeaconState::default();
        let spec = ChainSpec::foundation();

        for i in 0..5 {
            let deposit = get_deposit();
            let result = process_deposit(&mut state, &deposit, &spec);
            assert_eq!(result.unwrap(), i);
            assert!(deposit_equals_record(&deposit, &state.validator_registry[i]));
            assert_eq!(state.validator_registry.len(), i + 1);
            assert_eq!(state.validator_balances.len(), i + 1);
        }
    }
    
    #[test]
    fn test_process_deposit_top_out() {    
        let mut state = BeaconState::default();
        let spec = ChainSpec::foundation();
        
        let deposit = get_deposit();
        let (mut validator, _) = ValidatorRecord::zero_with_thread_rand_keypair();
        validator.pubkey = deposit.deposit_data.deposit_input.pubkey.clone();
        validator.withdrawal_credentials = deposit.deposit_data.deposit_input.withdrawal_credentials;
        validator.randao_commitment = deposit.deposit_data.deposit_input.randao_commitment;
        
        state.validator_registry.push(validator);
        state.validator_balances.push(DEPOSIT_GWEI);
        
        let result = process_deposit(&mut state, &deposit, &spec);
        
        assert_eq!(result.unwrap(), 0);
        assert!(deposit_equals_record(&deposit, &state.validator_registry[0]));
        assert_eq!(state.validator_balances[0], DEPOSIT_GWEI * 2);
        assert_eq!(state.validator_registry.len(), 1);
        assert_eq!(state.validator_balances.len(), 1);
    }
    
    #[test]
    fn test_process_deposit_replace_validator() {
        let mut state = BeaconState::default();
        let spec = ChainSpec::foundation();
            
        let (mut validator, _) = ValidatorRecord::zero_with_thread_rand_keypair();
        state.validator_registry.push(validator);
        state.validator_balances.push(0);
        
        let deposit = get_deposit();
        state.slot = spec.zero_balance_validator_ttl;
        
        let result = process_deposit(&mut state, &deposit, &spec);
        
        assert_eq!(result.unwrap(), 0);
        assert!(deposit_equals_record(&deposit, &state.validator_registry[0]));
        assert_eq!(state.validator_balances[0], DEPOSIT_GWEI);
        assert_eq!(state.validator_registry.len(), 1);
        assert_eq!(state.validator_balances.len(), 1);
    }
}
