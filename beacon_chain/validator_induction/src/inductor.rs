use bls::{verify_proof_of_possession};
use types::{BeaconState, Deposit, ValidatorRecord, ValidatorStatus};
use spec::ChainSpec;

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
        
    // TODO: Update the signature validation as defined in the spec once issues #91 and #70 are completed     
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
                exit_count: 0,
                poc_commitment: deposit_input.poc_commitment,
                last_poc_change_slot: 0,
                second_last_poc_slot: 0
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
    
    use bls::{create_proof_of_possession, Keypair};
    
    /// The size of a validators deposit in GWei.
    pub const DEPOSIT_GWEI: u64 = 32_000_000_000;
    
    fn deposit_equals_record(dep: &Deposit, val: &ValidatorRecord) -> bool {
        (dep.deposit_data.deposit_input.pubkey == val.pubkey)
            & (dep.deposit_data.deposit_input.withdrawal_credentials == val.withdrawal_credentials)
            & (dep.deposit_data.deposit_input.randao_commitment == val.randao_commitment)
            & (verify_proof_of_possession(&dep.deposit_data.deposit_input.proof_of_possession, &val.pubkey))
    }

    #[test]
    fn test_process_deposit_valid_empty_validators() {
        let mut state = BeaconState::default();
        let mut deposit = Deposit::zero_with_rand_keypair();
        let spec = ChainSpec::foundation();
        deposit.deposit_data.value = DEPOSIT_GWEI;
        
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
            let mut deposit = Deposit::zero_with_rand_keypair();
            let result = process_deposit(&mut state, &deposit, &spec);
            deposit.deposit_data.value = DEPOSIT_GWEI;
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
        
        let mut deposit = Deposit::zero_with_rand_keypair();
        let mut validator = ValidatorRecord::zero_with_rand_keypair();
        deposit.deposit_data.value = DEPOSIT_GWEI;
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
            
        let validator = ValidatorRecord::zero_with_rand_keypair();
        state.validator_registry.push(validator);
        state.validator_balances.push(0);
        
        let mut deposit = Deposit::zero_with_rand_keypair();
        deposit.deposit_data.value = DEPOSIT_GWEI;
        state.slot = spec.zero_balance_validator_ttl;
        
        let result = process_deposit(&mut state, &deposit, &spec);
        
        assert_eq!(result.unwrap(), 0);
        assert!(deposit_equals_record(&deposit, &state.validator_registry[0]));
        assert_eq!(state.validator_balances[0], DEPOSIT_GWEI);
        assert_eq!(state.validator_registry.len(), 1);
        assert_eq!(state.validator_balances.len(), 1);
    }
    
    #[test]
    fn test_process_deposit_invalid_proof_of_possession() {    
        let mut state = BeaconState::default();
        let mut deposit = Deposit::zero_with_rand_keypair();
        let spec = ChainSpec::foundation();
        deposit.deposit_data.value = DEPOSIT_GWEI;
        deposit.deposit_data.deposit_input.proof_of_possession = create_proof_of_possession(&Keypair::random());
        
        let result = process_deposit(&mut state, &deposit, &spec);

        assert_eq!(result, Err(ValidatorInductionError::InvaidProofOfPossession));
        assert_eq!(state.validator_registry.len(), 0);
        assert_eq!(state.validator_balances.len(), 0);
    }
}
