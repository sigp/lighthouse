use bls::verify_proof_of_possession;
use types::{BeaconState, ChainSpec, Deposit, Slot, Validator};

#[derive(Debug, PartialEq, Clone)]
pub enum ValidatorInductionError {
    InvalidShard,
    InvaidProofOfPossession,
    InvalidWithdrawalCredentials,
}

pub fn process_deposit(
    state: &mut BeaconState,
    deposit: &Deposit,
    spec: &ChainSpec,
) -> Result<(), ValidatorInductionError> {
    let deposit_input = &deposit.deposit_data.deposit_input;
    let deposit_data = &deposit.deposit_data;

    // TODO: Update the signature validation as defined in the spec once issues #91 and #70 are completed
    if !verify_proof_of_possession(&deposit_input.proof_of_possession, &deposit_input.pubkey) {
        return Err(ValidatorInductionError::InvaidProofOfPossession);
    }

    let validator_index = state
        .validator_registry
        .iter()
        .position(|validator| validator.pubkey == deposit_input.pubkey);

    match validator_index {
        Some(i) => {
            if state.validator_registry[i].withdrawal_credentials
                == deposit_input.withdrawal_credentials
            {
                state.validator_balances[i] += deposit_data.amount;
                return Ok(());
            }

            Err(ValidatorInductionError::InvalidWithdrawalCredentials)
        }
        None => {
            let validator = Validator {
                pubkey: deposit_input.pubkey.clone(),
                withdrawal_credentials: deposit_input.withdrawal_credentials,
                proposer_slots: Slot::new(0),
                activation_slot: spec.far_future_slot,
                exit_slot: spec.far_future_slot,
                withdrawal_slot: spec.far_future_slot,
                penalized_slot: spec.far_future_slot,
                exit_count: 0,
                status_flags: None,
                latest_custody_reseed_slot: Slot::new(0),
                penultimate_custody_reseed_slot: Slot::new(0),
            };

            let _index = state.validator_registry.len();
            state.validator_registry.push(validator);
            state.validator_balances.push(deposit_data.amount);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::test_utils::{SeedableRng, TestRandom, XorShiftRng};

    use bls::{create_proof_of_possession, Keypair};

    /// The size of a validators deposit in GWei.
    pub const DEPOSIT_GWEI: u64 = 32_000_000_000;

    fn get_deposit() -> Deposit {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let mut deposit = Deposit::random_for_test(&mut rng);

        let kp = Keypair::random();
        deposit.deposit_data.deposit_input.pubkey = kp.pk.clone();
        deposit.deposit_data.deposit_input.proof_of_possession = create_proof_of_possession(&kp);
        deposit
    }

    fn get_validator() -> Validator {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        Validator::random_for_test(&mut rng)
    }

    fn deposit_equals_record(dep: &Deposit, val: &Validator) -> bool {
        (dep.deposit_data.deposit_input.pubkey == val.pubkey)
            & (dep.deposit_data.deposit_input.withdrawal_credentials == val.withdrawal_credentials)
            & (verify_proof_of_possession(
                &dep.deposit_data.deposit_input.proof_of_possession,
                &val.pubkey,
            ))
    }

    #[test]
    fn test_process_deposit_valid_empty_validators() {
        let mut state = BeaconState::default();
        let mut deposit = get_deposit();
        let spec = ChainSpec::foundation();
        deposit.deposit_data.amount = DEPOSIT_GWEI;

        let result = process_deposit(&mut state, &deposit, &spec);

        assert_eq!(result.unwrap(), ());
        assert!(deposit_equals_record(
            &deposit,
            &state.validator_registry[0]
        ));
        assert_eq!(state.validator_registry.len(), 1);
        assert_eq!(state.validator_balances.len(), 1);
    }

    #[test]
    fn test_process_deposits_empty_validators() {
        let mut state = BeaconState::default();
        let spec = ChainSpec::foundation();

        for i in 0..5 {
            let mut deposit = get_deposit();
            let result = process_deposit(&mut state, &deposit, &spec);
            deposit.deposit_data.amount = DEPOSIT_GWEI;
            assert_eq!(result.unwrap(), ());
            assert!(deposit_equals_record(
                &deposit,
                &state.validator_registry[i]
            ));
            assert_eq!(state.validator_registry.len(), i + 1);
            assert_eq!(state.validator_balances.len(), i + 1);
        }
    }

    #[test]
    fn test_process_deposit_top_out() {
        let mut state = BeaconState::default();
        let spec = ChainSpec::foundation();

        let mut deposit = get_deposit();
        let mut validator = get_validator();

        deposit.deposit_data.amount = DEPOSIT_GWEI;
        validator.pubkey = deposit.deposit_data.deposit_input.pubkey.clone();
        validator.withdrawal_credentials =
            deposit.deposit_data.deposit_input.withdrawal_credentials;

        state.validator_registry.push(validator);
        state.validator_balances.push(DEPOSIT_GWEI);

        let result = process_deposit(&mut state, &deposit, &spec);

        assert_eq!(result.unwrap(), ());
        assert!(deposit_equals_record(
            &deposit,
            &state.validator_registry[0]
        ));
        assert_eq!(state.validator_balances[0], DEPOSIT_GWEI * 2);
        assert_eq!(state.validator_registry.len(), 1);
        assert_eq!(state.validator_balances.len(), 1);
    }

    #[test]
    fn test_process_deposit_invalid_proof_of_possession() {
        let mut state = BeaconState::default();
        let mut deposit = get_deposit();
        let spec = ChainSpec::foundation();
        deposit.deposit_data.amount = DEPOSIT_GWEI;
        deposit.deposit_data.deposit_input.proof_of_possession =
            create_proof_of_possession(&Keypair::random());

        let result = process_deposit(&mut state, &deposit, &spec);

        assert_eq!(
            result,
            Err(ValidatorInductionError::InvaidProofOfPossession)
        );
        assert_eq!(state.validator_registry.len(), 0);
        assert_eq!(state.validator_balances.len(), 0);
    }
}
