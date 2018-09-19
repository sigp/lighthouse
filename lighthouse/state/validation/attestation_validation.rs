use super::CrystallizedState;
use super::ActiveState;
use super::AttestationRecord;
use super::Block;
use super::ChainConfig;

use ::utils::errors::AttestationValidationError;

// implementation of validate_attestation in the v2.1 python reference implementation
// see: https://github.com/ethereum/beacon_chain/blob/a79ab2c6f03cbdabf2b6d9d435c26e2b216e09a5/beacon_chain/state/state_transition.py#L61
pub fn validate_attestation(
    crystallized_state: &CrystallizedState,
    active_state: &ActiveState,
    attestation: &AttestationRecord,
    block: &Block,
    chain_config: &ChainConfig)
    -> Result<bool, AttestationValidationError> {

        if !(attestation.slot < block.slot_number) {
            return Err(AttestationValidationError::SlotTooHigh);
        }

        if !(attestation.slot > (block.slot_number - chain_config.cycle_length as u64)) {
            return Err(AttestationValidationError::SlotTooLow(format!("Attestation slot number too low\n\tFound: {:?}, Needed greater than: {:?}", attestation.slot, block.slot_number - chain_config.cycle_length as u64)));
        }

        Ok(true)
    }


#[cfg(test)]
mod tests {

    use super::*;
    // test helper functions

    fn generate_standard_state() -> (
        CrystallizedState,
        ActiveState,
        AttestationRecord,
        Block,
        ChainConfig) {

        let crystallized_state = CrystallizedState::zero();
        let active_state = ActiveState::zero();
        let attestation_record = AttestationRecord::zero();
        let block = Block::zero();
        let chain_config = ChainConfig::standard();

        return (crystallized_state, active_state, attestation_record, block, chain_config);
    }

    #[test]
    fn test_attestation_validation_slot_high() {
        // generate standard state
        let (crystallized_state, active_state, mut attestation_record, mut block, chain_config) = generate_standard_state();
        // set slot too high
        attestation_record.slot = 30;
        block.slot_number = 10;

        let result = validate_attestation(&crystallized_state, &active_state, &attestation_record, &block, &chain_config);
        assert_eq!(result, Err(AttestationValidationError::SlotTooHigh));
    }

    #[test]
    fn test_attestation_validation_slot_low() {
        // generate standard state
        let (crystallized_state, active_state, mut attestation_record, mut block, chain_config) = generate_standard_state();
        // set slot too high
        attestation_record.slot = 2;
        block.slot_number = 10;

        let result = validate_attestation(
            &crystallized_state,
            &active_state,
            &attestation_record,
            &block,
            &chain_config);
        //assert_eq!(result, Err(AttestationValidationError::SlotTooLow));
    }
}
