use std::sync::Arc;

use super::helpers::{
    TestRig,
    setup_attestation_validation_test,
};
use super::state::attestation_record::{
    AttestationValidationError,
};
use super::state::block::validation::AttesterMap;
use super::bls::{
    AggregateSignature,
};
use super::utils::types::{
    Hash256,
};

fn generic_rig() -> TestRig {
    let shard_id = 10;
    let validator_count = 2;
    setup_attestation_validation_test(shard_id, validator_count)
}

#[test]
fn test_attestation_validation_valid() {
    let rig = generic_rig();

    let result = rig.context.validate_attestation(&rig.attestation);

    let voter_map = result.unwrap();
    assert_eq!(voter_map.len(), 2);
}

#[test]
fn test_attestation_validation_invalid_slot_too_high() {
    let mut rig = generic_rig();

    rig.attestation.slot = rig.context.block_slot + 1;

    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(result, Err(AttestationValidationError::SlotTooHigh));
}

#[test]
fn test_attestation_validation_invalid_slot_too_low() {
    let mut rig = generic_rig();

    rig.attestation.slot = rig.context.block_slot - u64::from(rig.context.cycle_length) - 2;
    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(result, Err(AttestationValidationError::SlotTooLow));
}

#[test]
fn test_attestation_validation_invalid_justified_slot_incorrect() {
    let mut rig = generic_rig();

    let original = rig.attestation.justified_slot;
    rig.attestation.justified_slot = original - 1;
    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(result, Err(AttestationValidationError::JustifiedSlotIncorrect));

    rig.attestation.justified_slot = original + 1;
    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(result, Err(AttestationValidationError::JustifiedSlotIncorrect));
}

#[test]
fn test_attestation_validation_invalid_too_many_oblique() {
    let mut rig = generic_rig();

    let obliques: Vec<Hash256> = (0..(rig.context.cycle_length + 1))
        .map(|i| Hash256::from((i * 2) as u64))
        .collect();

    rig.attestation.oblique_parent_hashes = obliques;

    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(result, Err(AttestationValidationError::TooManyObliqueHashes));
}

#[test]
fn test_attestation_validation_invalid_bad_attester_map() {
    let mut rig = generic_rig();

    rig.context.attester_map = Arc::new(AttesterMap::new());

    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(result, Err(AttestationValidationError::BadAttesterMap));
}

#[test]
fn test_attestation_validation_invalid_bad_bitfield_length() {
    let mut rig = generic_rig();

    /*
     * Extend the bitfield by one byte
     *
     * This is a little hacky and makes assumptions about the internals
     * of the bitfield.
     */
    let one_byte_higher = rig.attester_count + 8;
    rig.attestation.attester_bitfield.set_bit(one_byte_higher, true);
    rig.attestation.attester_bitfield.set_bit(one_byte_higher, false);

    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(result, Err(AttestationValidationError::BadBitfieldLength));
}

#[test]
fn test_attestation_validation_invalid_unknown_justfied_block_hash() {
    let mut rig = generic_rig();

    rig.attestation.justified_block_hash = Hash256::from("unknown block hash".as_bytes());

    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(result, Err(AttestationValidationError::UnknownJustifiedBlock));
}

#[test]
fn test_attestation_validation_invalid_empty_signature() {
    let mut rig = generic_rig();

    rig.attestation.aggregate_sig = AggregateSignature::new();

    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(result, Err(AttestationValidationError::BadAggregateSignature));
}
