use std::sync::Arc;

use super::bls::AggregateSignature;
use super::helpers::{create_block_at_slot, setup_attestation_validation_test, TestRig};
use super::types::AttesterMap;
use super::types::Hash256;
use super::validation::attestation_validation::AttestationValidationError;

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
fn test_attestation_validation_invalid_parent_slot_too_high() {
    let mut rig = generic_rig();

    rig.context.parent_block_slot = rig.attestation.slot - 1;

    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(result, Err(AttestationValidationError::ParentSlotTooHigh));
}

#[test]
fn test_attestation_validation_invalid_parent_slot_too_low() {
    let mut rig = generic_rig();

    rig.attestation.slot = rig.context.parent_block_slot - u64::from(rig.context.cycle_length) - 2;
    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(result, Err(AttestationValidationError::ParentSlotTooLow));
}

#[test]
fn test_attestation_validation_invalid_block_slot_too_high() {
    let mut rig = generic_rig();

    rig.context.block_slot = rig.attestation.slot - 1;

    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(result, Err(AttestationValidationError::BlockSlotTooHigh));
}

#[test]
fn test_attestation_validation_invalid_block_slot_too_low() {
    let mut rig = generic_rig();

    rig.context.block_slot = rig.context.block_slot + u64::from(rig.context.cycle_length);
    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(result, Err(AttestationValidationError::BlockSlotTooLow));
}

#[test]
fn test_attestation_validation_invalid_justified_slot_incorrect() {
    let mut rig = generic_rig();

    let original = rig.attestation.justified_slot;
    rig.attestation.justified_slot = original - 1;
    // Ensures we don't get a bad justified block error instead.
    create_block_at_slot(
        &rig.stores.block,
        &rig.attestation.justified_block_hash,
        rig.attestation.justified_slot,
    );
    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(
        result,
        Err(AttestationValidationError::BadAggregateSignature)
    );

    rig.attestation.justified_slot = original + 1;
    // Ensures we don't get a bad justified block error instead.
    create_block_at_slot(
        &rig.stores.block,
        &rig.attestation.justified_block_hash,
        rig.attestation.justified_slot,
    );
    // Ensures we don't get an error that the last justified slot is ahead of the context justified
    // slot.
    rig.context.last_justified_slot = rig.attestation.justified_slot;
    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(
        result,
        Err(AttestationValidationError::BadAggregateSignature)
    );
}

#[test]
fn test_attestation_validation_invalid_too_many_oblique() {
    let mut rig = generic_rig();

    let obliques: Vec<Hash256> = (0..(rig.context.cycle_length + 1))
        .map(|i| Hash256::from((i * 2) as u64))
        .collect();

    rig.attestation.oblique_parent_hashes = obliques;

    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(
        result,
        Err(AttestationValidationError::TooManyObliqueHashes)
    );
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
     * We take advantage of the fact that setting a bit outside the current bounds will grow the bitvector.
     */
    let one_byte_higher = rig.attester_count + 8;
    rig.attestation
        .attester_bitfield
        .set(one_byte_higher, false);

    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(result, Err(AttestationValidationError::BadBitfieldLength));
}

#[test]
fn test_attestation_validation_invalid_invalid_bitfield_end_bit() {
    let mut rig = generic_rig();

    let one_bit_high = rig.attester_count + 1;
    rig.attestation.attester_bitfield.set(one_bit_high, true);

    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(
        result,
        Err(AttestationValidationError::InvalidBitfieldEndBits)
    );
}

#[test]
fn test_attestation_validation_invalid_invalid_bitfield_end_bit_with_irreguar_bitfield_len() {
    let mut rig = generic_rig();

    /*
     * This test ensure that if the number of attesters is "irregular" (with respect to the
     * bitfield), and there is a invalid bit is set, validation will still fail.
     *
     * "Irregular" here means that number of validators + 1 is not a clean multiple of eight.
     *
     * This test exists to ensure that the application can distinguish between the highest set
     * bit in a bitfield and the byte length of that bitfield
     */
    let one_bit_high = rig.attester_count + 1;
    assert!(
        one_bit_high % 8 != 0,
        "the test is ineffective in this case."
    );
    rig.attestation.attester_bitfield.set(one_bit_high, true);

    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(
        result,
        Err(AttestationValidationError::InvalidBitfieldEndBits)
    );
}

#[test]
fn test_attestation_validation_invalid_unknown_justified_block_hash() {
    let mut rig = generic_rig();

    rig.attestation.justified_block_hash = Hash256::from("unknown block hash".as_bytes());

    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(
        result,
        Err(AttestationValidationError::InvalidJustifiedBlockHash)
    );
}

#[test]
fn test_attestation_validation_invalid_unknown_justified_block_hash_wrong_slot() {
    let rig = generic_rig();

    /*
     * justified_block_hash points to a block with a slot that is too high.
     */
    create_block_at_slot(
        &rig.stores.block,
        &rig.attestation.justified_block_hash,
        rig.attestation.justified_slot + 1,
    );
    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(
        result,
        Err(AttestationValidationError::InvalidJustifiedBlockHash)
    );

    /*
     * justified_block_hash points to a block with a slot that is too low.
     */
    create_block_at_slot(
        &rig.stores.block,
        &rig.attestation.justified_block_hash,
        rig.attestation.justified_slot - 1,
    );
    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(
        result,
        Err(AttestationValidationError::InvalidJustifiedBlockHash)
    );
}

#[test]
fn test_attestation_validation_invalid_empty_signature() {
    let mut rig = generic_rig();

    rig.attestation.aggregate_sig = AggregateSignature::new();

    let result = rig.context.validate_attestation(&rig.attestation);
    assert_eq!(
        result,
        Err(AttestationValidationError::BadAggregateSignature)
    );
}
