use std::sync::Arc;

use super::helpers::{
    TestStore,
    setup_attestation_validation_test,
};
use super::state::attestation_record::{
    AttestationRecord,
    AttestationValidationContext,
    AttestationValidationError,
};
use super::state::block::validation::AttesterMap;
use super::bls::{
    AggregateSignature,
    Keypair,
};
use super::db::{
    MemoryDB,
};
use super::db::stores::{
    BlockStore,
    ValidatorStore,
};
use super::utils::types::{
    Hash256,
    Bitfield,
};

#[test]
fn test_attestation_validation_valid() {
    let (a, c, _stores) = setup_attestation_validation_test(10, 2);

    let result = c.validate_attestation(&a);

    assert!(result.unwrap().is_some());
}
