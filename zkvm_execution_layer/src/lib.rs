pub mod config;
pub mod proof_cache;

pub mod proof_generation;
pub mod proof_verification;

pub mod registry_proof_gen;
pub mod registry_proof_verification;

pub mod dummy_proof_gen;
pub mod dummy_proof_verifier;

#[test]
fn add() {
    assert!(1 + 1 == 2)
}
