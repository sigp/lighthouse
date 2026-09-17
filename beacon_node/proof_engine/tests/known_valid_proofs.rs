//! End-to-end verification of one known-valid execution proof.
//!
//! The fixture was produced by the reth stateless-validator guest published by
//! `eth-act/ere-guests` at tag `v0.17.0`. One ZisK proof is sufficient to bind the built-in
//! key to a real artifact without adding the substantially larger SP1 and OpenVM proof files.
#![cfg(feature = "ere-verifier")]

use proof_engine::ere::EreProofEngine;
use proof_engine::{ProofEngineConfig, ProofEngineT, ProofVerificationOutcome};
use ssz::Encode;
use tree_hash::TreeHash;
use types::Hash256;
use types::execution::{ExecutionProof, ProofData, ProofType, PublicInput};

const PROOF_FIXTURE: &str = "stateless-validator-reth-zisk-v1.1.0-alpha.proof";

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("missing fixture {path:?}: {error}"))
}

fn public_input() -> PublicInput {
    PublicInput {
        new_payload_request_root: Hash256::from_slice(
            &hex::decode("68e2250786a622ab175a8149c63d220704e7ed9610a12b7864047510235e7bb7")
                .expect("fixture root is valid hex"),
        ),
        successful_validation: true,
        chain_id: 1,
        schema_id: 0x1501,
    }
}

fn execution_proof(public_input: PublicInput, proof_data: Vec<u8>) -> ExecutionProof {
    ExecutionProof {
        proof_data: ProofData::new(proof_data).expect("fixture is within the proof size bound"),
        proof_type: ProofType::RethZisk,
        public_input,
    }
}

#[test]
fn public_input_reproduces_the_guest_commitment() {
    let public_input = public_input();
    let serialized = public_input.as_ssz_bytes();

    assert_eq!(serialized, fixture("public_values.bin"));
    assert_ne!(
        serialized.as_slice(),
        public_input.tree_hash_root().as_slice()
    );
}

#[test]
fn known_valid_proof_verifies_against_the_built_in_key() {
    let engine = EreProofEngine::new(ProofEngineConfig::default()).expect("engine initializes");
    let proof = execution_proof(public_input(), fixture(PROOF_FIXTURE));

    assert_eq!(
        engine
            .verify_execution_proof(&proof)
            .expect("verifier runs"),
        ProofVerificationOutcome::Valid
    );
}

#[test]
fn known_valid_proof_rejects_changed_public_input() {
    let engine = EreProofEngine::new(ProofEngineConfig::default()).expect("engine initializes");
    let proof_data = fixture(PROOF_FIXTURE);

    let mut altered_root = public_input();
    altered_root.new_payload_request_root = Hash256::repeat_byte(0xab);
    let mut altered_chain = public_input();
    altered_chain.chain_id = 2;
    let mut altered_validation = public_input();
    altered_validation.successful_validation = false;

    for altered in [altered_root, altered_chain, altered_validation] {
        let proof = execution_proof(altered, proof_data.clone());
        assert_eq!(
            engine
                .verify_execution_proof(&proof)
                .expect("verifier runs"),
            ProofVerificationOutcome::Invalid
        );
    }
}

#[test]
fn malformed_proof_data_is_rejected() {
    let engine = EreProofEngine::new(ProofEngineConfig::default()).expect("engine initializes");
    let valid = fixture(PROOF_FIXTURE);

    for data in [vec![0], vec![0xaa; 4096], valid[..valid.len() / 3].to_vec()] {
        let proof = execution_proof(public_input(), data);
        assert_eq!(
            engine
                .verify_execution_proof(&proof)
                .expect("verifier runs"),
            ProofVerificationOutcome::Invalid
        );
    }
}
