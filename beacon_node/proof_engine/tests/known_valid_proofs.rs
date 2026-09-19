//! End-to-end verification of known-valid execution proofs.
//!
//! The fixtures are Ethrex v26.0.0 and reth v0.1.0-rc.3 guest artifacts copied from
//! `eth-act/zkboost` at commit `7f99d70a679bd0c0e8951f9d2797183340f80262`. Their program
//! verification keys are registered by `eth-act/ere-guests` v0.17.0 and verified here with ERE
//! v0.17.1, the verifier release pinned by this crate. zkBoost does not publish a Zesu proof
//! fixture at that commit, so Zesu is covered by configuration tests but not by this known-valid
//! proof suite. The fixtures are embedded only in this integration-test target, so proof data does
//! not become part of the production client.
#![cfg(feature = "ere-verifier")]

use proof_engine::{ProofEngineConfig, ProofVerificationOutcome};
use ssz::Encode;
use tree_hash::TreeHash;
use types::Hash256;
use types::execution::{ExecutionProof, ProofData, ProofType, PublicInput};

const PUBLIC_VALUES: &[u8] = include_bytes!("fixtures/public_values.bin");

/// The proof fixture for each proof type for which zkBoost publishes an artifact.
const PROOFS: [(ProofType, &[u8]); 6] = [
    (
        ProofType::EthrexOpenVM,
        include_bytes!("fixtures/stateless-validator-ethrex-openvm-v2.1.0-preview.proof"),
    ),
    (
        ProofType::EthrexSP1,
        include_bytes!("fixtures/stateless-validator-ethrex-sp1-v6.4.0.proof"),
    ),
    (
        ProofType::EthrexZisk,
        include_bytes!("fixtures/stateless-validator-ethrex-zisk-v1.1.0-alpha.proof"),
    ),
    (
        ProofType::RethOpenVM,
        include_bytes!("fixtures/stateless-validator-reth-openvm-v2.1.0-preview.proof"),
    ),
    (
        ProofType::RethSP1,
        include_bytes!("fixtures/stateless-validator-reth-sp1-v6.4.0.proof"),
    ),
    (
        ProofType::RethZisk,
        include_bytes!("fixtures/stateless-validator-reth-zisk-v1.1.0-alpha.proof"),
    ),
];

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

fn execution_proof(proof_type: ProofType, public_input: PublicInput) -> ExecutionProof {
    let proof_data = PROOFS
        .iter()
        .find_map(|(candidate, data)| (*candidate == proof_type).then_some(*data))
        .expect("proof type has a fixture");
    ExecutionProof {
        proof_data: ProofData::new(proof_data.to_vec())
            .expect("fixture is within the proof size bound"),
        proof_type,
        public_input,
    }
}

#[test]
fn public_input_reproduces_the_guest_commitment() {
    let public_input = public_input();
    let serialized = public_input.as_ssz_bytes();

    assert_eq!(serialized, PUBLIC_VALUES);
    assert_ne!(
        serialized.as_slice(),
        public_input.tree_hash_root().as_slice()
    );
}

#[test]
fn known_valid_proofs_verify_against_the_built_in_keys() {
    let engine = ProofEngineConfig::default()
        .build_engine()
        .expect("engine initializes");

    for (proof_type, _) in PROOFS {
        let proof = execution_proof(proof_type, public_input());
        assert_eq!(
            engine
                .verify_execution_proof(&proof)
                .expect("verifier runs"),
            ProofVerificationOutcome::Valid,
            "{proof_type:?} proof did not verify against the built-in program verification key"
        );
    }
}

#[test]
fn known_valid_proofs_reject_changed_public_input() {
    let engine = ProofEngineConfig::default()
        .build_engine()
        .expect("engine initializes");

    let mut altered_root = public_input();
    altered_root.new_payload_request_root = Hash256::repeat_byte(0xab);
    let mut altered_chain = public_input();
    altered_chain.chain_id = 2;
    let mut altered_validation = public_input();
    altered_validation.successful_validation = false;

    for (proof_type, _) in PROOFS {
        for altered in [&altered_root, &altered_chain, &altered_validation] {
            let proof = execution_proof(proof_type, altered.clone());
            assert_eq!(
                engine
                    .verify_execution_proof(&proof)
                    .expect("verifier runs"),
                ProofVerificationOutcome::Invalid,
                "{proof_type:?} accepted a public input it does not prove"
            );
        }
    }
}

#[test]
fn known_valid_proofs_reject_a_foreign_proof_type() {
    let engine = ProofEngineConfig::default()
        .build_engine()
        .expect("engine initializes");

    for (proof_type, proof_data) in PROOFS {
        for (foreign_type, _) in PROOFS {
            if foreign_type == proof_type {
                continue;
            }
            let proof = ExecutionProof {
                proof_data: ProofData::new(proof_data.to_vec())
                    .expect("fixture is within the proof size bound"),
                proof_type: foreign_type,
                public_input: public_input(),
            };
            assert_eq!(
                engine
                    .verify_execution_proof(&proof)
                    .expect("verifier runs"),
                ProofVerificationOutcome::Invalid,
                "a {proof_type:?} proof verified as {foreign_type:?}"
            );
        }
    }
}

#[test]
fn corrupted_sp1_nested_lengths_are_rejected() {
    let engine = ProofEngineConfig::default()
        .build_engine()
        .expect("engine initializes");
    let valid = PROOFS
        .iter()
        .find_map(|(proof_type, data)| (*proof_type == ProofType::RethSP1).then_some(*data))
        .expect("SP1 proof fixture is present");

    for offset in [8usize, 64, 256, 1024, 4096] {
        let mut data = valid.to_vec();
        if offset + 8 <= data.len() {
            data[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        }
        let proof = ExecutionProof {
            proof_data: ProofData::new(data).expect("fixture is within the proof size bound"),
            proof_type: ProofType::RethSP1,
            public_input: public_input(),
        };
        assert_eq!(
            engine
                .verify_execution_proof(&proof)
                .expect("verifier runs"),
            ProofVerificationOutcome::Invalid,
            "corrupted SP1 proof at offset {offset} was not rejected cleanly"
        );
    }
}

#[test]
fn malformed_proof_data_is_rejected() {
    let engine = ProofEngineConfig::default()
        .build_engine()
        .expect("engine initializes");
    for (proof_type, valid) in PROOFS {
        for data in [vec![0], vec![0xaa; 4096], valid[..valid.len() / 3].to_vec()] {
            let proof = ExecutionProof {
                proof_data: ProofData::new(data).expect("fixture is within the proof size bound"),
                proof_type,
                public_input: public_input(),
            };
            assert_eq!(
                engine
                    .verify_execution_proof(&proof)
                    .expect("verifier runs"),
                ProofVerificationOutcome::Invalid,
                "{proof_type:?} accepted malformed proof data"
            );
        }
    }
}
