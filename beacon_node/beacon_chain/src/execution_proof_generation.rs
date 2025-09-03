//! Execution proof generation and verification
//!
//! This module handles the generation and verification of execution proofs.
//! Currently implements dummy proof generation, but will be replaced with
//! actual proof generation from zkVMs or other proof systems.

use tracing::debug;
use types::{
    execution_proof_subnet_id::ExecutionProofSubnetId, EthSpec, ExecutionPayload, ExecutionProof, Hash256,
};

/// Generate a proof for an execution payload
///
/// TODO: Currently generates dummy proofs. Will be replaced with actual proof generation
/// from zkVMs or other proof systems.
///
/// This accepts the concrete ExecutionPayload<E> type which is what the EL expects
/// and can be easily serialized for sending to external systems.
/// The execution_state_witness would be obtained from the EL (e.g., via debug_executionWitness)
pub async fn generate_proof<T: EthSpec>(
    block_root: Hash256,
    payload: &ExecutionPayload<T>,
    execution_state_witness: &[u8],
    proof_id: ExecutionProofSubnetId,
) -> ExecutionProof {
    let execution_block_hash = payload.block_hash();
    let block_number = payload.block_number();

    // Simulate (some) proof computation delay
    // In a real implementation, this would be the time needed for zkVM local proof generation
    // or communication with external proof generation services
    use rand::{rng, Rng};
    let delay_ms = rng().random_range(1000..=3000);

    debug!(
        execution_block_hash = ?execution_block_hash,
        subnet_id = *proof_id,
        delay_ms,
        "Simulating proof generation delay"
    );

    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;

    // Create dummy proof data that includes the subnet information and payload details
    // In a real implementation, this would use the execution_state_witness to generate
    // a cryptographic proof of the payload's validity
    let dummy_data = format!(
        "dummy_proof_subnet_{}_block_{:?}_number_{}_witness_len_{}",
        *proof_id,
        execution_block_hash,
        block_number,
        execution_state_witness.len()
    )
    .into_bytes();

    ExecutionProof::new(block_root, execution_block_hash, proof_id, 1, dummy_data)
}

/// Validate a proof (placeholder implementation)
///
/// TODO: Implement actual cryptographic proof validation based on version and type
pub fn validate_proof(proof: &ExecutionProof) -> bool {
    // Placeholder validation - in reality this would verify cryptographic proofs
    // based on both proof_id and version
    match proof.version {
        1 => {
            // Version 1: basic validation - non-empty proof data
            !proof.proof_data.is_empty()
        }
        _ => {
            // Unknown versions are considered invalid
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{
        ExecutionBlockHash, ExecutionPayloadBellatrix, FixedBytesExtended, FullPayloadBellatrix,
        Hash256, MainnetEthSpec, Uint256,
    };

    #[tokio::test]
    async fn test_generate_proof() {
        let execution_block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ExecutionProofSubnetId::new(5).unwrap();

        // Create a dummy payload for testing
        let payload = FullPayloadBellatrix::<MainnetEthSpec> {
            execution_payload: ExecutionPayloadBellatrix::<MainnetEthSpec> {
                parent_hash: ExecutionBlockHash::zero(),
                fee_recipient: Default::default(),
                state_root: Hash256::zero(),
                receipts_root: Hash256::zero(),
                logs_bloom: Default::default(),
                prev_randao: Hash256::zero(),
                block_number: 12345,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 0,
                extra_data: Default::default(),
                base_fee_per_gas: Uint256::from(1u64),
                block_hash: execution_block_hash,
                transactions: Default::default(),
            },
        };

        let exec_payload = ExecutionPayload::Bellatrix(payload.execution_payload);
        let dummy_witness = b"test_witness_data";
        let proof = generate_proof(Hash256::random(), &exec_payload, dummy_witness, proof_id).await;

        assert_eq!(proof.block_hash, execution_block_hash);
        assert_eq!(proof.subnet_id, proof_id);
        assert_eq!(proof.version, 1);
        assert!(!proof.proof_data.is_empty());
        assert!(validate_proof(&proof));

        // Verify the proof data contains expected information
        let proof_data_str = String::from_utf8_lossy(&proof.proof_data);
        assert!(proof_data_str.contains("subnet_5"));
        assert!(proof_data_str.contains("number_12345"));
        assert!(proof_data_str.contains("witness_len_17")); // 17 is the length of "test_witness_data"
    }

    #[test]
    fn test_validate_proof() {
        let hash = ExecutionBlockHash::from(Hash256::random());

        // Test version 1 proof (supported)
        let v1_proof = ExecutionProof::new(
            Hash256::random(),
            hash,
            ExecutionProofSubnetId::new(0).unwrap(),
            1,
            vec![1, 2, 3],
        );
        assert!(validate_proof(&v1_proof));

        // Test unsupported version
        let v2_proof = ExecutionProof::new(
            Hash256::random(),
            hash,
            ExecutionProofSubnetId::new(0).unwrap(),
            2,
            vec![7, 8, 9],
        );
        assert!(!validate_proof(&v2_proof)); // Should fail validation for unknown version

        // Test empty data with version 1 (should be invalid)
        let empty_v1 =
            ExecutionProof::new(Hash256::random(), hash, ExecutionProofSubnetId::new(0).unwrap(), 1, vec![]);
        assert!(!validate_proof(&empty_v1));
    }

    #[tokio::test]
    async fn test_generate_proof_different_subnets() {
        let execution_block_hash = ExecutionBlockHash::from(Hash256::random());

        // Create a dummy payload for testing
        let payload = FullPayloadBellatrix::<MainnetEthSpec> {
            execution_payload: ExecutionPayloadBellatrix::<MainnetEthSpec> {
                parent_hash: ExecutionBlockHash::zero(),
                fee_recipient: Default::default(),
                state_root: Hash256::zero(),
                receipts_root: Hash256::zero(),
                logs_bloom: Default::default(),
                prev_randao: Hash256::zero(),
                block_number: 42,
                gas_limit: 0,
                gas_used: 0,
                timestamp: 0,
                extra_data: Default::default(),
                base_fee_per_gas: Uint256::from(0u64),
                block_hash: execution_block_hash,
                transactions: Default::default(),
            },
        };

        let exec_payload = ExecutionPayload::Bellatrix(payload.execution_payload);
        let dummy_witness = b"test_witness_data";

        let proof_0 = generate_proof(
            Hash256::random(),
            &exec_payload,
            dummy_witness,
            ExecutionProofSubnetId::new(0).unwrap(),
        )
        .await;
        let proof_1 = generate_proof(
            Hash256::random(),
            &exec_payload,
            dummy_witness,
            ExecutionProofSubnetId::new(1).unwrap(),
        )
        .await;
        let proof_2 = generate_proof(
            Hash256::random(),
            &exec_payload,
            dummy_witness,
            ExecutionProofSubnetId::new(2).unwrap(),
        )
        .await;

        // All proofs should be for the same block hash
        assert_eq!(proof_0.block_hash, execution_block_hash);
        assert_eq!(proof_1.block_hash, execution_block_hash);
        assert_eq!(proof_2.block_hash, execution_block_hash);

        // But should have different proof IDs and data
        assert_eq!(*proof_0.subnet_id, 0);
        assert_eq!(*proof_1.subnet_id, 1);
        assert_eq!(*proof_2.subnet_id, 2);

        // Proof data should be different for different subnets
        assert_ne!(proof_0.proof_data, proof_1.proof_data);
        assert_ne!(proof_1.proof_data, proof_2.proof_data);

        let data_0 = String::from_utf8_lossy(&proof_0.proof_data);
        let data_1 = String::from_utf8_lossy(&proof_1.proof_data);
        let data_2 = String::from_utf8_lossy(&proof_2.proof_data);

        assert!(data_0.contains("subnet_0"));
        assert!(data_1.contains("subnet_1"));
        assert!(data_2.contains("subnet_2"));
    }

    #[tokio::test]
    async fn test_generate_proof_deterministic() {
        // Test that proof generation is deterministic - same input always produces same output
        let execution_block_hash = ExecutionBlockHash::from(Hash256::from_low_u64_be(12345));
        let proof_id = ExecutionProofSubnetId::new(3).unwrap();

        // Create a specific payload with fixed values
        let payload = FullPayloadBellatrix::<MainnetEthSpec> {
            execution_payload: ExecutionPayloadBellatrix::<MainnetEthSpec> {
                parent_hash: ExecutionBlockHash::from(Hash256::from_low_u64_be(111)),
                fee_recipient: Default::default(),
                state_root: Hash256::from_low_u64_be(222),
                receipts_root: Hash256::from_low_u64_be(333),
                logs_bloom: Default::default(),
                prev_randao: Hash256::from_low_u64_be(444),
                block_number: 555,
                gas_limit: 30_000_000,
                gas_used: 15_000_000,
                timestamp: 1234567890,
                extra_data: b"test_extra_data".to_vec().into(),
                base_fee_per_gas: Uint256::from(7u64),
                block_hash: execution_block_hash,
                transactions: vec![b"tx1".to_vec().into(), b"tx2".to_vec().into()].into(),
            },
        };

        let exec_payload = ExecutionPayload::Bellatrix(payload.execution_payload);
        let witness_data = b"deterministic_witness_data";

        // Generate proof multiple times with same input
        let block_root = Hash256::random();
        let proof1 = generate_proof(block_root, &exec_payload, witness_data, proof_id).await;
        let proof2 = generate_proof(block_root, &exec_payload, witness_data, proof_id).await;
        let proof3 = generate_proof(block_root, &exec_payload, witness_data, proof_id).await;

        // All proofs should be identical
        assert_eq!(proof1.block_hash, proof2.block_hash);
        assert_eq!(proof1.block_hash, proof3.block_hash);

        assert_eq!(proof1.subnet_id, proof2.subnet_id);
        assert_eq!(proof1.subnet_id, proof3.subnet_id);

        assert_eq!(proof1.version, proof2.version);
        assert_eq!(proof1.version, proof3.version);

        // Most importantly, proof data should be identical
        assert_eq!(proof1.proof_data, proof2.proof_data);
        assert_eq!(proof1.proof_data, proof3.proof_data);

        // Verify the content is as expected
        let proof_str = String::from_utf8_lossy(&proof1.proof_data);
        assert!(proof_str.contains("subnet_3"));
        assert!(proof_str.contains("number_555"));
        assert!(proof_str.contains("witness_len_26"));

        // Now test that different inputs produce different proofs
        let different_witness = b"different_witness_data";
        let proof_different = generate_proof(block_root, &exec_payload, different_witness, proof_id).await;

        // Same block hash and subnet, but different proof data
        assert_eq!(proof_different.block_hash, proof1.block_hash);
        assert_eq!(proof_different.subnet_id, proof1.subnet_id);
        assert_ne!(proof_different.proof_data, proof1.proof_data);
    }
}
