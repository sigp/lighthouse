//! Execution payload proof message for gossip.

use crate::execution_proof_subnet_id::ExecutionProofSubnetId;
use crate::ExecutionBlockHash;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};

/// A simplified execution proof message for gossip subnet distribution.
/// This is a lighter version of ExecutionPayloadProof for network transmission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ExecutionProof {
    /// The execution block hash this proof attests to
    pub block_hash: ExecutionBlockHash,
    /// The subnet ID where this proof was received/should be sent
    ///
    /// TODO: This is not strictly needed. Its useful because there is a
    /// TODO: conversion from SubnetId to ProofID. We could encode the ProofID
    /// TODO: into the `proof_data`.
    pub subnet_id: ExecutionProofSubnetId,
    /// Version of the proof format.
    /// TODO: This is currently always set to `1` by `new_v1`
    /// TODO: but we want to have a proper way to set this and or
    /// TODO: decide, if this should be explicitly set in lighthouse.
    pub version: u32,
    /// Opaque proof data - structure depends on subnet_id and version
    /// This contains cryptographic proofs from zkVMs or other proof systems
    pub proof_data: Vec<u8>,
}

impl ExecutionProof {
    /// Create a new execution proof for gossip
    pub fn new(
        block_hash: ExecutionBlockHash,
        subnet_id: ExecutionProofSubnetId,
        version: u32,
        proof_data: Vec<u8>,
    ) -> Self {
        Self {
            block_hash,
            subnet_id,
            version,
            proof_data,
        }
    }

    /// Get a description of the proof type based on subnet_id
    pub fn description(&self) -> String {
        match *self.subnet_id {
            0 => "Execution witness proof".to_string(),
            _ => format!("Custom proof type {}", *self.subnet_id),
        }
    }

    /// Check if this proof version is supported
    pub fn is_version_supported(&self) -> bool {
        matches!(self.version, 1)
    }

    /// Validate basic structure of the proof
    pub fn is_structurally_valid(&self) -> bool {
        // Basic validation: non-empty proof data and supported version
        !self.proof_data.is_empty() && self.is_version_supported()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash256;
    use ssz::{Decode, Encode};

    #[test]
    fn test_execution_proof_creation() {
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();
        let proof_data = vec![1, 2, 3, 4];

        let proof = ExecutionProof::new(block_hash, subnet_id, 1, proof_data.clone());

        assert_eq!(proof.block_hash, block_hash);
        assert_eq!(proof.subnet_id, subnet_id);
        assert_eq!(proof.version, 1);
        assert_eq!(proof.proof_data, proof_data);
    }

    #[test]
    fn test_execution_proof_validation() {
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();

        // Valid proof
        let valid_proof = ExecutionProof::new(block_hash, subnet_id, 1, vec![1, 2, 3]);
        assert!(valid_proof.is_version_supported());
        assert!(valid_proof.is_structurally_valid());

        // Invalid version
        let invalid_version = ExecutionProof::new(block_hash, subnet_id, 99, vec![1, 2, 3]);
        assert!(!invalid_version.is_version_supported());
        assert!(!invalid_version.is_structurally_valid());

        // Empty proof data
        let empty_proof = ExecutionProof::new(block_hash, subnet_id, 1, vec![]);
        assert!(empty_proof.is_version_supported());
        assert!(!empty_proof.is_structurally_valid());
    }

    #[test]
    fn test_execution_proof_description() {
        let block_hash = ExecutionBlockHash::from(Hash256::random());

        let witness_proof = ExecutionProof::new(
            block_hash,
            ExecutionProofSubnetId::new(0).unwrap(),
            1,
            vec![1, 2, 3],
        );
        assert_eq!(witness_proof.description(), "Execution witness proof");

        let custom_proof = ExecutionProof::new(
            block_hash,
            ExecutionProofSubnetId::new(5).unwrap(),
            1,
            vec![1, 2, 3],
        );
        assert_eq!(custom_proof.description(), "Custom proof type 5");
    }

    #[test]
    fn test_execution_proof_ssz_encoding() {
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let subnet_id = ExecutionProofSubnetId::new(2).unwrap();
        let proof_data = vec![10, 20, 30, 40, 50];

        let original = ExecutionProof::new(block_hash, subnet_id, 1, proof_data);

        // Test SSZ encoding and decoding
        let encoded = original.as_ssz_bytes();
        let decoded = ExecutionProof::from_ssz_bytes(&encoded).expect("should decode successfully");

        assert_eq!(original, decoded);
    }
}
