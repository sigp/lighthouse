use crate::{ExecutionBlockHash, Hash256, VariableList};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::typenum;
use std::fmt::{self, Debug};
use tree_hash_derive::TreeHash;

use super::ExecutionProofSubnetId;

/// Maximum size of proof data in bytes
/// 
/// Note: Most proofs will fit within 300KB. Some zkVMs have 1MB proofs (currently)
/// and so this number was set to accommodate for the most zkVMs.
pub const MAX_PROOF_DATA_BYTES: usize = 1_048_576;

type ProofData = VariableList<u8, typenum::U1048576>;

/// ExecutionProof represents a cryptographic `proof of execution` that
/// an execution payload is valid. 
/// 
/// In short, it is proof that if we were to run a particular execution layer client
/// with the given execution payload, they would return the output values that are attached
/// to the proof.
///
/// Each proof is associated with a specific subnet_id, which identifies the
/// zkVM and EL combination used to generate it. Multiple proofs from different
/// subnets can exist for the same execution payload, providing both client and EL diversity.
#[derive(Clone, Serialize, Deserialize, Encode, Decode, TreeHash, PartialEq, Eq)]
pub struct ExecutionProof {
    /// Which subnet/zkVM this proof belongs to
    /// TODO(zkproofs): The node should provide this in themselves since they
    /// know what subnet the proof came from.
    pub subnet_id: ExecutionProofSubnetId,

    /// The block hash of the execution payload this proof validates
    pub block_hash: ExecutionBlockHash,

    /// The beacon block root corresponding to the beacon block
    /// with the execution payload, that this proof attests to.
    pub block_root: Hash256,

    /// The actual proof data
    pub proof_data: ProofData,
}

impl ExecutionProof {
    pub fn new(
        subnet_id: ExecutionProofSubnetId,
        block_hash: ExecutionBlockHash,
        block_root: Hash256,
        proof_data: Vec<u8>,
    ) -> Result<Self, String> {
        let proof_data = ProofData::new(proof_data)
            .map_err(|e| format!("Failed to create proof data: {:?}", e))?;

        Ok(Self {
            subnet_id,
            block_hash,
            block_root,
            proof_data,
        })
    }

    /// Returns the size of the proof data in bytes
    pub fn proof_data_size(&self) -> usize {
        self.proof_data.len()
    }

    /// Get a reference to the proof data as a slice
    pub fn proof_data_slice(&self) -> &[u8] {
        &self.proof_data
    }

    /// Check if this proof is for a specific execution block hash
    pub fn is_for_block(&self, block_hash: &ExecutionBlockHash) -> bool {
        &self.block_hash == block_hash
    }

    /// Check if this proof is from a specific subnet
    pub fn is_from_subnet(&self, subnet_id: ExecutionProofSubnetId) -> bool {
        self.subnet_id == subnet_id
    }
}

impl Debug for ExecutionProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutionProof")
            .field("subnet_id", &self.subnet_id)
            .field("block_hash", &self.block_hash)
            .field("block_root", &self.block_root)
            .field("proof_data_size", &self.proof_data.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_proof_too_large() {
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();
        let block_hash = ExecutionBlockHash::zero();
        let block_root = Hash256::zero();
        let proof_data = vec![0u8; MAX_PROOF_DATA_BYTES + 1];

        let result = ExecutionProof::new(subnet_id, block_hash, block_root, proof_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Proof data too large"));
    }

    #[test]
    fn test_execution_proof_max_size() {
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();
        let block_hash = ExecutionBlockHash::zero();
        let block_root = Hash256::zero();
        let proof_data = vec![0u8; MAX_PROOF_DATA_BYTES];

        let result = ExecutionProof::new(subnet_id, block_hash, block_root, proof_data);
        assert!(result.is_ok());
    }

}