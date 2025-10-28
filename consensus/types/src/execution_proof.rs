use crate::{ExecutionBlockHash, Hash256, Slot, VariableList};
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode as DeriveEncode};
use ssz_types::typenum;
use std::fmt::{self, Debug};
use tree_hash_derive::TreeHash;

use super::ExecutionProofId;

/// Maximum size of proof data in bytes
///
/// Note: Most proofs will fit within 300KB. Some zkVMs have 1MB proofs (currently)
/// and so this number was set to accommodate for the most zkVMs.
pub const MAX_PROOF_DATA_BYTES: usize = 1_048_576;

/// Minimum number of execution proofs required from different proof types
/// before marking an execution payload as available in ZK-VM mode.
///
/// This provides client diversity - nodes wait for proofs from K different
/// zkVM+EL combinations before considering an execution payload available.
pub const DEFAULT_MIN_PROOFS_REQUIRED: usize = 2;

/// Maximum number of execution proofs that can be requested or stored.
/// This corresponds to the maximum number of proof types (zkVM+EL combinations)
/// that can be supported, which is currently 8 (ExecutionProofId is 0-7).
pub const MAX_PROOFS: usize = 8;

type ProofData = VariableList<u8, typenum::U1048576>;

/// ExecutionProof represents a cryptographic `proof of execution` that
/// an execution payload is valid.
///
/// In short, it is proof that if we were to run a particular execution layer client
/// with the given execution payload, they would return the output values that are attached
/// to the proof.
///
/// Each proof is associated with a specific proof_id, which identifies the
/// zkVM and EL combination used to generate it. Multiple proofs from different
/// proof IDs can exist for the same execution payload, providing both zkVM and EL diversity.
#[derive(Clone, Serialize, Deserialize, DeriveEncode, Decode, TreeHash, PartialEq, Eq)]
pub struct ExecutionProof {
    /// Which proof type (zkVM+EL combination) this proof belongs to
    /// Examples: 0=SP1+Reth, 1=Risc0+Geth, 2=SP1+Geth, etc.
    pub proof_id: ExecutionProofId,

    /// The slot of the beacon block this proof validates
    pub slot: Slot,

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
        proof_id: ExecutionProofId,
        slot: Slot,
        block_hash: ExecutionBlockHash,
        block_root: Hash256,
        proof_data: Vec<u8>,
    ) -> Result<Self, String> {
        let proof_data = ProofData::new(proof_data)
            .map_err(|e| format!("Failed to create proof data: {:?}", e))?;

        Ok(Self {
            proof_id,
            slot,
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

    /// Check if this proof is from a specific proof type
    pub fn is_from_proof_type(&self, proof_id: ExecutionProofId) -> bool {
        self.proof_id == proof_id
    }

    /// Get the proof type ID
    pub fn proof_id(&self) -> ExecutionProofId {
        self.proof_id
    }

    /// Minimum size of an ExecutionProof in SSZ bytes (with empty proof_data)
    /// TODO(zkproofs): If the proof_data is empty, then that is an invalid proof
    pub fn min_size() -> usize {
        use bls::FixedBytesExtended;
        Self {
            proof_id: ExecutionProofId::new(0).unwrap(),
            slot: Slot::new(0),
            block_hash: ExecutionBlockHash::zero(),
            block_root: Hash256::zero(),
            proof_data: ProofData::new(vec![]).unwrap(),
        }
        .as_ssz_bytes()
        .len()
    }

    /// Maximum size of an ExecutionProof in SSZ bytes (with max proof_data)
    pub fn max_size() -> usize {
        use bls::FixedBytesExtended;
        Self {
            proof_id: ExecutionProofId::new(0).unwrap(),
            slot: Slot::new(0),
            block_hash: ExecutionBlockHash::zero(),
            block_root: Hash256::zero(),
            proof_data: ProofData::new(vec![0u8; MAX_PROOF_DATA_BYTES]).unwrap(),
        }
        .as_ssz_bytes()
        .len()
    }
}

impl Debug for ExecutionProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutionProof")
            .field("proof_id", &self.proof_id)
            .field("slot", &self.slot)
            .field("block_hash", &self.block_hash)
            .field("block_root", &self.block_root)
            .field("proof_data_size", &self.proof_data.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::FixedBytesExtended;

    #[test]
    fn test_execution_proof_too_large() {
        let subnet_id = ExecutionProofId::new(0).unwrap();
        let slot = Slot::new(100);
        let block_hash = ExecutionBlockHash::zero();
        let block_root = Hash256::zero();
        let proof_data = vec![0u8; MAX_PROOF_DATA_BYTES + 1];

        let result = ExecutionProof::new(subnet_id, slot, block_hash, block_root, proof_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to create proof data"));
    }

    #[test]
    fn test_execution_proof_max_size() {
        let subnet_id = ExecutionProofId::new(0).unwrap();
        let slot = Slot::new(100);
        let block_hash = ExecutionBlockHash::zero();
        let block_root = Hash256::zero();
        let proof_data = vec![0u8; MAX_PROOF_DATA_BYTES];

        let result = ExecutionProof::new(subnet_id, slot, block_hash, block_root, proof_data);
        assert!(result.is_ok());
    }

}