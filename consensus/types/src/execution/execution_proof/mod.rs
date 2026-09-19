mod envelope;
mod proof_type;

pub use envelope::{ExecutionProofEnvelope, SignedExecutionProofEnvelope};
pub use proof_type::{ProofType, UnassignedProofType, ZkvmKind};

use crate::{ForkName, Hash256};
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash_derive::TreeHash;

/// SSZ bound for `proof_data`: 4 MiB (4,194,304 bytes).
pub type MaxProofSize = typenum::U4194304;

/// Schema identifier for the Amsterdam stateless execution input, revision 1.
const STATELESS_INPUT_SCHEMA_ID: u16 = 0x1501;

/// Opaque proof bytes, bounded by EIP-8025 `MAX_PROOF_SIZE`.
pub type ProofData = VariableList<u8, MaxProofSize>;

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct PublicInput {
    pub new_payload_request_root: Hash256,
    pub successful_validation: bool,
    #[serde(with = "serde_utils::quoted_u64")]
    pub chain_id: u64,
    pub schema_id: u16,
}

/// An execution proof and the proof-system public input used to verify it.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct ExecutionProof {
    pub proof_data: ProofData,
    pub proof_type: ProofType,
    pub public_input: PublicInput,
}

impl ExecutionProof {
    /// Construct an execution proof from proof data and public input values.
    pub fn new(
        proof_data: ProofData,
        proof_type: ProofType,
        new_payload_request_root: Hash256,
        chain_id: u64,
    ) -> Self {
        Self {
            proof_data,
            proof_type,
            public_input: PublicInput {
                new_payload_request_root,
                successful_validation: true,
                chain_id,
                schema_id: STATELESS_INPUT_SCHEMA_ID,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_proof_constructor_uses_proof_and_public_input_context() {
        let proof_data = ProofData::new(vec![1, 2, 3]).expect("valid proof data");
        let proof_type = ProofType::RethOpenVM;
        let new_payload_request_root = Hash256::repeat_byte(0x22);

        let proof =
            ExecutionProof::new(proof_data.clone(), proof_type, new_payload_request_root, 1);

        assert_eq!(proof.proof_data, proof_data);
        assert_eq!(proof.proof_type, proof_type);
        assert_eq!(
            proof.public_input,
            PublicInput {
                new_payload_request_root,
                successful_validation: true,
                chain_id: 1,
                schema_id: STATELESS_INPUT_SCHEMA_ID,
            }
        );
    }
}
