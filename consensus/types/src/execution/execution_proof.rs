use crate::{ForkName, Hash256, SignedRoot};
use bls::Signature;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash_derive::TreeHash;

/// Maximum size of `proof_data` in bytes (EIP-8025 `MAX_PROOF_SIZE`).
pub const MAX_PROOF_SIZE: usize = 4_194_304;

/// SSZ bound for `proof_data`.
pub type MaxProofSize = typenum::U4194304;

/// Opaque proof bytes, the EIP-8025 `ProofData` (a `ByteList` limited to `MAX_PROOF_SIZE`).
pub type ProofData = VariableList<u8, MaxProofSize>;

/// Identifier for the proof system, guest program and version (EIP-8025 `ProofType`).
pub type ProofType = u8;

/// The proof types this node will dispatch to a proof engine (EIP-8025
/// `get_supported_proof_types`).
pub const SUPPORTED_PROOF_TYPES: [ProofType; 3] = [1, 2, 3];

/// The Amsterdam protocol fork (`0x15`) and schema revision (`0x01`), pinning the input schema a
/// guest was run against (EIP-8025 `STATELESS_INPUT_SCHEMA_ID`).
pub const STATELESS_INPUT_SCHEMA_ID: u16 = 0x1501;

/// What a proof claims, and the chain and schema it claims it against.
///
/// Never gossiped: a node builds this from the payload envelope it accepted, so a prover cannot
/// assert its own public input.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
#[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 1, 1, 1))]
pub struct PublicInput {
    pub new_payload_request_root: Hash256,
    pub successful_validation: bool,
    #[serde(with = "serde_utils::quoted_u64")]
    pub chain_id: u64,
    pub schema_id: u16,
}

/// An execution proof as the proof engine sees it (EIP-8025 `ExecutionProof`).
///
/// Built locally by `get_execution_proof`, never sent or received.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct ExecutionProof {
    pub proof_data: ProofData,
    pub proof_type: ProofType,
    pub public_input: PublicInput,
}

/// An execution proof as it travels the `execution_proof` topic (EIP-8025
/// `ExecutionProofEnvelope`), keyed to the beacon block whose envelope committed the payload.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct ExecutionProofEnvelope {
    pub proof_data: ProofData,
    pub proof_type: ProofType,
    pub beacon_block_root: Hash256,
}

impl SignedRoot for ExecutionProofEnvelope {}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct SignedExecutionProofEnvelope {
    pub message: ExecutionProofEnvelope,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub signature: Signature,
}

impl SignedExecutionProofEnvelope {
    pub fn beacon_block_root(&self) -> Hash256 {
        self.message.beacon_block_root
    }

    pub fn proof_type(&self) -> ProofType {
        self.message.proof_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(SignedExecutionProofEnvelope);
}
