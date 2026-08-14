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

/// Opaque proof bytes.
///
/// The EIP-8025 spec defines this as `ProgressiveByteList` (EIP-7916), which is not yet
/// supported by `ssz_types`. A `VariableList` serializes identically but merkleizes
/// differently, so signing roots are not interoperable with spec-conformant clients.
pub type ProofData = VariableList<u8, MaxProofSize>;

/// Identifier for the proof system that produced a proof (EIP-8025 `ProofType`).
pub type ProofType = u8;

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct PublicInput {
    pub new_payload_request_root: Hash256,
}

/// An execution proof attesting to the validity of an execution payload (EIP-8025).
///
/// Deviation from the spec: `beacon_block_root` binds the proof to the beacon block whose
/// envelope committed the payload, allowing the proof to be resolved without an index from
/// `new_payload_request_root` to block root.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct ExecutionProof {
    pub proof_data: ProofData,
    pub proof_type: ProofType,
    pub public_input: PublicInput,
    pub beacon_block_root: Hash256,
}

impl SignedRoot for ExecutionProof {}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct SignedExecutionProof {
    pub message: ExecutionProof,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub signature: Signature,
}

impl SignedExecutionProof {
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

    ssz_and_tree_hash_tests!(SignedExecutionProof);
}
