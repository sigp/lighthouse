use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};
use std::fmt::{self, Display};
use tree_hash::TreeHash;

/// Number of execution proofs
/// Each proof represents a different zkVM+EL combination
///
/// TODO(zkproofs): The number 8 is a parameter that we will want to configure in the future
pub const EXECUTION_PROOF_TYPE_COUNT: u8 = 8;

/// ExecutionProofId identifies which zkVM/proof system a proof belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExecutionProofId(u8);

impl Encode for ExecutionProofId {
    fn is_ssz_fixed_len() -> bool {
        <u8 as Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u8 as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf)
    }

    fn as_ssz_bytes(&self) -> Vec<u8> {
        self.0.as_ssz_bytes()
    }
}

impl Decode for ExecutionProofId {
    fn is_ssz_fixed_len() -> bool {
        <u8 as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u8 as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let value = u8::from_ssz_bytes(bytes)?;
        Self::new(value).map_err(DecodeError::BytesInvalid)
    }
}

impl TreeHash for ExecutionProofId {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <u8 as TreeHash>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <u8 as TreeHash>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}

impl ExecutionProofId {
    /// Creates a new ExecutionProofId if the value is valid
    pub fn new(id: u8) -> Result<Self, String> {
        if id < EXECUTION_PROOF_TYPE_COUNT {
            Ok(Self(id))
        } else {
            Err(format!(
                "Invalid ExecutionProofId: {}, must be < {}",
                id, EXECUTION_PROOF_TYPE_COUNT
            ))
        }
    }

    /// Returns the inner u8 value
    pub fn as_u8(&self) -> u8 {
        self.0
    }

    /// Returns the subnet ID as a usize
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }

    /// Returns all valid subnet IDs
    pub fn all() -> Vec<Self> {
        (0..EXECUTION_PROOF_TYPE_COUNT).map(Self).collect()
    }
}

impl Display for ExecutionProofId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<ExecutionProofId> for u8 {
    fn from(subnet_id: ExecutionProofId) -> u8 {
        subnet_id.0
    }
}

impl TryFrom<u8> for ExecutionProofId {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_proof_ids() {
        for id in 0..EXECUTION_PROOF_TYPE_COUNT {
            assert!(ExecutionProofId::new(id).is_ok());
        }
    }

    #[test]
    fn test_invalid_proof_ids() {
        assert!(ExecutionProofId::new(EXECUTION_PROOF_TYPE_COUNT).is_err());
    }

    #[test]
    fn test_all_proof_ids() {
        let all = ExecutionProofId::all();
        assert_eq!(all.len(), EXECUTION_PROOF_TYPE_COUNT as usize);
        for (idx, proof_id) in all.iter().enumerate() {
            assert_eq!(proof_id.as_usize(), idx);
        }
    }
}
