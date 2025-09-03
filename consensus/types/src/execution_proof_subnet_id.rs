//! Identifies each execution proof subnet by an integer identifier.
use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};
use std::fmt::{self, Display};
use std::ops::{Deref, DerefMut};

/// Maximum number of execution proof subnets allowed by the protocol.
///
/// This is a hard protocol limit that defines the total number of proof subnets
/// that can exist in the network. Individual nodes may choose to participate in
/// fewer subnets (configured via max_execution_proof_subnets in ChainConfig),
/// but no node can exceed this protocol maximum.
///
/// The value of 8 subnets provides a good balance between:
/// - Proof diversity (multiple independent proofs per block)
/// - Network overhead (not too many gossip topics)
/// - Resource requirements (reasonable for most nodes(?))
///
/// In reality, I do not think we will have 8, more closer to 3, though this is still being
/// explored. This number could be larger if we consider combining different zkVMs with different guests.
pub const MAX_EXECUTION_PROOF_SUBNETS: u64 = 8;

/// ExecutionProofSubnetId is both the id for the subnet that a particular proof will be on
/// and the proof ID to identify the proof. ie, we have one type of proof per subnet.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExecutionProofSubnetId(#[serde(with = "serde_utils::quoted_u64")] u64);

impl ExecutionProofSubnetId {
    /// Create an ExecutionProofSubnetId from a u64, validating it's within bounds
    ///
    /// Note: bounds here relates to the fact that there is a maximum number of subnets
    /// that we can have; it is the number of maximum number of proofs that we will accept.
    pub fn new(id: u64) -> Result<Self, InvalidSubnetId> {
        if id >= MAX_EXECUTION_PROOF_SUBNETS {
            return Err(InvalidSubnetId(id));
        }
        Ok(Self(id))
    }
}

impl Display for ExecutionProofSubnetId {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl Deref for ExecutionProofSubnetId {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ExecutionProofSubnetId {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<ExecutionProofSubnetId> for u64 {
    fn from(val: ExecutionProofSubnetId) -> Self {
        val.0
    }
}

impl From<&ExecutionProofSubnetId> for u64 {
    fn from(val: &ExecutionProofSubnetId) -> Self {
        val.0
    }
}

#[derive(Debug)]
pub struct InvalidSubnetId(pub u64);

impl std::fmt::Display for InvalidSubnetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Invalid execution proof subnet ID: {}, must be < {}",
            self.0, MAX_EXECUTION_PROOF_SUBNETS
        )
    }
}

impl std::error::Error for InvalidSubnetId {}

// Manual SSZ implementations for ExecutionProofSubnetId
impl Encode for ExecutionProofSubnetId {
    fn is_ssz_fixed_len() -> bool {
        <u64 as Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u64 as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf)
    }
}

impl Decode for ExecutionProofSubnetId {
    fn is_ssz_fixed_len() -> bool {
        <u64 as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u64 as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        u64::from_ssz_bytes(bytes).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_proof_subnet_id_creation() {
        for id in 0..MAX_EXECUTION_PROOF_SUBNETS {
            let subnet_id = ExecutionProofSubnetId::new(id).unwrap();
            assert_eq!(*subnet_id, id);
        }

        assert!(ExecutionProofSubnetId::new(0).is_ok());
        assert!(ExecutionProofSubnetId::new(7).is_ok());
        assert!(ExecutionProofSubnetId::new(MAX_EXECUTION_PROOF_SUBNETS).is_err());
        assert!(ExecutionProofSubnetId::new(u64::MAX).is_err());
    }
}
