//! Identifies each execution proof subnet by an integer identifier.
use safe_arith::ArithError;
use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};
use std::fmt::{self, Display};
use std::ops::{Deref, DerefMut};

/// Maximum number of execution proof subnets
/// This should match DEFAULT_MAX_EXECUTION_PROOF_SUBNETS from execution_payload_proofs.rs
pub const MAX_EXECUTION_PROOF_SUBNETS: u64 = 8;

#[derive(arbitrary::Arbitrary, Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExecutionProofSubnetId(#[serde(with = "serde_utils::quoted_u64")] u64);

impl ExecutionProofSubnetId {
    pub fn new(id: u64) -> Self {
        id.into()
    }

    /// Create an ExecutionProofSubnetId from a ProofId
    /// Since ProofId directly maps to subnet ID, this is a simple conversion
    pub fn from_proof_id(proof_id: u64) -> Result<Self, Error> {
        if proof_id >= MAX_EXECUTION_PROOF_SUBNETS {
            return Err(Error::InvalidSubnetId(proof_id));
        }
        Ok(Self(proof_id))
    }

    /// Validate that this subnet ID is within acceptable bounds
    pub fn is_valid(&self) -> bool {
        self.0 < MAX_EXECUTION_PROOF_SUBNETS
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

impl From<u64> for ExecutionProofSubnetId {
    fn from(x: u64) -> Self {
        Self(x)
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
pub enum Error {
    ArithError(ArithError),
    InvalidSubnetId(u64),
}

impl From<ArithError> for Error {
    fn from(e: ArithError) -> Self {
        Error::ArithError(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ArithError(e) => write!(f, "Arithmetic error: {:?}", e),
            Error::InvalidSubnetId(id) => write!(
                f,
                "Invalid execution proof subnet ID: {}, must be < {}",
                id, MAX_EXECUTION_PROOF_SUBNETS
            ),
        }
    }
}

impl std::error::Error for Error {}

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
        // Valid subnet IDs
        for id in 0..MAX_EXECUTION_PROOF_SUBNETS {
            let subnet_id = ExecutionProofSubnetId::new(id);
            assert_eq!(*subnet_id, id);
            assert!(subnet_id.is_valid());
        }

        // Test from_proof_id
        assert!(ExecutionProofSubnetId::from_proof_id(0).is_ok());
        assert!(ExecutionProofSubnetId::from_proof_id(7).is_ok());
        assert!(ExecutionProofSubnetId::from_proof_id(8).is_err()); // >= MAX
        assert!(ExecutionProofSubnetId::from_proof_id(100).is_err());
    }

    #[test]
    fn test_execution_proof_subnet_id_validation() {
        // Valid IDs
        assert!(ExecutionProofSubnetId::new(0).is_valid());
        assert!(ExecutionProofSubnetId::new(7).is_valid());

        // Invalid IDs (outside bounds)
        assert!(!ExecutionProofSubnetId::new(8).is_valid());
        assert!(!ExecutionProofSubnetId::new(100).is_valid());
    }

    #[test]
    fn test_execution_proof_subnet_id_conversions() {
        let subnet_id = ExecutionProofSubnetId::new(5);

        // Test Deref
        assert_eq!(*subnet_id, 5);

        // Test Into/From u64
        let id_u64: u64 = subnet_id.into();
        assert_eq!(id_u64, 5);

        let subnet_id2 = ExecutionProofSubnetId::from(5u64);
        assert_eq!(subnet_id, subnet_id2);

        // Test Into/From &u64
        let id_ref: u64 = (&subnet_id).into();
        assert_eq!(id_ref, 5);
    }

    #[test]
    fn test_execution_proof_subnet_id_display() {
        let subnet_id = ExecutionProofSubnetId::new(3);
        assert_eq!(format!("{}", subnet_id), "3");
    }
}
