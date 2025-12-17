use ssz_derive::{Decode, Encode};
use ssz_types::FixedVector;
use tree_hash_derive::TreeHash;
use typenum::*;

/// XMSS signature size in bytes (3112 bytes)
pub const SIGNATURE_SIZE: usize = 3112;

/// Type alias for U3112 = U2048 + U1024 + U40
type U3112 = Sum<Sum<U2048, U1024>, U40>;

/// XMSS signature represented as fixed-size vector (3112 bytes)
#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, TreeHash)]
pub struct Signature {
    bytes: FixedVector<u8, U3112>,
}

impl Signature {
    /// Create a new signature from a 3112-byte array
    pub fn from_bytes(bytes: [u8; SIGNATURE_SIZE]) -> Self {
        Self {
            bytes: FixedVector::new(bytes.to_vec())
                .expect("Fixed vector creation should not fail for correct size"),
        }
    }

    /// Create a signature from a byte slice (must be exactly SIGNATURE_SIZE bytes)
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(format!(
                "Invalid signature length: expected {}, got {}",
                SIGNATURE_SIZE,
                bytes.len()
            ));
        }
        let vec = bytes.to_vec();
        let fixed =
            FixedVector::new(vec).map_err(|e| format!("Failed to create fixed vector: {:?}", e))?;
        Ok(Self { bytes: fixed })
    }

    /// Get the signature as a slice
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Create a zero-filled signature
    pub fn zero() -> Self {
        Self {
            bytes: FixedVector::new(vec![0u8; SIGNATURE_SIZE])
                .expect("Fixed vector creation should not fail for correct size"),
        }
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self::zero()
    }
}

impl core::fmt::Display for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x")?;
        for byte in self.bytes.iter().take(6) {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "...({} bytes)", SIGNATURE_SIZE)?;
        Ok(())
    }
}

impl core::hash::Hash for Signature {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl From<[u8; SIGNATURE_SIZE]> for Signature {
    fn from(bytes: [u8; SIGNATURE_SIZE]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// SSZ Encoding/Decoding is derived from FixedVector implementation
// TreeHash is also derived from FixedVector implementation

use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
use leansig::signature::SignatureScheme;
use leansig::serialization::Serializable;
use leansig::MESSAGE_LENGTH;

pub type LeanSigScheme = SIGTopLevelTargetSumLifetime32Dim64Base8;
type PublicKeyType = <LeanSigScheme as SignatureScheme>::PublicKey;
type SignatureType = <LeanSigScheme as SignatureScheme>::Signature;

/// Verify an XMSS signature
pub fn verify_signature(
    pubkey_bytes: &[u8],
    message: &[u8],
    signature: &Signature,
    epoch: u64,
) -> Result<bool, String> {
    if message.len() != MESSAGE_LENGTH {
        return Err(format!(
            "Invalid message length: expected {}, got {}",
            MESSAGE_LENGTH,
            message.len()
        ));
    }

    // Convert message slice to fixed array
    let mut message_array = [0u8; MESSAGE_LENGTH];
    message_array.copy_from_slice(message);

    // Deserialize public key
    // The public key in Lighthouse is just the raw bytes (FixedVector<u8, U52>)
    // We need to parse it into the leanSig PublicKey type
    let pk = PublicKeyType::from_bytes(pubkey_bytes)
        .map_err(|_| "Failed to deserialize public key".to_string())?;

    // Deserialize signature
    // The signature in Lighthouse is a wrapper around the raw bytes
    let sig = SignatureType::from_bytes(&signature.bytes[..])
        .map_err(|_| "Failed to deserialize signature".to_string())?;

    // Verify
    let epoch32 = epoch as u32;
    Ok(LeanSigScheme::verify(&pk, epoch32, &message_array, &sig))
}
