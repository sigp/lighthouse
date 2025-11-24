use ssz::{Decode, DecodeError, Encode};
use tree_hash::TreeHash;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature {
    bytes: Vec<u8>,
}

impl Signature {
    /// Create a new signature from a byte vector.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Create an empty signature (zero-length).
    pub fn empty() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Returns true if this signature is empty (has no bytes).
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Get a reference to the signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert the signature to a byte vector.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Get the length of the signature in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Verify the signature using Generalized XMSS verification.
    ///
    /// # Parameters
    /// - `public_key`: The public key bytes (XMSS root + parameter values)
    /// - `epoch`: The epoch/slot number used for signature generation
    /// - `message`: The message hash to verify (32 bytes)
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise
    pub fn verify(&self, public_key: &[u8], epoch: u64, message: &[u8]) -> bool {
        use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
        use hashsig::signature::SignatureScheme;

        // Validate input lengths
        if self.bytes.is_empty() || public_key.is_empty() || message.len() != 32 {
            return false;
        }

        // Epoch must fit in u32 for XMSS
        let epoch_u32 = match epoch.try_into() {
            Ok(e) => e,
            Err(_) => return false,
        };

        // Deserialize the public key
        let public_key_deserialized: <SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::PublicKey =
            match bincode::deserialize(public_key) {
                Ok(pk) => pk,
                Err(_) => return false,
            };

        // Deserialize the signature
        let signature_deserialized: <SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::Signature =
            match bincode::deserialize(&self.bytes) {
                Ok(sig) => sig,
                Err(_) => return false,
            };

        // Convert message to fixed-size array (32 bytes)
        let mut message_array = [0u8; 32];
        if message.len() == 32 {
            message_array.copy_from_slice(message);
        } else {
            return false;
        }

        // Verify the signature
        SIGTopLevelTargetSumLifetime32Dim64Base8::verify(
            &public_key_deserialized,
            epoch_u32,
            &message_array,
            &signature_deserialized,
        )
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self::empty()
    }
}

impl core::fmt::Display for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x")?;
        for byte in self.bytes.iter().take(6) {
            write!(f, "{:02x}", byte)?;
        }
        if self.bytes.len() > 6 {
            write!(f, "...({} bytes)", self.bytes.len())?;
        }
        Ok(())
    }
}

impl core::hash::Hash for Signature {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl From<Vec<u8>> for Signature {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<Signature> for Vec<u8> {
    fn from(sig: Signature) -> Self {
        sig.into_bytes()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// SSZ Encoding/Decoding implementation for variable-length signatures
impl Encode for Signature {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.bytes);
    }

    fn ssz_bytes_len(&self) -> usize {
        self.bytes.len()
    }
}

impl Decode for Signature {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
}

// TreeHash implementation for variable-length signatures
impl TreeHash for Signature {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Vector
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("Vector should never be packed")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("Vector should never be packed")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        tree_hash::merkle_root(&self.bytes, 0)
    }
}
