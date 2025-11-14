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
    /// - `public_key`: The public key bytes (52 bytes for XMSS)
    /// - `epoch`: The epoch/slot number
    /// - `message`: The message bytes to verify
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise
    ///
    /// # TODO
    /// Implement XMSS signature verification using the hashsig crate.
    /// This requires:
    /// 1. Configuring the GeneralizedXMSSSignatureScheme with the correct parameters
    ///    matching the Python spec (TEST_CONFIG or PROD_CONFIG)
    /// 2. Setting up the Poseidon2 tweakable hash function
    /// 3. Configuring the incomparable encoding with LOG_LIFETIME = 24
    /// 4. Deserializing the public key and signature from bytes
    /// 5. Calling the verify function with the correct parameters
    ///
    /// Reference: /Users/manasnagaraj/projects/oss/sigmaprime/leanSpec/src/lean_spec/subspecs/xmss/interface.py
    pub fn verify(&self, _public_key: &[u8], _epoch: u64, _message: &[u8]) -> bool {
        // For now, return false to maintain security
        // Signature verification should be explicitly enabled once properly implemented
        false
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
