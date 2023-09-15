use crate::EthSpec;
use arbitrary::{Arbitrary, Unstructured};
use kzg::{BlobTrait, KzgPreset, BYTES_PER_FIELD_ELEMENT};
use rand::Rng;
use safe_arith::SafeArith;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use ssz::{Decode, DecodeError, Encode};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use tree_hash::{PackedEncoding, TreeHash};

/// A wrapper around a c_kzg::Blob that implements all the required traits
/// to be easily included & used in other consensus types. The blob is wrapped
/// in an Arc making it cheaply cloneable & allocated on the heap.
///
/// Use the `c_kzg_blob` method to obtain a reference to the underlying blob
#[derive(Clone, PartialEq, Eq)]
pub struct WrappedBlob<E: EthSpec>(Arc<<E::Kzg as KzgPreset>::Blob>);
impl<E: EthSpec> WrappedBlob<E> {
    /// Constructs a new blob from random bytes while ensuring it conforms
    /// to the canonical form required for cryptographic operations.
    fn canonical_blob_from_bytes(random_bytes: &mut [u8]) -> Result<Self, String> {
        // Ensure that the blob is canonical by ensuring that
        // each field element contained in the blob is < BLS_MODULUS
        for i in 0..<E::Kzg as KzgPreset>::FIELD_ELEMENTS_PER_BLOB {
            let Some(byte) = random_bytes.get_mut(
                i.checked_mul(BYTES_PER_FIELD_ELEMENT)
                    .ok_or("overflow".to_string())?,
            ) else {
                return Err(format!("blob byte index out of bounds: {:?}", i));
            };
            *byte = 0;
        }
        <E::Kzg as KzgPreset>::Blob::from_bytes(random_bytes)
            .map(|blob| Self(Arc::new(blob)))
            .map_err(|e| format!("failed to create blob: {:?}", e))
    }

    pub fn random_valid<R: Rng>(rng: &mut R) -> Result<Self, String> {
        let mut blob_bytes = vec![0u8; <E::Kzg as KzgPreset>::BYTES_PER_BLOB];
        rng.fill_bytes(&mut blob_bytes);
        Self::canonical_blob_from_bytes(&mut blob_bytes)
    }

    /// Obtain a reference to the underlying c_kzg::Blob
    pub fn c_kzg_blob(&self) -> &<E::Kzg as KzgPreset>::Blob {
        self.0.as_ref()
    }
}

impl<'a, E: EthSpec> Arbitrary<'a> for WrappedBlob<E> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut blob_bytes = vec![0u8; <E::Kzg as KzgPreset>::BYTES_PER_BLOB];
        u.fill_buffer(&mut blob_bytes)?;
        Self::canonical_blob_from_bytes(&mut blob_bytes)
            .map_err(|_| arbitrary::Error::NotEnoughData)
    }
}

impl<E: EthSpec> Hash for WrappedBlob<E> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_ref().as_ref().hash(state)
    }
}

impl<E: EthSpec> Serialize for WrappedBlob<E> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_string = format!("0x{}", hex::encode(self.0.as_ref().as_ref()));
        serializer.serialize_str(&hex_string)
    }
}

impl<'de, T: EthSpec> Deserialize<'de> for WrappedBlob<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BlobVisitor<T: EthSpec> {
            _marker: std::marker::PhantomData<T>,
        }

        impl<'de, T: EthSpec> Visitor<'de> for BlobVisitor<T> {
            type Value = WrappedBlob<T>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a hex-encoded string representing a blob")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let hex_value = value
                    .strip_prefix("0x")
                    .ok_or_else(|| de::Error::invalid_value(de::Unexpected::Str(value), &self))?;

                let bytes = hex::decode(hex_value)
                    .map_err(|_| de::Error::invalid_value(de::Unexpected::Str(value), &self))?;

                let kzg_blob =
                    <T::Kzg as KzgPreset>::Blob::from_bytes(bytes.as_slice()).map_err(|_| {
                        de::Error::invalid_length(
                            bytes.len(),
                            &"a blob with the correct byte length",
                        )
                    })?;

                Ok(WrappedBlob(Arc::new(kzg_blob)))
            }
        }

        deserializer.deserialize_str(BlobVisitor {
            _marker: std::marker::PhantomData,
        })
    }
}

impl<E: EthSpec> Encode for WrappedBlob<E> {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.0.as_ref().as_ref())
    }

    fn ssz_bytes_len(&self) -> usize {
        <E::Kzg as KzgPreset>::BYTES_PER_BLOB
    }

    fn ssz_fixed_len() -> usize {
        <E::Kzg as KzgPreset>::BYTES_PER_BLOB
    }
}

impl<E: EthSpec> Decode for WrappedBlob<E> {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        <E::Kzg as KzgPreset>::BYTES_PER_BLOB
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let kzg_blob = <E::Kzg as KzgPreset>::Blob::from_bytes(bytes).map_err(|_| {
            DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: <E::Kzg as KzgPreset>::BYTES_PER_BLOB,
            }
        })?;

        Ok(Self(Arc::new(kzg_blob)))
    }
}

impl<E: EthSpec> TryFrom<Vec<u8>> for WrappedBlob<E> {
    type Error = String;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let length = bytes.len();
        let kzg_blob = <E::Kzg as KzgPreset>::Blob::from_bytes(bytes.as_slice()).map_err(|_| {
            format!(
                "Invalid blob length: {} bytes, expected {}",
                length,
                <E::Kzg as KzgPreset>::BYTES_PER_BLOB
            )
        })?;
        Ok(Self(Arc::new(kzg_blob)))
    }
}

impl<E: EthSpec> TreeHash for WrappedBlob<E> {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Vector
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        let num_leaves = <E::Kzg as KzgPreset>::BYTES_PER_BLOB
            .safe_add(u8::tree_hash_packing_factor())
            .and_then(|n| n.safe_sub(1))
            .and_then(|n| n.safe_div(u8::tree_hash_packing_factor()))
            .expect("unsafe math in tree_hash_root of Blob");
        let mut hasher = tree_hash::MerkleHasher::with_leaves(num_leaves);

        for byte in self.0.as_ref().as_ref() {
            hasher
                .write(&byte.tree_hash_packed_encoding())
                .expect("ssz_types variable vec should not contain more elements than max");
        }

        hasher
            .finish()
            .expect("ssz_types variable vec should not have a remaining buffer")
    }
}

impl<E: EthSpec> Default for WrappedBlob<E> {
    fn default() -> Self {
        let bytes = vec![0u8; <E::Kzg as KzgPreset>::BYTES_PER_BLOB];
        WrappedBlob(Arc::new(
            <E::Kzg as KzgPreset>::Blob::from_bytes(bytes.as_slice())
                .expect("default blob should be valid"),
        ))
    }
}

impl<E: EthSpec> std::fmt::Debug for WrappedBlob<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", serde_utils::hex::encode(self.0.as_ref()))
    }
}
