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

#[derive(Clone, PartialEq, Eq)]
pub struct SigpBlob<E: EthSpec>(Arc<<E::Kzg as KzgPreset>::Blob>);

impl<E: EthSpec> SigpBlob<E> {
    pub fn random_valid<R: Rng>(rng: &mut R) -> Result<Self, String> {
        let mut blob_bytes = vec![0u8; <E::Kzg as KzgPreset>::BYTES_PER_BLOB];
        rng.fill_bytes(&mut blob_bytes);

        // Ensure that the blob is canonical by ensuring that
        // each field element contained in the blob is < BLS_MODULUS
        for i in 0..<E::Kzg as KzgPreset>::FIELD_ELEMENTS_PER_BLOB {
            let Some(byte) = blob_bytes.get_mut(
                i.checked_mul(BYTES_PER_FIELD_ELEMENT)
                    .ok_or("overflow".to_string())?,
            ) else {
                return Err(format!("blob byte index out of bounds: {:?}", i));
            };
            *byte = 0;
        }
        let kzg_blob = <E::Kzg as KzgPreset>::Blob::from_bytes(&blob_bytes)
            .map_err(|e| format!("failed to create blob: {:?}", e))?;
        Ok(Self(Arc::new(kzg_blob)))
    }

    pub fn c_kzg_blob(&self) -> &<E::Kzg as KzgPreset>::Blob {
        self.0.as_ref()
    }
}

impl<'a, E: EthSpec> Arbitrary<'a> for SigpBlob<E> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut blob_bytes = vec![0u8; <E::Kzg as KzgPreset>::BYTES_PER_BLOB];
        u.fill_buffer(&mut blob_bytes)?;
        // FIXME: what is the correct error condition here?
        //        also.. this is a duplication of the code above..
        let arbitrary_error = arbitrary::Error::NotEnoughData;
        for i in 0..<E::Kzg as KzgPreset>::FIELD_ELEMENTS_PER_BLOB {
            let Some(byte) = blob_bytes.get_mut(
                i.checked_mul(BYTES_PER_FIELD_ELEMENT)
                    .ok_or(arbitrary_error)?,
            ) else {
                return Err(arbitrary_error);
            };
            *byte = 0;
        }
        let kzg_blob =
            <E::Kzg as KzgPreset>::Blob::from_bytes(&blob_bytes).map_err(|_| arbitrary_error)?;
        Ok(Self(Arc::new(kzg_blob)))
    }
}

impl<E: EthSpec> Hash for SigpBlob<E> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_ref().as_ref().hash(state)
    }
}

impl<E: EthSpec> Serialize for SigpBlob<E> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_string = format!("0x{}", hex::encode(self.0.as_ref().as_ref()));
        serializer.serialize_str(&hex_string)
    }
}

impl<'de, T: EthSpec> Deserialize<'de> for SigpBlob<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BlobVisitor<T: EthSpec> {
            _marker: std::marker::PhantomData<T>,
        }

        impl<'de, T: EthSpec> Visitor<'de> for BlobVisitor<T> {
            type Value = SigpBlob<T>;

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

                Ok(SigpBlob(Arc::new(kzg_blob)))
            }
        }

        deserializer.deserialize_str(BlobVisitor {
            _marker: std::marker::PhantomData,
        })
    }
}

impl<E: EthSpec> Encode for SigpBlob<E> {
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

impl<E: EthSpec> Decode for SigpBlob<E> {
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

impl<E: EthSpec> TryFrom<Vec<u8>> for SigpBlob<E> {
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

impl<E: EthSpec> TreeHash for SigpBlob<E> {
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

impl<E: EthSpec> Default for SigpBlob<E> {
    fn default() -> Self {
        let bytes = vec![0u8; <E::Kzg as KzgPreset>::BYTES_PER_BLOB];
        SigpBlob(Arc::new(
            <E::Kzg as KzgPreset>::Blob::from_bytes(bytes.as_slice())
                .expect("default blob should be valid"),
        ))
    }
}

impl<E: EthSpec> std::fmt::Debug for SigpBlob<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", serde_utils::hex::encode(self.0.as_ref()))
    }
}
