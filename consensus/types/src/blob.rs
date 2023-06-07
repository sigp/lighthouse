use arbitrary::{Arbitrary, Unstructured};
use kzg::{self, BYTES_PER_BLOB, BYTES_PER_FIELD_ELEMENT, FIELD_ELEMENTS_PER_BLOB};
use safe_arith::SafeArith;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, DecodeError, Encode};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use tree_hash::{PackedEncoding, TreeHash};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blob(Arc<kzg::Blob>);

impl Blob {
    pub fn from_hex(hex: &str) -> Result<Self, String> {
        Ok(Self(Arc::new(
            kzg::Blob::from_hex(hex).map_err(|e| format!("invalid hex: {:?}", e))?,
        )))
    }

    pub fn c_kzg_blob(&self) -> &kzg::Blob {
        self.0.as_ref()
    }
}

impl From<[u8; BYTES_PER_BLOB]> for Blob {
    fn from(bytes: [u8; BYTES_PER_BLOB]) -> Self {
        Blob(Arc::new(kzg::Blob::from(bytes)))
    }
}

impl TryFrom<Vec<u8>> for Blob {
    type Error = String;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let length = bytes.len();
        let fixed: [u8; BYTES_PER_BLOB] = bytes.try_into().map_err(|_| {
            format!(
                "Invalid blob length: {} bytes, expected {}",
                length, BYTES_PER_BLOB
            )
        })?;
        Ok(Self(Arc::new(kzg::Blob::from(fixed))))
    }
}

impl TreeHash for Blob {
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
        let num_leaves = BYTES_PER_BLOB
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

impl Default for Blob {
    fn default() -> Self {
        Blob(Arc::new(kzg::Blob::from([0; BYTES_PER_BLOB])))
    }
}

impl<'a> Arbitrary<'a> for Blob {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut bytes = [0; BYTES_PER_BLOB];
        u.fill_buffer(&mut bytes)?;
        // Ensure that the blob is canonical by ensuring that
        // each field element contained in the blob is < BLS_MODULUS
        for i in 0..FIELD_ELEMENTS_PER_BLOB {
            let offset = i
                .safe_mul(BYTES_PER_FIELD_ELEMENT)
                .and_then(|o| o.safe_add(BYTES_PER_FIELD_ELEMENT))
                .and_then(|o| o.safe_sub(1))
                .expect("unsafe math while generating random blob");
            if let Some(byte) = bytes.get_mut(offset) {
                *byte = 0;
            }
        }
        Ok(Self(Arc::new(kzg::Blob::from(bytes))))
    }
}

impl AsRef<[u8]> for Blob {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref().as_ref()
    }
}

impl Encode for Blob {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.0.as_ref().as_ref())
    }

    fn ssz_bytes_len(&self) -> usize {
        BYTES_PER_BLOB
    }
}

impl Decode for Blob {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        BYTES_PER_BLOB
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != BYTES_PER_BLOB {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: BYTES_PER_BLOB,
            });
        }

        let mut array = [0; BYTES_PER_BLOB];
        array[..].copy_from_slice(bytes);

        Ok(Self(Arc::new(kzg::Blob::from(array))))
    }
}

impl Hash for Blob {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_ref().as_ref().hash(state)
    }
}

impl Serialize for Blob {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_string = format!("0x{}", hex::encode(self.0.as_ref().as_ref()));
        serializer.serialize_str(&hex_string)
    }
}

impl<'de> Deserialize<'de> for Blob {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BlobVisitor;

        impl<'de> Visitor<'de> for BlobVisitor {
            type Value = Blob;

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

                if bytes.len() != BYTES_PER_BLOB {
                    return Err(de::Error::invalid_length(
                        bytes.len(),
                        &"a blob with the correct byte length",
                    ));
                }

                let mut array = [0; BYTES_PER_BLOB];
                array[..].copy_from_slice(&bytes);

                Ok(Blob(Arc::new(kzg::Blob::from(array))))
            }
        }

        deserializer.deserialize_str(BlobVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestRandom;
    use crate::{EthSpec, FixedVector};

    type OldBlob<E> = FixedVector<u8, <E as EthSpec>::BytesPerBlob>;
    #[cfg(feature = "spec-minimal")]
    type E = crate::MinimalEthSpec;
    #[cfg(not(feature = "spec-minimal"))]
    type E = crate::MainnetEthSpec;

    #[test]
    fn tree_hash_equivalence() {
        let new_blob = Blob::random_for_test(&mut rand::thread_rng());
        let old_blob = OldBlob::<E>::new(Vec::from(new_blob.as_ref())).unwrap();

        // test that their tree_hash_roots are the same
        assert_eq!(
            old_blob.tree_hash_root(),
            new_blob.tree_hash_root(),
            "Tree Hash Roots should be the same"
        );
    }

    #[test]
    fn ssz_equivalence() {
        let new_blob = Blob::random_for_test(&mut rand::thread_rng());
        let old_blob = OldBlob::<E>::new(Vec::from(new_blob.as_ref())).unwrap();

        // test that their ssz encodings are the same
        assert_eq!(
            old_blob.as_ssz_bytes(),
            new_blob.as_ssz_bytes(),
            "SSZ encodings should be the same"
        );
    }

    ssz_and_tree_hash_tests!(Blob);
}
