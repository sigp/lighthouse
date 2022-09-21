/// Contains the functions required for a `TreeHash` implementation.
///
/// Does not include the `Impl` section since it gets very complicated when it comes to generics.
macro_rules! impl_tree_hash {
    ($byte_size: expr) => {
        fn tree_hash_type() -> tree_hash::TreeHashType {
            tree_hash::TreeHashType::Vector
        }

        fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
            unreachable!("Vector should never be packed.")
        }

        fn tree_hash_packing_factor() -> usize {
            unreachable!("Vector should never be packed.")
        }

        fn tree_hash_root(&self) -> tree_hash::Hash256 {
            // We could use the tree hash implementation for `FixedVec<u8, $byte_size>`,
            // but benchmarks have show that to be at least 15% slower because of the
            // unnecessary copying and allocation (one Vec per byte)
            let values_per_chunk = tree_hash::BYTES_PER_CHUNK;
            let minimum_chunk_count = ($byte_size + values_per_chunk - 1) / values_per_chunk;
            tree_hash::merkle_root(&self.serialize(), minimum_chunk_count)
        }
    };
}

/// Contains the functions required for a `ssz::Encode` implementation.
///
/// Does not include the `Impl` section since it gets very complicated when it comes to generics.
macro_rules! impl_ssz_encode {
    ($byte_size: expr) => {
        fn is_ssz_fixed_len() -> bool {
            true
        }

        fn ssz_fixed_len() -> usize {
            $byte_size
        }

        fn ssz_bytes_len(&self) -> usize {
            $byte_size
        }

        fn ssz_append(&self, buf: &mut Vec<u8>) {
            buf.extend_from_slice(&self.serialize())
        }
    };
}

/// Contains the functions required for a `ssz::Decode` implementation.
///
/// Does not include the `Impl` section since it gets very complicated when it comes to generics.
macro_rules! impl_ssz_decode {
    ($byte_size: expr) => {
        fn is_ssz_fixed_len() -> bool {
            true
        }

        fn ssz_fixed_len() -> usize {
            $byte_size
        }

        fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
            let len = bytes.len();
            let expected = <Self as ssz::Decode>::ssz_fixed_len();

            if len != expected {
                Err(ssz::DecodeError::InvalidByteLength { len, expected })
            } else {
                Self::deserialize(bytes)
                    .map_err(|e| ssz::DecodeError::BytesInvalid(format!("{:?}", e)))
            }
        }
    };
}

/// Contains the functions required for a `fmt::Display` implementation.
///
/// Does not include the `Impl` section since it gets very complicated when it comes to generics.
macro_rules! impl_display {
    () => {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", hex_encode(self.serialize().to_vec()))
        }
    };
}

/// Contains the functions required for a `fmt::Display` implementation.
///
/// Does not include the `Impl` section since it gets very complicated when it comes to generics.
macro_rules! impl_from_str {
    () => {
        type Err = String;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            if let Some(stripped) = s.strip_prefix("0x") {
                let bytes = hex::decode(stripped).map_err(|e| e.to_string())?;
                Self::deserialize(&bytes[..]).map_err(|e| format!("{:?}", e))
            } else {
                Err("must start with 0x".to_string())
            }
        }
    };
}

/// Contains the functions required for a `serde::Serialize` implementation.
///
/// Does not include the `Impl` section since it gets very complicated when it comes to generics.
macro_rules! impl_serde_serialize {
    () => {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&self.to_string())
        }
    };
}

/// Contains the functions required for a `serde::Deserialize` implementation.
///
/// Does not include the `Impl` section since it gets very complicated when it comes to generics.
macro_rules! impl_serde_deserialize {
    () => {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            pub struct StringVisitor;

            impl<'de> serde::de::Visitor<'de> for StringVisitor {
                type Value = String;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("a hex string with 0x prefix")
                }

                fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ok(value.to_string())
                }
            }

            let string = deserializer.deserialize_str(StringVisitor)?;
            <Self as std::str::FromStr>::from_str(&string).map_err(serde::de::Error::custom)
        }
    };
}

/// Contains the functions required for a `Debug` implementation.
///
/// Does not include the `Impl` section since it gets very complicated when it comes to generics.
macro_rules! impl_debug {
    () => {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", hex_encode(&self.serialize().to_vec()))
        }
    };
}

/// Contains the functions required for an `Arbitrary` implementation.
///
/// Does not include the `Impl` section since it gets very complicated when it comes to generics.
#[cfg(feature = "arbitrary")]
macro_rules! impl_arbitrary {
    ($byte_size: expr) => {
        fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
            let mut bytes = [0u8; $byte_size];
            u.fill_buffer(&mut bytes)?;
            Self::deserialize(&bytes).map_err(|_| arbitrary::Error::IncorrectFormat)
        }
    };
}
