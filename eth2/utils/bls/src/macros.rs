macro_rules! impl_ssz {
    ($type: ident, $byte_size: expr, $item_str: expr) => {
        impl ssz::Encode for $type {
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
                buf.append(&mut self.as_bytes())
            }
        }

        impl ssz::Decode for $type {
            fn is_ssz_fixed_len() -> bool {
                true
            }

            fn ssz_fixed_len() -> usize {
                $byte_size
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
                let len = bytes.len();
                let expected = <Self as ssz::Decode>::ssz_fixed_len();

                if len != expected {
                    Err(ssz::DecodeError::InvalidByteLength { len, expected })
                } else {
                    $type::from_bytes(bytes)
                }
            }
        }
    };
}

macro_rules! impl_tree_hash {
    ($type: ty, $byte_size: expr) => {
        impl tree_hash::TreeHash for $type {
            fn tree_hash_type() -> tree_hash::TreeHashType {
                tree_hash::TreeHashType::Vector
            }

            fn tree_hash_packed_encoding(&self) -> Vec<u8> {
                unreachable!("Vector should never be packed.")
            }

            fn tree_hash_packing_factor() -> usize {
                unreachable!("Vector should never be packed.")
            }

            fn tree_hash_root(&self) -> Vec<u8> {
                // We could use the tree hash implementation for `FixedVec<u8, $byte_size>`,
                // but benchmarks have show that to be at least 15% slower because of the
                // unnecessary copying and allocation (one Vec per byte)
                let values_per_chunk = tree_hash::BYTES_PER_CHUNK;
                let minimum_chunk_count = ($byte_size + values_per_chunk - 1) / values_per_chunk;
                tree_hash::merkle_root(&self.as_ssz_bytes(), minimum_chunk_count)
            }
        }
    };
}

macro_rules! bytes_struct {
    ($name: ident, $type: ty, $byte_size: expr, $small_name: expr,
     $type_str: expr, $byte_size_str: expr) => {
        #[doc = "Stores `"]
        #[doc = $byte_size_str]
        #[doc = "` bytes which may or may not represent a valid BLS "]
        #[doc = $small_name]
        #[doc = ".\n\nThe `"]
        #[doc = $type_str]
        #[doc = "` struct performs validation when it is instantiated, where as this struct does \
                 not. This struct is suitable where we may wish to store bytes that are \
                 potentially not a valid "]
        #[doc = $small_name]
        #[doc = " (e.g., from the deposit contract)."]
        #[derive(Clone)]
        pub struct $name {
            bytes: [u8; $byte_size],
            decompressed: Option<$type>
        }
    };
    ($name: ident, $type: ty, $byte_size: expr, $small_name: expr) => {
        bytes_struct!($name, $type, $byte_size, $small_name, stringify!($type),
                      stringify!($byte_size));

        impl $name {
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
                Ok(Self {
                    bytes: Self::get_bytes(bytes)?,
                    decompressed: None
                })
            }

            pub fn empty() -> Self {
                Self {
                    bytes: [0; $byte_size],
                    decompressed: None
                }
            }

            pub fn as_bytes(&self) -> Vec<u8> {
                self.bytes.to_vec()
            }

            fn get_bytes(bytes: &[u8]) -> Result<[u8; $byte_size], ssz::DecodeError> {
                let mut result = [0; $byte_size];
                if bytes.len() != $byte_size {
                    Err(ssz::DecodeError::InvalidByteLength {
                        len: bytes.len(),
                        expected: $byte_size,
                    })
                } else {
                    result[..].copy_from_slice(bytes);
                    Ok(result)
                }
            }

            pub fn decompress(&mut self) -> Result<(), ssz::DecodeError> {
                self.decompressed = Some(<&Self as std::convert::TryInto<$type>>::try_into(self)?);
                Ok(())
            }

            pub fn decompressed(&self) -> &Option<$type> {
                &self.decompressed
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                self.bytes[..].fmt(formatter)
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                &self.bytes[..] == &other.bytes[..]
            }
        }

        impl std::hash::Hash for $name {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.bytes.hash(state)
            }
        }

        impl Eq for $name {}

        impl std::convert::TryInto<$type> for &$name {
            type Error = ssz::DecodeError;

            fn try_into(self) -> Result<$type, Self::Error> {
                <$type>::from_bytes(&self.bytes[..])
            }
        }

        impl std::convert::From<$type> for $name {
            fn from(obj: $type) -> Self {
                // We know that obj.as_bytes() always has exactly $byte_size many bytes.
                Self::from_bytes(obj.as_ssz_bytes().as_slice()).unwrap()
            }
        }

        impl_ssz!($name, $byte_size, "$type");

        impl_tree_hash!($name, $byte_size);

        impl serde::ser::Serialize for $name {
            /// Serde serialization is compliant the Ethereum YAML test format.
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                serializer.serialize_str(&serde_hex::encode(ssz::ssz_encode(self)))
            }
        }

        impl<'de> serde::de::Deserialize<'de> for $name {
            /// Serde serialization is compliant the Ethereum YAML test format.
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::de::Deserializer<'de>,
            {
                let bytes = deserializer.deserialize_str(serde_hex::PrefixedHexVisitor)?;
                let signature = Self::from_ssz_bytes(&bytes[..])
                    .map_err(|e| serde::de::Error::custom(format!("invalid ssz ({:?})", e)))?;
                Ok(signature)
            }
        }
    };
}
