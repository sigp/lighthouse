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
    ($type: ty, $byte_size: ident) => {
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
                let vector: ssz_types::FixedVector<u8, ssz_types::typenum::$byte_size> =
                    ssz_types::FixedVector::from(self.as_ssz_bytes());
                vector.tree_hash_root()
            }
        }
    };
}

macro_rules! bytes_struct {
    ($name: ident, $type: ty, $byte_size: expr, $small_name: expr, $ssz_type_size: ident,
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
        pub struct $name([u8; $byte_size]);
    };
    ($name: ident, $type: ty, $byte_size: expr, $small_name: expr, $ssz_type_size: ident) => {
        bytes_struct!($name, $type, $byte_size, $small_name, $ssz_type_size, stringify!($type),
        stringify!($byte_size));

        impl $name {
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
                Ok(Self(Self::get_bytes(bytes)?))
            }

            pub fn empty() -> Self {
                Self([0; $byte_size])
            }

            pub fn as_bytes(&self) -> Vec<u8> {
                self.0.to_vec()
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
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                self.0[..].fmt(formatter)
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                &self.0[..] == &other.0[..]
            }
        }

        impl Eq for $name {}

        impl std::convert::TryInto<$type> for &$name {
            type Error = ssz::DecodeError;

            fn try_into(self) -> Result<$type, Self::Error> {
                <$type>::from_bytes(&self.0[..])
            }
        }

        impl std::convert::From<$type> for $name {
            fn from(obj: $type) -> Self {
                // We know that obj.as_bytes() always has exactly $byte_size many bytes.
                Self::from_bytes(obj.as_ssz_bytes().as_slice()).unwrap()
            }
        }

        impl_ssz!($name, $byte_size, "$type");

        impl_tree_hash!($name, $ssz_type_size);

        impl serde::ser::Serialize for $name {
            /// Serde serialization is compliant the Ethereum YAML test format.
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                serializer.serialize_str(&hex::encode(ssz::ssz_encode(self)))
            }
        }

        impl<'de> serde::de::Deserialize<'de> for $name {
            /// Serde serialization is compliant the Ethereum YAML test format.
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::de::Deserializer<'de>,
            {
                let bytes = deserializer.deserialize_str(serde_hex::HexVisitor)?;
                let signature = Self::from_ssz_bytes(&bytes[..])
                    .map_err(|e| serde::de::Error::custom(format!("invalid ssz ({:?})", e)))?;
                Ok(signature)
            }
        }
    };
}
