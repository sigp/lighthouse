use bit_reverse::LookupReverse;

/// Provides a common `impl` for structs that wrap a `$name`.
#[macro_export]
macro_rules! impl_bitfield_fns {
    ($name: ident) => {
        impl<N: Unsigned> $name<N> {
            /// Create a new BitList list with `initial_len` bits all set to `false`.
            pub fn with_capacity(initial_len: usize) -> Result<Self, Error> {
                Self::from_elem(initial_len, false)
            }

            /// Create a new bitfield with the given length `initial_len` and all values set to `bit`.
            ///
            /// Note: if `initial_len` is not a multiple of 8, the remaining bits will be set to `false`
            /// regardless of `bit`.
            pub fn from_elem(initial_len: usize, bit: bool) -> Result<Self, Error> {
                // BitVec can panic if we don't set the len to be a multiple of 8.
                let full_len = ((initial_len + 7) / 8) * 8;

                Self::validate_length(full_len)?;

                let mut bitfield = Bitfield::from_elem(full_len, false);

                if bit {
                    for i in 0..initial_len {
                        bitfield.set(i, true);
                    }
                }

                Ok(Self {
                    bitfield,
                    _phantom: PhantomData,
                })
            }

            /// Create a new bitfield using the supplied `bytes` as input
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                Self::validate_length(bytes.len().saturating_mul(8))?;

                Ok(Self {
                    bitfield: Bitfield::from_bytes(&reverse_bit_order(bytes.to_vec())),
                    _phantom: PhantomData,
                })
            }
            /// Returns a vector of bytes representing the bitfield
            pub fn to_bytes(&self) -> Vec<u8> {
                if self.bitfield.is_empty() {
                    vec![0] // Empty bitfield should be represented as a zero byte.
                } else {
                    reverse_bit_order(self.bitfield.to_bytes().to_vec())
                }
            }

            /// Read the value of a bit.
            ///
            /// If the index is in bounds, then result is Ok(value) where value is `true` if the
            /// bit is 1 and `false` if the bit is 0.  If the index is out of bounds, we return an
            /// error to that extent.
            pub fn get(&self, i: usize) -> Result<bool, Error> {
                if i < N::to_usize() {
                    match self.bitfield.get(i) {
                        Some(value) => Ok(value),
                        None => Err(Error::OutOfBounds {
                            i,
                            len: self.bitfield.len(),
                        }),
                    }
                } else {
                    Err(Error::InvalidLength {
                        i,
                        len: N::to_usize(),
                    })
                }
            }

            /// Set the value of a bit.
            ///
            /// If the index is out of bounds, we expand the size of the underlying set to include
            /// the new index.  Returns the previous value if there was one.
            pub fn set(&mut self, i: usize, value: bool) -> Result<(), Error> {
                match self.get(i) {
                    Ok(previous) => Some(previous),
                    Err(Error::OutOfBounds { len, .. }) => {
                        let new_len = i - len + 1;
                        self.bitfield.grow(new_len, false);
                        None
                    }
                    Err(e) => return Err(e),
                };

                self.bitfield.set(i, value);

                Ok(())
            }

            /// Returns the number of bits in this bitfield.
            pub fn len(&self) -> usize {
                self.bitfield.len()
            }

            /// Returns true if `self.len() == 0`
            pub fn is_empty(&self) -> bool {
                self.len() == 0
            }

            /// Returns true if all bits are set to 0.
            pub fn is_zero(&self) -> bool {
                self.bitfield.none()
            }

            /// Returns the number of bytes required to represent this bitfield.
            pub fn num_bytes(&self) -> usize {
                self.to_bytes().len()
            }

            /// Returns the number of `1` bits in the bitfield
            pub fn num_set_bits(&self) -> usize {
                self.bitfield.iter().filter(|&bit| bit).count()
            }
        }

        impl<N: Unsigned> cmp::PartialEq for $name<N> {
            /// Determines equality by comparing the `ssz` encoding of the two candidates.  This
            /// method ensures that the presence of high-order (empty) bits in the highest byte do
            /// not exclude equality when they are in fact representing the same information.
            fn eq(&self, other: &Self) -> bool {
                ssz::ssz_encode(self) == ssz::ssz_encode(other)
            }
        }

        /// Create a new bitfield that is a union of two other bitfields.
        ///
        /// For example `union(0101, 1000) == 1101`
        // TODO: length-independent intersection for BitAnd
        impl<N: Unsigned + Clone> std::ops::BitOr for $name<N> {
            type Output = Self;

            fn bitor(self, other: Self) -> Self {
                let (biggest, smallest) = if self.len() > other.len() {
                    (&self, &other)
                } else {
                    (&other, &self)
                };
                let mut new = (*biggest).clone();
                for i in 0..smallest.len() {
                    if let Ok(true) = smallest.get(i) {
                        new.set(i, true)
                            .expect("Cannot produce bitfield larger than smallest of two given");
                    }
                }
                new
            }
        }

        impl<N: Unsigned> Encode for $name<N> {
            fn is_ssz_fixed_len() -> bool {
                false
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                buf.append(&mut self.to_bytes())
            }
        }

        impl<N: Unsigned> Decode for $name<N> {
            fn is_ssz_fixed_len() -> bool {
                false
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
                $name::from_bytes(bytes)
                    .map_err(|e| ssz::DecodeError::BytesInvalid(format!("Bitfield {:?}", e)))
            }
        }

        impl<N: Unsigned> Serialize for $name<N> {
            /// Serde serialization is compliant with the Ethereum YAML test format.
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&encode(self.to_bytes()))
            }
        }

        impl<'de, N: Unsigned> Deserialize<'de> for $name<N> {
            /// Serde serialization is compliant with the Ethereum YAML test format.
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                // We reverse the bit-order so that the BitVec library can read its 0th
                // bit from the end of the hex string, e.g.
                // "0xef01" => [0xef, 0x01] => [0b1000_0000, 0b1111_1110]
                let bytes = deserializer.deserialize_str(PrefixedHexVisitor)?;
                $name::from_bytes(&bytes)
                    .map_err(|e| serde::de::Error::custom(format!("Bitfield {:?}", e)))
            }
        }

        impl<N: Unsigned> tree_hash::TreeHash for $name<N> {
            fn tree_hash_type() -> tree_hash::TreeHashType {
                tree_hash::TreeHashType::List
            }

            fn tree_hash_packed_encoding(&self) -> Vec<u8> {
                unreachable!("List should never be packed.")
            }

            fn tree_hash_packing_factor() -> usize {
                unreachable!("List should never be packed.")
            }

            fn tree_hash_root(&self) -> Vec<u8> {
                self.to_bytes().tree_hash_root()
            }
        }
    };
}

// Reverse the bit order of a whole byte vec, so that the ith bit
// of the input vec is placed in the (N - i)th bit of the output vec.
// This function is necessary for converting bitfields to and from YAML,
// as the BitVec library and the hex-parser use opposing bit orders.
pub fn reverse_bit_order(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.reverse();
    bytes.into_iter().map(LookupReverse::swap_bits).collect()
}
