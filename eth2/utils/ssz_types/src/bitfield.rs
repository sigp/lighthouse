/// A heap-allocated, ordered, fixed-length, collection of `bool` values.
///
/// The length of the Bitfield is set at instantiation (i.e., runtime, not compile time).
///
/// The internal representation of the bitfield is the same as that required by SSZ - the highest
/// byte (by `Vec` index) stores the lowest bit-indices and the right-most bit stores the lowest
/// bit-index. E.g., `vec![0b0000_0010, 0b0000_0001]` has bits `0, 9` set.
#[derive(Clone, Debug, PartialEq)]
pub struct Bitfield {
    bytes: Vec<u8>,
    len: usize,
}

impl Bitfield {
    pub fn with_capacity(num_bits: usize) -> Self {
        Self {
            bytes: vec![0; Self::bytes_for_bit_len(num_bits)],
            len: num_bits,
        }
    }

    pub fn set(&mut self, i: usize, value: bool) -> Option<()> {
        if i < self.len {
            let byte = {
                let num_bytes = self.bytes.len();
                let offset = i / 8;
                self.bytes
                    .get_mut(num_bytes - offset - 1)
                    .expect("Cannot be OOB if less than self.len")
            };

            if value {
                *byte |= 1 << (i % 8)
            } else {
                *byte &= !(1 << (i % 8))
            }

            Some(())
        } else {
            None
        }
    }

    pub fn get(&self, i: usize) -> Option<bool> {
        if i < self.len {
            let byte = {
                let num_bytes = self.bytes.len();
                let offset = i / 8;
                self.bytes
                    .get(num_bytes - offset - 1)
                    .expect("Cannot be OOB if less than self.len")
            };

            Some(*byte & 1 << (i % 8) > 0)
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn bytes_for_bit_len(bit_len: usize) -> usize {
        (bit_len + 7) / 8
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_bytes(bytes: Vec<u8>, bit_len: usize) -> Option<Self> {
        if bytes.len() == 1 && bit_len == 0 && bytes == &[0] {
            // A bitfield with `bit_len` 0 can only be represented by a single zero byte.
            Some(Self { bytes, len: 0 })
        } else if bytes.len() != Bitfield::bytes_for_bit_len(bit_len) || bytes.is_empty() {
            // The number of bytes must be the minimum required to represent `bit_len`.
            None
        } else {
            // Ensure there are no bits higher than `bit_len` that are set to true.
            let (mask, _) = u8::max_value().overflowing_shr(8 - (bit_len as u32 % 8));

            if (bytes.first().expect("Bytes cannot be empty") & !mask) == 0 {
                Some(Self {
                    bytes,
                    len: bit_len,
                })
            } else {
                None
            }
        }
    }

    pub fn iter(&self) -> BitIter<'_> {
        BitIter {
            bitfield: self,
            i: 0,
        }
    }

    pub fn is_zero(&self) -> bool {
        !self.bytes.iter().any(|byte| (*byte & u8::max_value()) > 0)
    }

    pub fn intersection(&self, other: &Self) -> Option<Self> {
        if self.is_comparable(other) {
            let mut res = self.clone();
            res.intersection_inplace(other);
            Some(res)
        } else {
            None
        }
    }

    pub fn intersection_inplace(&mut self, other: &Self) -> Option<()> {
        if self.is_comparable(other) {
            for i in 0..self.bytes.len() {
                self.bytes[i] = self.bytes[i] & other.bytes[i];
            }
            Some(())
        } else {
            None
        }
    }

    pub fn union(&self, other: &Self) -> Option<Self> {
        if self.is_comparable(other) {
            let mut res = self.clone();
            res.union_inplace(other);
            Some(res)
        } else {
            None
        }
    }

    pub fn union_inplace(&mut self, other: &Self) -> Option<()> {
        if self.is_comparable(other) {
            for i in 0..self.bytes.len() {
                self.bytes[i] = self.bytes[i] | other.bytes[i];
            }
            Some(())
        } else {
            None
        }
    }

    pub fn difference(&self, other: &Self) -> Option<Self> {
        if self.is_comparable(other) {
            let mut res = self.clone();
            res.difference_inplace(other);
            Some(res)
        } else {
            None
        }
    }

    pub fn difference_inplace(&mut self, other: &Self) -> Option<()> {
        if self.is_comparable(other) {
            for i in 0..self.bytes.len() {
                self.bytes[i] = self.bytes[i] & !other.bytes[i];
            }
            Some(())
        } else {
            None
        }
    }

    pub fn is_comparable(&self, other: &Self) -> bool {
        (self.len() == other.len()) && (self.bytes.len() == other.bytes.len())
    }
}

pub struct BitIter<'a> {
    bitfield: &'a Bitfield,
    i: usize,
}

impl<'a> Iterator for BitIter<'a> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        let res = self.bitfield.get(self.i);
        self.i += 1;
        res
    }
}

/// Provides a common `impl` for structs that wrap a `$name`.
#[macro_export]
macro_rules! impl_bitfield_fns {
    ($name: ident) => {
        impl<N: Unsigned> $name<N> {
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

            pub fn set(&mut self, i: usize, value: bool) -> Option<()> {
                self.bitfield.set(i, value)
            }

            /// Returns the number of bits in this bitfield.
            pub fn len(&self) -> usize {
                self.bitfield.len()
            }

            /// Returns true if `self.len() == 0`
            pub fn is_empty(&self) -> bool {
                self.bitfield.is_empty()
            }

            /// Returns true if all bits are set to 0.
            pub fn is_zero(&self) -> bool {
                self.bitfield.is_zero()
            }

            /// Returns the number of bytes presently used to store the bitfield.
            pub fn num_bytes(&self) -> usize {
                self.bitfield.as_slice().len()
            }

            /// Returns the number of `1` bits in the bitfield
            pub fn num_set_bits(&self) -> usize {
                self.bitfield.iter().filter(|&bit| bit).count()
            }
        }

        /*
        impl<N: Unsigned> Encode for $name<N> {
            fn is_ssz_fixed_len() -> bool {
                false
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                buf.append(&mut self.bitfield.to_bytes())
            }
        }

        impl<N: Unsigned> Decode for $name<N> {
            fn is_ssz_fixed_len() -> bool {
                false
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
                let bitfield =
                    Bitfield::from_bytes(bytes.to_vec(), bytes.len() * 8).expect("Cannot fail");
                Ok(Self {
                    bitfield,
                    _phantom: PhantomData,
                })
                /*
                $name::from_bytes(bytes)
                    .map_err(|e| ssz::DecodeError::BytesInvalid(format!("Bitfield {:?}", e)))
                */
            }
        }

        impl<N: Unsigned> Serialize for $name<N> {
            /// Serde serialization is compliant with the Ethereum YAML test format.
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&encode(self.bitfield.to_bytes()))
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
        */
    };
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn from_bytes() {
        assert!(Bitfield::from_bytes(vec![0b0000_0000], 0).is_some());
        assert!(Bitfield::from_bytes(vec![0b0000_0001], 1).is_some());
        assert!(Bitfield::from_bytes(vec![0b0000_0011], 2).is_some());
        assert!(Bitfield::from_bytes(vec![0b0000_0111], 3).is_some());
        assert!(Bitfield::from_bytes(vec![0b0000_1111], 4).is_some());
        assert!(Bitfield::from_bytes(vec![0b0001_1111], 5).is_some());
        assert!(Bitfield::from_bytes(vec![0b0011_1111], 6).is_some());
        assert!(Bitfield::from_bytes(vec![0b0111_1111], 7).is_some());
        assert!(Bitfield::from_bytes(vec![0b1111_1111], 8).is_some());

        assert!(Bitfield::from_bytes(vec![0b0000_0001, 0b1111_1111], 9).is_some());
        assert!(Bitfield::from_bytes(vec![0b0000_0011, 0b1111_1111], 10).is_some());
        assert!(Bitfield::from_bytes(vec![0b0000_0111, 0b1111_1111], 11).is_some());
        assert!(Bitfield::from_bytes(vec![0b0000_1111, 0b1111_1111], 12).is_some());
        assert!(Bitfield::from_bytes(vec![0b0001_1111, 0b1111_1111], 13).is_some());
        assert!(Bitfield::from_bytes(vec![0b0011_1111, 0b1111_1111], 14).is_some());
        assert!(Bitfield::from_bytes(vec![0b0111_1111, 0b1111_1111], 15).is_some());
        assert!(Bitfield::from_bytes(vec![0b1111_1111, 0b1111_1111], 16).is_some());

        for i in 0..8 {
            assert!(Bitfield::from_bytes(vec![], i).is_none());
            assert!(Bitfield::from_bytes(vec![0b1111_1111], i).is_none());
            assert!(Bitfield::from_bytes(vec![0b1111_1110, 0b0000_0000], i).is_none());
        }

        assert!(Bitfield::from_bytes(vec![0b0000_0001], 0).is_none());

        assert!(Bitfield::from_bytes(vec![0b0000_0001], 0).is_none());
        assert!(Bitfield::from_bytes(vec![0b0000_0011], 1).is_none());
        assert!(Bitfield::from_bytes(vec![0b0000_0111], 2).is_none());
        assert!(Bitfield::from_bytes(vec![0b0000_1111], 3).is_none());
        assert!(Bitfield::from_bytes(vec![0b0001_1111], 4).is_none());
        assert!(Bitfield::from_bytes(vec![0b0011_1111], 5).is_none());
        assert!(Bitfield::from_bytes(vec![0b0111_1111], 6).is_none());
        assert!(Bitfield::from_bytes(vec![0b1111_1111], 7).is_none());

        assert!(Bitfield::from_bytes(vec![0b0000_0001, 0b1111_1111], 8).is_none());
        assert!(Bitfield::from_bytes(vec![0b0000_0011, 0b1111_1111], 9).is_none());
        assert!(Bitfield::from_bytes(vec![0b0000_0111, 0b1111_1111], 10).is_none());
        assert!(Bitfield::from_bytes(vec![0b0000_1111, 0b1111_1111], 11).is_none());
        assert!(Bitfield::from_bytes(vec![0b0001_1111, 0b1111_1111], 12).is_none());
        assert!(Bitfield::from_bytes(vec![0b0011_1111, 0b1111_1111], 13).is_none());
        assert!(Bitfield::from_bytes(vec![0b0111_1111, 0b1111_1111], 14).is_none());
        assert!(Bitfield::from_bytes(vec![0b1111_1111, 0b1111_1111], 15).is_none());
    }

    fn test_set_unset(num_bits: usize) {
        let mut bitfield = Bitfield::with_capacity(num_bits);

        for i in 0..num_bits + 1 {
            dbg!(i);
            if i < num_bits {
                // Starts as false
                assert_eq!(bitfield.get(i), Some(false));
                // Can be set true.
                assert!(bitfield.set(i, true).is_some());
                assert_eq!(bitfield.get(i), Some(true));
                // Can be set false
                assert!(bitfield.set(i, false).is_some());
                assert_eq!(bitfield.get(i), Some(false));
            } else {
                assert_eq!(bitfield.get(i), None);
                assert!(bitfield.set(i, true).is_none());
                assert_eq!(bitfield.get(i), None);
            }
        }
    }

    fn test_bytes_round_trip(num_bits: usize) {
        dbg!(num_bits);
        for i in 0..num_bits {
            dbg!(i);
            let mut bitfield = Bitfield::with_capacity(num_bits);
            bitfield.set(i, true).unwrap();

            let bytes = bitfield.clone().to_bytes();
            dbg!(&bytes);
            assert_eq!(bitfield, Bitfield::from_bytes(bytes, num_bits).unwrap());
        }
    }

    #[test]
    fn set_unset() {
        for i in 0..8 * 5 {
            test_set_unset(i)
        }
    }

    #[test]
    fn bytes_round_trip() {
        for i in 0..8 * 5 {
            test_bytes_round_trip(i)
        }
    }

    #[test]
    fn to_bytes() {
        let mut bitfield = Bitfield::with_capacity(9);
        bitfield.set(0, true);
        assert_eq!(bitfield.clone().to_bytes(), vec![0b0000_0000, 0b0000_0001]);
        bitfield.set(1, true);
        assert_eq!(bitfield.clone().to_bytes(), vec![0b0000_0000, 0b0000_0011]);
        bitfield.set(2, true);
        assert_eq!(bitfield.clone().to_bytes(), vec![0b0000_0000, 0b0000_0111]);
        bitfield.set(3, true);
        assert_eq!(bitfield.clone().to_bytes(), vec![0b0000_0000, 0b0000_1111]);
        bitfield.set(4, true);
        assert_eq!(bitfield.clone().to_bytes(), vec![0b0000_0000, 0b0001_1111]);
        bitfield.set(5, true);
        assert_eq!(bitfield.clone().to_bytes(), vec![0b0000_0000, 0b0011_1111]);
        bitfield.set(6, true);
        assert_eq!(bitfield.clone().to_bytes(), vec![0b0000_0000, 0b0111_1111]);
        bitfield.set(7, true);
        assert_eq!(bitfield.clone().to_bytes(), vec![0b0000_0000, 0b1111_1111]);
        bitfield.set(8, true);
        assert_eq!(bitfield.clone().to_bytes(), vec![0b0000_0001, 0b1111_1111]);
    }

    #[test]
    fn intersection() {
        let a = Bitfield::from_bytes(vec![0b1100, 0b0001], 16).unwrap();
        let b = Bitfield::from_bytes(vec![0b1011, 0b1001], 16).unwrap();
        let c = Bitfield::from_bytes(vec![0b1000, 0b0001], 16).unwrap();

        assert_eq!(a.intersection(&b).unwrap(), c);
        assert_eq!(b.intersection(&a).unwrap(), c);
        assert_eq!(a.intersection(&c).unwrap(), c);
        assert_eq!(b.intersection(&c).unwrap(), c);
        assert_eq!(a.intersection(&a).unwrap(), a);
        assert_eq!(b.intersection(&b).unwrap(), b);
        assert_eq!(c.intersection(&c).unwrap(), c);
    }

    #[test]
    fn union() {
        let a = Bitfield::from_bytes(vec![0b1100, 0b0001], 16).unwrap();
        let b = Bitfield::from_bytes(vec![0b1011, 0b1001], 16).unwrap();
        let c = Bitfield::from_bytes(vec![0b1111, 0b1001], 16).unwrap();

        assert_eq!(a.union(&b).unwrap(), c);
        assert_eq!(b.union(&a).unwrap(), c);
        assert_eq!(a.union(&a).unwrap(), a);
        assert_eq!(b.union(&b).unwrap(), b);
        assert_eq!(c.union(&c).unwrap(), c);
    }

    #[test]
    fn difference() {
        let a = Bitfield::from_bytes(vec![0b1100, 0b0001], 16).unwrap();
        let b = Bitfield::from_bytes(vec![0b1011, 0b1001], 16).unwrap();
        let a_b = Bitfield::from_bytes(vec![0b0100, 0b0000], 16).unwrap();
        let b_a = Bitfield::from_bytes(vec![0b0011, 0b1000], 16).unwrap();

        assert_eq!(a.difference(&b).unwrap(), a_b);
        assert_eq!(b.difference(&a).unwrap(), b_a);
        assert!(a.difference(&a).unwrap().is_zero());
    }

    #[test]
    fn iter() {
        let mut bitfield = Bitfield::with_capacity(9);
        bitfield.set(2, true);
        bitfield.set(8, true);

        assert_eq!(
            bitfield.iter().collect::<Vec<bool>>(),
            vec![false, false, true, false, false, false, false, false, true]
        );
    }
}
