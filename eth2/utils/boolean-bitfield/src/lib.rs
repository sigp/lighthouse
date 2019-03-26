extern crate bit_vec;
extern crate ssz;

use bit_vec::BitVec;

use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode, PrefixedHexVisitor};
use ssz::{Decodable, Encodable};
use std::cmp;
use std::default;

/// A BooleanBitfield represents a set of booleans compactly stored as a vector of bits.
/// The BooleanBitfield is given a fixed size during construction. Reads outside of the current size return an out-of-bounds error. Writes outside of the current size expand the size of the set.
#[derive(Debug, Clone)]
pub struct BooleanBitfield(BitVec);

/// Error represents some reason a request against a bitfield was not satisfied
#[derive(Debug, PartialEq)]
pub enum Error {
    /// OutOfBounds refers to indexing into a bitfield where no bits exist; returns the illegal index and the current size of the bitfield, respectively
    OutOfBounds(usize, usize),
}

impl BooleanBitfield {
    /// Create a new bitfield.
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_capacity(initial_len: usize) -> Self {
        Self::from_elem(initial_len, false)
    }

    /// Create a new bitfield with the given length `initial_len` and all values set to `bit`.
    pub fn from_elem(inital_len: usize, bit: bool) -> Self {
        Self {
            0: BitVec::from_elem(inital_len, bit),
        }
    }

    /// Create a new bitfield using the supplied `bytes` as input
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            0: BitVec::from_bytes(bytes),
        }
    }

    /// Read the value of a bit.
    ///
    /// If the index is in bounds, then result is Ok(value) where value is `true` if the bit is 1 and `false` if the bit is 0.
    /// If the index is out of bounds, we return an error to that extent.
    pub fn get(&self, i: usize) -> Result<bool, Error> {
        match self.0.get(i) {
            Some(value) => Ok(value),
            None => Err(Error::OutOfBounds(i, self.0.len())),
        }
    }

    /// Set the value of a bit.
    ///
    /// If the index is out of bounds, we expand the size of the underlying set to include the new index.
    /// Returns the previous value if there was one.
    pub fn set(&mut self, i: usize, value: bool) -> Option<bool> {
        let previous = match self.get(i) {
            Ok(previous) => Some(previous),
            Err(Error::OutOfBounds(_, len)) => {
                let new_len = i - len + 1;
                self.0.grow(new_len, false);
                None
            }
        };
        self.0.set(i, value);
        previous
    }

    /// Returns the index of the highest set bit. Some(n) if some bit is set, None otherwise.
    pub fn highest_set_bit(&self) -> Option<usize> {
        self.0.iter().rposition(|bit| bit)
    }

    /// Returns the number of bits in this bitfield.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if `self.len() == 0`
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of bytes required to represent this bitfield.
    pub fn num_bytes(&self) -> usize {
        self.to_bytes().len()
    }

    /// Returns the number of `1` bits in the bitfield
    pub fn num_set_bits(&self) -> usize {
        self.0.iter().filter(|&bit| bit).count()
    }

    /// Returns a vector of bytes representing the bitfield
    /// Note that this returns the bit layout of the underlying implementation in the `bit-vec` crate.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl default::Default for BooleanBitfield {
    /// default provides the "empty" bitfield
    /// Note: the empty bitfield is set to the `0` byte.
    fn default() -> Self {
        Self::from_elem(8, false)
    }
}

impl cmp::PartialEq for BooleanBitfield {
    /// Determines equality by comparing the `ssz` encoding of the two candidates.
    /// This method ensures that the presence of high-order (empty) bits in the highest byte do not exclude equality when they are in fact representing the same information.
    fn eq(&self, other: &Self) -> bool {
        ssz::ssz_encode(self) == ssz::ssz_encode(other)
    }
}

/// Create a new bitfield that is a union of two other bitfields.
///
/// For example `union(0101, 1000) == 1101`
impl std::ops::BitAnd for BooleanBitfield {
    type Output = Self;

    fn bitand(self, other: Self) -> Self {
        let (biggest, smallest) = if self.len() > other.len() {
            (&self, &other)
        } else {
            (&other, &self)
        };
        let mut new = biggest.clone();
        for i in 0..smallest.len() {
            if let Ok(true) = smallest.get(i) {
                new.set(i, true);
            }
        }
        new
    }
}

impl Encodable for BooleanBitfield {
    // ssz_append encodes Self according to the `ssz` spec.
    fn ssz_append(&self, s: &mut ssz::SszStream) {
        s.append_vec(&self.to_bytes())
    }
}

impl Decodable for BooleanBitfield {
    fn ssz_decode(bytes: &[u8], index: usize) -> Result<(Self, usize), ssz::DecodeError> {
        let len = ssz::decode::decode_length(bytes, index, ssz::LENGTH_BYTES)?;
        if (ssz::LENGTH_BYTES + len) > bytes.len() {
            return Err(ssz::DecodeError::TooShort);
        }

        if len == 0 {
            Ok((BooleanBitfield::new(), index + ssz::LENGTH_BYTES))
        } else {
            let bytes = &bytes[(index + 4)..(index + len + 4)];

            let count = len * 8;
            let mut field = BooleanBitfield::with_capacity(count);
            for (byte_index, byte) in bytes.iter().enumerate() {
                for i in 0..8 {
                    let bit = byte & (128 >> i);
                    if bit != 0 {
                        field.set(8 * byte_index + i, true);
                    }
                }
            }

            let index = index + ssz::LENGTH_BYTES + len;
            Ok((field, index))
        }
    }
}

impl Serialize for BooleanBitfield {
    /// Serde serialization is compliant the Ethereum YAML test format.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode(&ssz::ssz_encode(self)))
    }
}

impl<'de> Deserialize<'de> for BooleanBitfield {
    /// Serde serialization is compliant the Ethereum YAML test format.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_str(PrefixedHexVisitor)?;
        let (bitfield, _) = <_>::ssz_decode(&bytes[..], 0)
            .map_err(|e| serde::de::Error::custom(format!("invalid ssz ({:?})", e)))?;
        Ok(bitfield)
    }
}

impl ssz::TreeHash for BooleanBitfield {
    fn hash_tree_root(&self) -> Vec<u8> {
        self.to_bytes().hash_tree_root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::{decode, ssz_encode, SszStream};

    #[test]
    fn test_new_bitfield() {
        let mut field = BooleanBitfield::new();
        let original_len = field.len();

        for i in 0..100 {
            if i < original_len {
                assert!(!field.get(i).unwrap());
            } else {
                assert!(field.get(i).is_err());
            }
            let previous = field.set(i, true);
            if i < original_len {
                assert!(!previous.unwrap());
            } else {
                assert!(previous.is_none());
            }
        }
    }

    #[test]
    fn test_empty_bitfield() {
        let mut field = BooleanBitfield::from_elem(0, false);
        let original_len = field.len();

        assert_eq!(original_len, 0);

        for i in 0..100 {
            if i < original_len {
                assert!(!field.get(i).unwrap());
            } else {
                assert!(field.get(i).is_err());
            }
            let previous = field.set(i, true);
            if i < original_len {
                assert!(!previous.unwrap());
            } else {
                assert!(previous.is_none());
            }
        }

        assert_eq!(field.len(), 100);
        assert_eq!(field.num_set_bits(), 100);
    }

    const INPUT: &[u8] = &[0b0000_0010, 0b0000_0010];

    #[test]
    fn test_get_from_bitfield() {
        let field = BooleanBitfield::from_bytes(INPUT);
        let unset = field.get(0).unwrap();
        assert!(!unset);
        let set = field.get(6).unwrap();
        assert!(set);
        let set = field.get(14).unwrap();
        assert!(set);
    }

    #[test]
    fn test_set_for_bitfield() {
        let mut field = BooleanBitfield::from_bytes(INPUT);
        let previous = field.set(10, true).unwrap();
        assert!(!previous);
        let previous = field.get(10).unwrap();
        assert!(previous);
        let previous = field.set(6, false).unwrap();
        assert!(previous);
        let previous = field.get(6).unwrap();
        assert!(!previous);
    }

    #[test]
    fn test_highest_set_bit() {
        let field = BooleanBitfield::from_bytes(INPUT);
        assert_eq!(field.highest_set_bit().unwrap(), 14);

        let field = BooleanBitfield::from_bytes(&[0b0000_0011]);
        assert_eq!(field.highest_set_bit().unwrap(), 7);

        let field = BooleanBitfield::new();
        assert_eq!(field.highest_set_bit(), None);
    }

    #[test]
    fn test_len() {
        let field = BooleanBitfield::from_bytes(INPUT);
        assert_eq!(field.len(), 16);

        let field = BooleanBitfield::new();
        assert_eq!(field.len(), 8);
    }

    #[test]
    fn test_num_set_bits() {
        let field = BooleanBitfield::from_bytes(INPUT);
        assert_eq!(field.num_set_bits(), 2);

        let field = BooleanBitfield::new();
        assert_eq!(field.num_set_bits(), 0);
    }

    #[test]
    fn test_to_bytes() {
        let field = BooleanBitfield::from_bytes(INPUT);
        assert_eq!(field.to_bytes(), INPUT);

        let field = BooleanBitfield::new();
        assert_eq!(field.to_bytes(), vec![0]);
    }

    #[test]
    fn test_out_of_bounds() {
        let mut field = BooleanBitfield::from_bytes(INPUT);

        let out_of_bounds_index = field.len();
        assert!(field.set(out_of_bounds_index, true).is_none());
        assert!(field.len() == out_of_bounds_index + 1);
        assert!(field.get(out_of_bounds_index).unwrap());

        for i in 0..100 {
            if i <= out_of_bounds_index {
                assert!(field.set(i, true).is_some());
            } else {
                assert!(field.set(i, true).is_none());
            }
        }
    }

    #[test]
    fn test_grows_with_false() {
        let input_all_set: &[u8] = &[0b1111_1111, 0b1111_1111];
        let mut field = BooleanBitfield::from_bytes(input_all_set);

        // Define `a` and `b`, where both are out of bounds and `b` is greater than `a`.
        let a = field.len();
        let b = a + 1;

        // Ensure `a` is out-of-bounds for test integrity.
        assert!(field.get(a).is_err());

        // Set `b` to `true`. Also, for test integrity, ensure it was previously out-of-bounds.
        assert!(field.set(b, true).is_none());

        // Ensure that `a` wasn't also set to `true` during the grow.
        assert_eq!(field.get(a), Ok(false));
        assert_eq!(field.get(b), Ok(true));
    }

    #[test]
    fn test_num_bytes() {
        let field = BooleanBitfield::from_bytes(INPUT);
        assert_eq!(field.num_bytes(), 2);

        let field = BooleanBitfield::from_elem(2, true);
        assert_eq!(field.num_bytes(), 1);

        let field = BooleanBitfield::from_elem(13, true);
        assert_eq!(field.num_bytes(), 2);
    }

    #[test]
    fn test_ssz_encode() {
        let field = create_test_bitfield();

        let mut stream = SszStream::new();
        stream.append(&field);
        assert_eq!(stream.drain(), vec![2, 0, 0, 0, 225, 192]);

        let field = BooleanBitfield::from_elem(18, true);
        let mut stream = SszStream::new();
        stream.append(&field);
        assert_eq!(stream.drain(), vec![3, 0, 0, 0, 255, 255, 192]);
    }

    fn create_test_bitfield() -> BooleanBitfield {
        let count = 2 * 8;
        let mut field = BooleanBitfield::with_capacity(count);

        let indices = &[0, 1, 2, 7, 8, 9];
        for &i in indices {
            field.set(i, true);
        }
        field
    }

    #[test]
    fn test_ssz_decode() {
        let encoded = vec![2, 0, 0, 0, 225, 192];
        let field = decode::<BooleanBitfield>(&encoded).unwrap();
        let expected = create_test_bitfield();
        assert_eq!(field, expected);

        let encoded = vec![3, 0, 0, 0, 255, 255, 3];
        let field = decode::<BooleanBitfield>(&encoded).unwrap();
        let expected = BooleanBitfield::from_bytes(&[255, 255, 3]);
        assert_eq!(field, expected);
    }

    #[test]
    fn test_ssz_round_trip() {
        let original = BooleanBitfield::from_bytes(&vec![18; 12][..]);
        let ssz = ssz_encode(&original);
        let decoded = decode::<BooleanBitfield>(&ssz).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_bitand() {
        let a = BooleanBitfield::from_bytes(&vec![2, 8, 1][..]);
        let b = BooleanBitfield::from_bytes(&vec![4, 8, 16][..]);
        let c = BooleanBitfield::from_bytes(&vec![6, 8, 17][..]);
        assert_eq!(c, a & b);
    }
}
