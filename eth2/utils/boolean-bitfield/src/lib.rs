extern crate bit_vec;
extern crate ssz;

use bit_reverse::LookupReverse;
use bit_vec::BitVec;
use cached_tree_hash::cached_tree_hash_bytes_as_list;
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
    ///
    /// Note: if `initial_len` is not a multiple of 8, the remaining bits will be set to `false`
    /// regardless of `bit`.
    pub fn from_elem(initial_len: usize, bit: bool) -> Self {
        // BitVec can panic if we don't set the len to be a multiple of 8.
        let full_len = ((initial_len + 7) / 8) * 8;
        let mut bitfield = BitVec::from_elem(full_len, false);

        if bit {
            for i in 0..initial_len {
                bitfield.set(i, true);
            }
        }

        Self { 0: bitfield }
    }

    /// Create a new bitfield using the supplied `bytes` as input
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            0: BitVec::from_bytes(&reverse_bit_order(bytes.to_vec())),
        }
    }

    /// Returns a vector of bytes representing the bitfield
    pub fn to_bytes(&self) -> Vec<u8> {
        reverse_bit_order(self.0.to_bytes().to_vec())
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

    /// Returns the number of bits in this bitfield.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if `self.len() == 0`
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns true if all bits are set to 0.
    pub fn is_zero(&self) -> bool {
        self.0.none()
    }

    /// Returns the number of bytes required to represent this bitfield.
    pub fn num_bytes(&self) -> usize {
        self.to_bytes().len()
    }

    /// Returns the number of `1` bits in the bitfield
    pub fn num_set_bits(&self) -> usize {
        self.0.iter().filter(|&bit| bit).count()
    }

    /// Compute the intersection (binary-and) of this bitfield with another. Lengths must match.
    pub fn intersection(&self, other: &Self) -> Self {
        let mut res = self.clone();
        res.intersection_inplace(other);
        res
    }

    /// Like `intersection` but in-place (updates `self`).
    pub fn intersection_inplace(&mut self, other: &Self) {
        self.0.intersect(&other.0);
    }

    /// Compute the union (binary-or) of this bitfield with another. Lengths must match.
    pub fn union(&self, other: &Self) -> Self {
        let mut res = self.clone();
        res.union_inplace(other);
        res
    }

    /// Like `union` but in-place (updates `self`).
    pub fn union_inplace(&mut self, other: &Self) {
        self.0.union(&other.0);
    }

    /// Compute the difference (binary-minus) of this bitfield with another. Lengths must match.
    ///
    /// Computes `self - other`.
    pub fn difference(&self, other: &Self) -> Self {
        let mut res = self.clone();
        res.difference_inplace(other);
        res
    }

    /// Like `difference` but in-place (updates `self`).
    pub fn difference_inplace(&mut self, other: &Self) {
        self.0.difference(&other.0);
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
// TODO: length-independent intersection for BitAnd
impl std::ops::BitOr for BooleanBitfield {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
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
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut self.to_bytes())
    }
}

impl Decodable for BooleanBitfield {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(BooleanBitfield::from_bytes(bytes))
    }
}

// Reverse the bit order of a whole byte vec, so that the ith bit
// of the input vec is placed in the (N - i)th bit of the output vec.
// This function is necessary for converting bitfields to and from YAML,
// as the BitVec library and the hex-parser use opposing bit orders.
fn reverse_bit_order(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.reverse();
    bytes.into_iter().map(|b| b.swap_bits()).collect()
}

impl Serialize for BooleanBitfield {
    /// Serde serialization is compliant with the Ethereum YAML test format.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode(self.to_bytes()))
    }
}

impl<'de> Deserialize<'de> for BooleanBitfield {
    /// Serde serialization is compliant with the Ethereum YAML test format.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // We reverse the bit-order so that the BitVec library can read its 0th
        // bit from the end of the hex string, e.g.
        // "0xef01" => [0xef, 0x01] => [0b1000_0000, 0b1111_1110]
        let bytes = deserializer.deserialize_str(PrefixedHexVisitor)?;
        Ok(BooleanBitfield::from_bytes(&bytes))
    }
}

impl tree_hash::TreeHash for BooleanBitfield {
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

cached_tree_hash_bytes_as_list!(BooleanBitfield);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_yaml;
    use ssz::ssz_encode;
    use tree_hash::TreeHash;

    #[test]
    pub fn test_cached_tree_hash() {
        let original = BooleanBitfield::from_bytes(&vec![18; 12][..]);

        let mut cache = cached_tree_hash::TreeHashCache::new(&original).unwrap();

        assert_eq!(
            cache.tree_hash_root().unwrap().to_vec(),
            original.tree_hash_root()
        );

        let modified = BooleanBitfield::from_bytes(&vec![2; 1][..]);

        cache.update(&modified).unwrap();

        assert_eq!(
            cache.tree_hash_root().unwrap().to_vec(),
            modified.tree_hash_root()
        );
    }

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

    const INPUT: &[u8] = &[0b0100_0000, 0b0100_0000];

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
        assert_eq!(field.as_ssz_bytes(), vec![0b0000_0011, 0b1000_0111]);

        let field = BooleanBitfield::from_elem(18, true);
        assert_eq!(
            field.as_ssz_bytes(),
            vec![0b0000_0011, 0b1111_1111, 0b1111_1111]
        );

        let mut b = BooleanBitfield::new();
        b.set(1, true);
        assert_eq!(ssz_encode(&b), vec![0b0000_0010]);
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
        let encoded = vec![0b0000_0011, 0b1000_0111];
        let field = BooleanBitfield::from_ssz_bytes(&encoded).unwrap();
        let expected = create_test_bitfield();
        assert_eq!(field, expected);

        let encoded = vec![255, 255, 3];
        let field = BooleanBitfield::from_ssz_bytes(&encoded).unwrap();
        let expected = BooleanBitfield::from_bytes(&[255, 255, 3]);
        assert_eq!(field, expected);
    }

    #[test]
    fn test_serialize_deserialize() {
        use serde_yaml::Value;

        let data: &[(_, &[_])] = &[
            ("0x01", &[0b00000001]),
            ("0xf301", &[0b11110011, 0b00000001]),
        ];
        for (hex_data, bytes) in data {
            let bitfield = BooleanBitfield::from_bytes(bytes);
            assert_eq!(
                serde_yaml::from_str::<BooleanBitfield>(hex_data).unwrap(),
                bitfield
            );
            assert_eq!(
                serde_yaml::to_value(&bitfield).unwrap(),
                Value::String(hex_data.to_string())
            );
        }
    }

    #[test]
    fn test_ssz_round_trip() {
        let original = BooleanBitfield::from_bytes(&vec![18; 12][..]);
        let ssz = ssz_encode(&original);
        let decoded = BooleanBitfield::from_ssz_bytes(&ssz).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_bitor() {
        let a = BooleanBitfield::from_bytes(&vec![2, 8, 1][..]);
        let b = BooleanBitfield::from_bytes(&vec![4, 8, 16][..]);
        let c = BooleanBitfield::from_bytes(&vec![6, 8, 17][..]);
        assert_eq!(c, a | b);
    }

    #[test]
    fn test_is_zero() {
        let yes_data: &[&[u8]] = &[&[], &[0], &[0, 0], &[0, 0, 0]];
        for bytes in yes_data {
            assert!(BooleanBitfield::from_bytes(bytes).is_zero());
        }
        let no_data: &[&[u8]] = &[&[1], &[6], &[0, 1], &[0, 0, 1], &[0, 0, 255]];
        for bytes in no_data {
            assert!(!BooleanBitfield::from_bytes(bytes).is_zero());
        }
    }

    #[test]
    fn test_intersection() {
        let a = BooleanBitfield::from_bytes(&[0b1100, 0b0001]);
        let b = BooleanBitfield::from_bytes(&[0b1011, 0b1001]);
        let c = BooleanBitfield::from_bytes(&[0b1000, 0b0001]);
        assert_eq!(a.intersection(&b), c);
        assert_eq!(b.intersection(&a), c);
        assert_eq!(a.intersection(&c), c);
        assert_eq!(b.intersection(&c), c);
        assert_eq!(a.intersection(&a), a);
        assert_eq!(b.intersection(&b), b);
        assert_eq!(c.intersection(&c), c);
    }

    #[test]
    fn test_union() {
        let a = BooleanBitfield::from_bytes(&[0b1100, 0b0001]);
        let b = BooleanBitfield::from_bytes(&[0b1011, 0b1001]);
        let c = BooleanBitfield::from_bytes(&[0b1111, 0b1001]);
        assert_eq!(a.union(&b), c);
        assert_eq!(b.union(&a), c);
        assert_eq!(a.union(&a), a);
        assert_eq!(b.union(&b), b);
        assert_eq!(c.union(&c), c);
    }

    #[test]
    fn test_difference() {
        let a = BooleanBitfield::from_bytes(&[0b1100, 0b0001]);
        let b = BooleanBitfield::from_bytes(&[0b1011, 0b1001]);
        let a_b = BooleanBitfield::from_bytes(&[0b0100, 0b0000]);
        let b_a = BooleanBitfield::from_bytes(&[0b0011, 0b1000]);
        assert_eq!(a.difference(&b), a_b);
        assert_eq!(b.difference(&a), b_a);
        assert!(a.difference(&a).is_zero());
    }
}
