use core::marker::PhantomData;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode as hex_encode, PrefixedHexVisitor};
use ssz::{Decode, Encode};
use typenum::Unsigned;

pub trait BitfieldBehaviour: Clone {}

/// A marker struct used to define SSZ `BitList` functionality on a `Bitfield`.
#[derive(Clone, PartialEq, Debug)]
pub struct BitList<N> {
    _phantom: PhantomData<N>,
}

/// A marker struct used to define SSZ `BitVector` functionality on a `Bitfield`.
#[derive(Clone, PartialEq, Debug)]
pub struct BitVector<N> {
    _phantom: PhantomData<N>,
}

impl<N: Unsigned + Clone> BitfieldBehaviour for BitList<N> {}
impl<N: Unsigned + Clone> BitfieldBehaviour for BitVector<N> {}

/// A heap-allocated, ordered, fixed-length, collection of `bool` values. Must be used with the `BitList` or
/// `BitVector` marker structs.
///
/// The length of the Bitfield is set at instantiation (i.e., runtime, not compile time). However,
/// use with a `BitList` sets a type-level (i.e., compile-time) maximum length and `BitVector`
/// provides a type-level fixed length.
///
/// ## Example
/// ```
/// use ssz_types::{Bitfield, BitVector, BitList, typenum};
///
/// // `BitList` has a type-level maximum length. The length of the list is specified at runtime
/// // and it must be less than or equal to `N`. After instantiation, `BitList` cannot grow or
/// // shrink.
/// type BitList8 = Bitfield<BitList<typenum::U8>>;
///
/// // Creating a `BitList` with a larger-than-`N` capacity returns `None`.
/// assert!(BitList8::with_capacity(9).is_none());
///
/// let mut bitlist = BitList8::with_capacity(4).unwrap();  // `BitList` permits a capacity of less than the maximum.
/// assert!(bitlist.set(3, true).is_some());  // Setting inside the instantiation capacity is permitted.
/// assert!(bitlist.set(5, true).is_none());  // Setting outside that capacity is not.
///
/// // `BitVector` has a type-level fixed length. Unlike `BitList`, it cannot be instantiated with a custom length
/// // or grow/shrink.
/// type BitVector8 = Bitfield<BitVector<typenum::U8>>;
///
/// let mut bitvector = BitVector8::new();
/// assert_eq!(bitvector.len(), 8); // `BitVector` length is fixed at the type-level.
/// assert!(bitvector.set(7, true).is_some());  // Setting inside the capacity is permitted.
/// assert!(bitvector.set(9, true).is_none());  // Setting outside the capacity is not.
///
/// ```
///
/// ## Note
///
/// The internal representation of the bitfield is the same as that required by SSZ. The highest
/// byte (by `Vec` index) stores the lowest bit-indices and the right-most bit stores the lowest
/// bit-index. E.g., `vec![0b0000_0010, 0b0000_0001]` has bits `0, 9` set.
#[derive(Clone, Debug, PartialEq)]
pub struct Bitfield<T> {
    bytes: Vec<u8>,
    len: usize,
    _phantom: PhantomData<T>,
}

impl<N: Unsigned + Clone> Bitfield<BitList<N>> {
    pub fn with_capacity(num_bits: usize) -> Option<Self> {
        if num_bits <= N::to_usize() {
            Some(Self {
                bytes: vec![0; bytes_for_bit_len(num_bits)],
                len: num_bits,
                _phantom: PhantomData,
            })
        } else {
            None
        }
    }

    pub fn capacity() -> usize {
        N::to_usize()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let len = self.len();
        let mut bytes = self.as_slice().to_vec();

        if bytes_for_bit_len(len + 1) == bytes.len() + 1 {
            bytes.insert(0, 0);
        }

        let mut bitfield: Bitfield<BitList<N>> = Bitfield::from_raw_bytes(bytes, len + 1)
            .expect("Bitfield capacity has been confirmed earlier.");
        bitfield
            .set(len, true)
            .expect("Bitfield capacity has been confirmed earlier.");

        bitfield.bytes
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        let mut initial_bitfield: Bitfield<BitList<N>> = {
            let num_bits = bytes.len() * 8;
            Bitfield::from_raw_bytes(bytes, num_bits)
                .expect("Must have adequate bytes for bit count.")
        };

        let len = initial_bitfield.highest_set_bit()?;
        initial_bitfield
            .set(len, false)
            .expect("Bit has been confirmed to exist");

        let mut bytes = initial_bitfield.to_raw_bytes();

        if bytes_for_bit_len(len) < bytes.len() {
            bytes.remove(0);
        }

        Self::from_raw_bytes(bytes, len)
    }
}

impl<N: Unsigned + Clone> Bitfield<BitVector<N>> {
    pub fn new() -> Self {
        let num_bits = N::to_usize();

        Self {
            bytes: vec![0; num_bits],
            len: num_bits,
            _phantom: PhantomData,
        }
    }

    pub fn capacity() -> usize {
        N::to_usize()
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.to_raw_bytes()
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        Self::from_raw_bytes(bytes, Self::capacity())
    }
}

impl<T: BitfieldBehaviour> Bitfield<T> {
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

    pub fn to_raw_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_raw_bytes(bytes: Vec<u8>, bit_len: usize) -> Option<Self> {
        if bytes.len() == 1 && bit_len == 0 && bytes == &[0] {
            // A bitfield with `bit_len` 0 can only be represented by a single zero byte.
            Some(Self {
                bytes,
                len: 0,
                _phantom: PhantomData,
            })
        } else if bytes.len() != bytes_for_bit_len(bit_len) || bytes.is_empty() {
            // The number of bytes must be the minimum required to represent `bit_len`.
            None
        } else {
            // Ensure there are no bits higher than `bit_len` that are set to true.
            let (mask, _) = u8::max_value().overflowing_shr(8 - (bit_len as u32 % 8));

            if (bytes.first().expect("Bytes cannot be empty") & !mask) == 0 {
                Some(Self {
                    bytes,
                    len: bit_len,
                    _phantom: PhantomData,
                })
            } else {
                None
            }
        }
    }

    pub fn highest_set_bit(&self) -> Option<usize> {
        let byte_i = self.bytes.iter().position(|byte| *byte > 0)?;
        let bit_i = 7 - self.bytes[byte_i].leading_zeros() as usize;

        Some((self.bytes.len().saturating_sub(1) - byte_i) * 8 + bit_i)
    }

    pub fn iter(&self) -> BitIter<'_, T> {
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

fn bytes_for_bit_len(bit_len: usize) -> usize {
    (bit_len + 7) / 8
}

pub struct BitIter<'a, T> {
    bitfield: &'a Bitfield<T>,
    i: usize,
}

impl<'a, T: BitfieldBehaviour> Iterator for BitIter<'a, T> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        let res = self.bitfield.get(self.i);
        self.i += 1;
        res
    }
}

impl<N: Unsigned + Clone> Encode for Bitfield<BitList<N>> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut self.clone().to_bytes())
    }
}

impl<N: Unsigned + Clone> Decode for Bitfield<BitList<N>> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Self::from_bytes(bytes.to_vec())
            .ok_or_else(|| ssz::DecodeError::BytesInvalid("BitList failed to decode".to_string()))
    }
}

impl<N: Unsigned + Clone> Encode for Bitfield<BitVector<N>> {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        bytes_for_bit_len(N::to_usize())
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut self.clone().to_bytes())
    }
}

impl<N: Unsigned + Clone> Decode for Bitfield<BitVector<N>> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Self::from_bytes(bytes.to_vec())
            .ok_or_else(|| ssz::DecodeError::BytesInvalid("BitVector failed to decode".to_string()))
    }
}

impl<N: Unsigned + Clone> Serialize for Bitfield<BitList<N>> {
    /// Serde serialization is compliant with the Ethereum YAML test format.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(self.as_ssz_bytes()))
    }
}

impl<'de, N: Unsigned + Clone> Deserialize<'de> for Bitfield<BitList<N>> {
    /// Serde serialization is compliant with the Ethereum YAML test format.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // We reverse the bit-order so that the BitVec library can read its 0th
        // bit from the end of the hex string, e.g.
        // "0xef01" => [0xef, 0x01] => [0b1000_0000, 0b1111_1110]
        let bytes = deserializer.deserialize_str(PrefixedHexVisitor)?;
        Self::from_ssz_bytes(&bytes)
            .map_err(|e| serde::de::Error::custom(format!("Bitfield {:?}", e)))
    }
}

impl<N: Unsigned + Clone> Serialize for Bitfield<BitVector<N>> {
    /// Serde serialization is compliant with the Ethereum YAML test format.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(self.as_ssz_bytes()))
    }
}

impl<'de, N: Unsigned + Clone> Deserialize<'de> for Bitfield<BitVector<N>> {
    /// Serde serialization is compliant with the Ethereum YAML test format.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // We reverse the bit-order so that the BitVec library can read its 0th
        // bit from the end of the hex string, e.g.
        // "0xef01" => [0xef, 0x01] => [0b1000_0000, 0b1111_1110]
        let bytes = deserializer.deserialize_str(PrefixedHexVisitor)?;
        Self::from_ssz_bytes(&bytes)
            .map_err(|e| serde::de::Error::custom(format!("Bitfield {:?}", e)))
    }
}

impl<N: Unsigned + Clone> tree_hash::TreeHash for Bitfield<BitList<N>> {
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
        // TODO: pad this out to max length.
        self.as_ssz_bytes().tree_hash_root()
    }
}

impl<N: Unsigned + Clone> tree_hash::TreeHash for Bitfield<BitVector<N>> {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        // TODO: move this to be a vector.
        tree_hash::TreeHashType::List
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        // TODO: move this to be a vector.
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        // TODO: move this to be a vector.
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_root(&self) -> Vec<u8> {
        self.as_ssz_bytes().tree_hash_root()
    }
}

impl<N: Unsigned + Clone> cached_tree_hash::CachedTreeHash for Bitfield<BitList<N>> {
    fn new_tree_hash_cache(
        &self,
        depth: usize,
    ) -> Result<cached_tree_hash::TreeHashCache, cached_tree_hash::Error> {
        let bytes = self.to_bytes();

        let (mut cache, schema) = cached_tree_hash::vec::new_tree_hash_cache(&bytes, depth)?;

        cache.add_length_nodes(schema.into_overlay(0).chunk_range(), bytes.len())?;

        Ok(cache)
    }

    fn num_tree_hash_cache_chunks(&self) -> usize {
        // Add two extra nodes to cater for the node before and after to allow mixing-in length.
        cached_tree_hash::BTreeOverlay::new(self, 0, 0).num_chunks() + 2
    }

    fn tree_hash_cache_schema(&self, depth: usize) -> cached_tree_hash::BTreeSchema {
        let bytes = self.to_bytes();
        cached_tree_hash::vec::produce_schema(&bytes, depth)
    }

    fn update_tree_hash_cache(
        &self,
        cache: &mut cached_tree_hash::TreeHashCache,
    ) -> Result<(), cached_tree_hash::Error> {
        let bytes = self.to_bytes();

        // Skip the length-mixed-in root node.
        cache.chunk_index += 1;

        // Update the cache, returning the new overlay.
        let new_overlay = cached_tree_hash::vec::update_tree_hash_cache(&bytes, cache)?;

        // Mix in length
        cache.mix_in_length(new_overlay.chunk_range(), bytes.len())?;

        // Skip an extra node to clear the length node.
        cache.chunk_index += 1;

        Ok(())
    }
}

impl<N: Unsigned + Clone> cached_tree_hash::CachedTreeHash for Bitfield<BitVector<N>> {
    fn new_tree_hash_cache(
        &self,
        depth: usize,
    ) -> Result<cached_tree_hash::TreeHashCache, cached_tree_hash::Error> {
        let (cache, _schema) =
            cached_tree_hash::vec::new_tree_hash_cache(&ssz::ssz_encode(self), depth)?;

        Ok(cache)
    }

    fn tree_hash_cache_schema(&self, depth: usize) -> cached_tree_hash::BTreeSchema {
        let lengths = vec![
            1;
            cached_tree_hash::merkleize::num_unsanitized_leaves(bytes_for_bit_len(
                N::to_usize()
            ))
        ];
        cached_tree_hash::BTreeSchema::from_lengths(depth, lengths)
    }

    fn update_tree_hash_cache(
        &self,
        cache: &mut cached_tree_hash::TreeHashCache,
    ) -> Result<(), cached_tree_hash::Error> {
        cached_tree_hash::vec::update_tree_hash_cache(&ssz::ssz_encode(self), cache)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    type Bitfield = super::Bitfield<BitList<typenum::U1024>>;

    #[test]
    fn from_raw_bytes() {
        assert!(Bitfield::from_raw_bytes(vec![0b0000_0000], 0).is_some());
        assert!(Bitfield::from_raw_bytes(vec![0b0000_0001], 1).is_some());
        assert!(Bitfield::from_raw_bytes(vec![0b0000_0011], 2).is_some());
        assert!(Bitfield::from_raw_bytes(vec![0b0000_0111], 3).is_some());
        assert!(Bitfield::from_raw_bytes(vec![0b0000_1111], 4).is_some());
        assert!(Bitfield::from_raw_bytes(vec![0b0001_1111], 5).is_some());
        assert!(Bitfield::from_raw_bytes(vec![0b0011_1111], 6).is_some());
        assert!(Bitfield::from_raw_bytes(vec![0b0111_1111], 7).is_some());
        assert!(Bitfield::from_raw_bytes(vec![0b1111_1111], 8).is_some());

        assert!(Bitfield::from_raw_bytes(vec![0b0000_0001, 0b1111_1111], 9).is_some());
        assert!(Bitfield::from_raw_bytes(vec![0b0000_0011, 0b1111_1111], 10).is_some());
        assert!(Bitfield::from_raw_bytes(vec![0b0000_0111, 0b1111_1111], 11).is_some());
        assert!(Bitfield::from_raw_bytes(vec![0b0000_1111, 0b1111_1111], 12).is_some());
        assert!(Bitfield::from_raw_bytes(vec![0b0001_1111, 0b1111_1111], 13).is_some());
        assert!(Bitfield::from_raw_bytes(vec![0b0011_1111, 0b1111_1111], 14).is_some());
        assert!(Bitfield::from_raw_bytes(vec![0b0111_1111, 0b1111_1111], 15).is_some());
        assert!(Bitfield::from_raw_bytes(vec![0b1111_1111, 0b1111_1111], 16).is_some());

        for i in 0..8 {
            assert!(Bitfield::from_raw_bytes(vec![], i).is_none());
            assert!(Bitfield::from_raw_bytes(vec![0b1111_1111], i).is_none());
            assert!(Bitfield::from_raw_bytes(vec![0b1111_1110, 0b0000_0000], i).is_none());
        }

        assert!(Bitfield::from_raw_bytes(vec![0b0000_0001], 0).is_none());

        assert!(Bitfield::from_raw_bytes(vec![0b0000_0001], 0).is_none());
        assert!(Bitfield::from_raw_bytes(vec![0b0000_0011], 1).is_none());
        assert!(Bitfield::from_raw_bytes(vec![0b0000_0111], 2).is_none());
        assert!(Bitfield::from_raw_bytes(vec![0b0000_1111], 3).is_none());
        assert!(Bitfield::from_raw_bytes(vec![0b0001_1111], 4).is_none());
        assert!(Bitfield::from_raw_bytes(vec![0b0011_1111], 5).is_none());
        assert!(Bitfield::from_raw_bytes(vec![0b0111_1111], 6).is_none());
        assert!(Bitfield::from_raw_bytes(vec![0b1111_1111], 7).is_none());

        assert!(Bitfield::from_raw_bytes(vec![0b0000_0001, 0b1111_1111], 8).is_none());
        assert!(Bitfield::from_raw_bytes(vec![0b0000_0011, 0b1111_1111], 9).is_none());
        assert!(Bitfield::from_raw_bytes(vec![0b0000_0111, 0b1111_1111], 10).is_none());
        assert!(Bitfield::from_raw_bytes(vec![0b0000_1111, 0b1111_1111], 11).is_none());
        assert!(Bitfield::from_raw_bytes(vec![0b0001_1111, 0b1111_1111], 12).is_none());
        assert!(Bitfield::from_raw_bytes(vec![0b0011_1111, 0b1111_1111], 13).is_none());
        assert!(Bitfield::from_raw_bytes(vec![0b0111_1111, 0b1111_1111], 14).is_none());
        assert!(Bitfield::from_raw_bytes(vec![0b1111_1111, 0b1111_1111], 15).is_none());
    }

    fn test_set_unset(num_bits: usize) {
        let mut bitfield = Bitfield::with_capacity(num_bits).unwrap();

        for i in 0..num_bits + 1 {
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
        for i in 0..num_bits {
            let mut bitfield = Bitfield::with_capacity(num_bits).unwrap();
            bitfield.set(i, true).unwrap();

            let bytes = bitfield.clone().to_raw_bytes();
            assert_eq!(bitfield, Bitfield::from_raw_bytes(bytes, num_bits).unwrap());
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
    fn to_raw_bytes() {
        let mut bitfield = Bitfield::with_capacity(9).unwrap();
        bitfield.set(0, true);
        assert_eq!(
            bitfield.clone().to_raw_bytes(),
            vec![0b0000_0000, 0b0000_0001]
        );
        bitfield.set(1, true);
        assert_eq!(
            bitfield.clone().to_raw_bytes(),
            vec![0b0000_0000, 0b0000_0011]
        );
        bitfield.set(2, true);
        assert_eq!(
            bitfield.clone().to_raw_bytes(),
            vec![0b0000_0000, 0b0000_0111]
        );
        bitfield.set(3, true);
        assert_eq!(
            bitfield.clone().to_raw_bytes(),
            vec![0b0000_0000, 0b0000_1111]
        );
        bitfield.set(4, true);
        assert_eq!(
            bitfield.clone().to_raw_bytes(),
            vec![0b0000_0000, 0b0001_1111]
        );
        bitfield.set(5, true);
        assert_eq!(
            bitfield.clone().to_raw_bytes(),
            vec![0b0000_0000, 0b0011_1111]
        );
        bitfield.set(6, true);
        assert_eq!(
            bitfield.clone().to_raw_bytes(),
            vec![0b0000_0000, 0b0111_1111]
        );
        bitfield.set(7, true);
        assert_eq!(
            bitfield.clone().to_raw_bytes(),
            vec![0b0000_0000, 0b1111_1111]
        );
        bitfield.set(8, true);
        assert_eq!(
            bitfield.clone().to_raw_bytes(),
            vec![0b0000_0001, 0b1111_1111]
        );
    }

    #[test]
    fn highest_set_bit() {
        assert_eq!(Bitfield::with_capacity(16).unwrap().highest_set_bit(), None);

        assert_eq!(
            Bitfield::from_raw_bytes(vec![0b0000_000, 0b0000_0001], 16)
                .unwrap()
                .highest_set_bit(),
            Some(0)
        );

        assert_eq!(
            Bitfield::from_raw_bytes(vec![0b0000_000, 0b0000_0010], 16)
                .unwrap()
                .highest_set_bit(),
            Some(1)
        );

        assert_eq!(
            Bitfield::from_raw_bytes(vec![0b0000_1000], 8)
                .unwrap()
                .highest_set_bit(),
            Some(3)
        );

        assert_eq!(
            Bitfield::from_raw_bytes(vec![0b1000_0000, 0b0000_0000], 16)
                .unwrap()
                .highest_set_bit(),
            Some(15)
        );
    }

    #[test]
    fn intersection() {
        let a = Bitfield::from_raw_bytes(vec![0b1100, 0b0001], 16).unwrap();
        let b = Bitfield::from_raw_bytes(vec![0b1011, 0b1001], 16).unwrap();
        let c = Bitfield::from_raw_bytes(vec![0b1000, 0b0001], 16).unwrap();

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
        let a = Bitfield::from_raw_bytes(vec![0b1100, 0b0001], 16).unwrap();
        let b = Bitfield::from_raw_bytes(vec![0b1011, 0b1001], 16).unwrap();
        let c = Bitfield::from_raw_bytes(vec![0b1111, 0b1001], 16).unwrap();

        assert_eq!(a.union(&b).unwrap(), c);
        assert_eq!(b.union(&a).unwrap(), c);
        assert_eq!(a.union(&a).unwrap(), a);
        assert_eq!(b.union(&b).unwrap(), b);
        assert_eq!(c.union(&c).unwrap(), c);
    }

    #[test]
    fn difference() {
        let a = Bitfield::from_raw_bytes(vec![0b1100, 0b0001], 16).unwrap();
        let b = Bitfield::from_raw_bytes(vec![0b1011, 0b1001], 16).unwrap();
        let a_b = Bitfield::from_raw_bytes(vec![0b0100, 0b0000], 16).unwrap();
        let b_a = Bitfield::from_raw_bytes(vec![0b0011, 0b1000], 16).unwrap();

        assert_eq!(a.difference(&b).unwrap(), a_b);
        assert_eq!(b.difference(&a).unwrap(), b_a);
        assert!(a.difference(&a).unwrap().is_zero());
    }

    #[test]
    fn iter() {
        let mut bitfield = Bitfield::with_capacity(9).unwrap();
        bitfield.set(2, true);
        bitfield.set(8, true);

        assert_eq!(
            bitfield.iter().collect::<Vec<bool>>(),
            vec![false, false, true, false, false, false, false, false, true]
        );
    }
}
