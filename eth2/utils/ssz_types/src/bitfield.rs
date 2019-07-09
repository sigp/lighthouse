use core::marker::PhantomData;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode as hex_encode, PrefixedHexVisitor};
use ssz::{Decode, Encode};
use typenum::Unsigned;

/// A marker trait applied to `BitList` and `BitVector` that defines the behaviour of a `Bitfield`.
pub trait BitfieldBehaviour: Clone {}

/// A marker struct used to define SSZ `BitList` functionality on a `Bitfield`.
///
/// See the [`Bitfield`](struct.Bitfield.html) docs for usage.
#[derive(Clone, PartialEq, Debug)]
pub struct BitList<N> {
    _phantom: PhantomData<N>,
}

/// A marker struct used to define SSZ `BitVector` functionality on a `Bitfield`.
///
/// See the [`Bitfield`](struct.Bitfield.html) docs for usage.
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
    /// Instantiate with capacity for `num_bits` boolean values. The length cannot be grown or
    /// shrunk after instantiation.
    ///
    /// All bits are initialized to `false`.
    ///
    /// Returns `None` if `num_bits > N`.
    pub fn with_capacity(num_bits: usize) -> Option<Self> {
        if num_bits <= N::to_usize() {
            let num_bytes = std::cmp::max(bytes_for_bit_len(num_bits), 1);

            Some(Self {
                bytes: vec![0; num_bytes],
                len: num_bits,
                _phantom: PhantomData,
            })
        } else {
            None
        }
    }

    /// Equal to `N` regardless of the value supplied to `with_capacity`.
    pub fn max_len() -> usize {
        N::to_usize()
    }

    /// Consumes `self`, returning a serialized representation.
    ///
    /// The output is faithful to the SSZ encoding of `self`, such that a leading `true` bit is
    /// used to indicate the length of the bitfield.
    ///
    /// ## Example
    /// ```
    /// use ssz_types::{Bitfield, typenum};
    ///
    /// type BitList = Bitfield<ssz_types::BitList<typenum::U8>>;
    ///
    /// let b = BitList::with_capacity(4).unwrap();
    ///
    /// assert_eq!(b.into_bytes(), vec![0b0001_0000]);
    /// ```
    pub fn into_bytes(self) -> Vec<u8> {
        let len = self.len();
        let mut bytes = self.as_slice().to_vec();

        while bytes_for_bit_len(len + 1) > bytes.len() {
            bytes.insert(0, 0);
        }

        let mut bitfield: Bitfield<BitList<N>> = Bitfield::from_raw_bytes(bytes, len + 1)
            .expect("Bitfield capacity has been confirmed earlier.");
        bitfield.set(len, true).expect("Bitfield index must exist.");

        bitfield.bytes
    }

    /// Instantiates a new instance from `bytes`. Consumes the same format that `self.into_bytes()`
    /// produces (SSZ).
    ///
    /// Returns `None` if `bytes` are not a valid encoding.
    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        let mut initial_bitfield: Bitfield<BitList<N>> = {
            let num_bits = bytes.len() * 8;
            Bitfield::from_raw_bytes(bytes, num_bits)
                .expect("Must have adequate bytes for bit count.")
        };

        let len = initial_bitfield.highest_set_bit()?;

        if len <= Self::max_len() {
            initial_bitfield
                .set(len, false)
                .expect("Bit has been confirmed to exist");

            let mut bytes = initial_bitfield.into_raw_bytes();

            if bytes_for_bit_len(len) < bytes.len() && bytes != [0] {
                bytes.remove(0);
            }

            Self::from_raw_bytes(bytes, len)
        } else {
            None
        }
    }
}

impl<N: Unsigned + Clone> Bitfield<BitVector<N>> {
    /// Instantiate a new `Bitfield` with a fixed-length of `N` bits.
    ///
    /// All bits are initialized to `false`.
    pub fn new() -> Self {
        let num_bits = N::to_usize();
        let num_bytes = std::cmp::max(bytes_for_bit_len(num_bits), 1);

        Self {
            bytes: vec![0; num_bytes],
            len: num_bits,
            _phantom: PhantomData,
        }
    }

    /// Returns `N`, the number of bits in `Self`.
    pub fn capacity() -> usize {
        N::to_usize()
    }

    /// Consumes `self`, returning a serialized representation.
    ///
    /// The output is faithful to the SSZ encoding of `self`.
    ///
    /// ## Example
    /// ```
    /// use ssz_types::{Bitfield, typenum};
    ///
    /// type BitVector = Bitfield<ssz_types::BitVector<typenum::U4>>;
    ///
    /// assert_eq!(BitVector::new().into_bytes(), vec![0b0000_0000]);
    /// ```
    pub fn into_bytes(self) -> Vec<u8> {
        self.into_raw_bytes()
    }

    /// Instantiates a new instance from `bytes`. Consumes the same format that `self.into_bytes()`
    /// produces (SSZ).
    ///
    /// Returns `None` if `bytes` are not a valid encoding.
    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        Self::from_raw_bytes(bytes, Self::capacity())
    }
}

impl<N: Unsigned + Clone> Default for Bitfield<BitVector<N>> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: BitfieldBehaviour> Bitfield<T> {
    /// Sets the `i`'th bit to `value`.
    ///
    /// Returns `None` if `i` is out-of-bounds of `self`.
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

    /// Returns the value of the `i`'th bit.
    ///
    /// Returns `None` if `i` is out-of-bounds of `self`.
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

    /// Returns the number of bits stored in `self`.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if `self.len() == 0`.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the underlying bytes representation of the bitfield.
    pub fn into_raw_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Returns a view into the underlying bytes representation of the bitfield.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Instantiates from the given `bytes`, which are the same format as output from
    /// `self.into_raw_bytes()`.
    ///
    /// Returns `None` if:
    ///
    /// - `bytes` is not the minimal required bytes to represent a bitfield of `bit_len` bits.
    /// - `bit_len` is not a multiple of 8 and `bytes` contains set bits that are higher than, or
    /// equal to `bit_len`.
    fn from_raw_bytes(bytes: Vec<u8>, bit_len: usize) -> Option<Self> {
        if bytes.len() == 1 && bit_len == 0 && bytes == [0] {
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

    /// Returns the `Some(i)` where `i` is the highest index with a set bit. Returns `None` if
    /// there are no set bits.
    pub fn highest_set_bit(&self) -> Option<usize> {
        let byte_i = self.bytes.iter().position(|byte| *byte > 0)?;
        let bit_i = 7 - self.bytes[byte_i].leading_zeros() as usize;

        Some((self.bytes.len().saturating_sub(1) - byte_i) * 8 + bit_i)
    }

    /// Returns an iterator across bitfield `bool` values, starting at the lowest index.
    pub fn iter(&self) -> BitIter<'_, T> {
        BitIter {
            bitfield: self,
            i: 0,
        }
    }

    /// Returns true if no bits are set.
    pub fn is_zero(&self) -> bool {
        !self.bytes.iter().any(|byte| (*byte & u8::max_value()) > 0)
    }

    /// Compute the intersection (binary-and) of this bitfield with another.
    ///
    /// Returns `None` if `self.is_comparable(other) == false`.
    pub fn intersection(&self, other: &Self) -> Option<Self> {
        if self.is_comparable(other) {
            let mut res = self.clone();
            res.intersection_inplace(other);
            Some(res)
        } else {
            None
        }
    }

    /// Like `intersection` but in-place (updates `self`).
    pub fn intersection_inplace(&mut self, other: &Self) -> Option<()> {
        if self.is_comparable(other) {
            for i in 0..self.bytes.len() {
                self.bytes[i] &= other.bytes[i];
            }
            Some(())
        } else {
            None
        }
    }

    /// Compute the union (binary-or) of this bitfield with another.
    ///
    /// Returns `None` if `self.is_comparable(other) == false`.
    pub fn union(&self, other: &Self) -> Option<Self> {
        if self.is_comparable(other) {
            let mut res = self.clone();
            res.union_inplace(other);
            Some(res)
        } else {
            None
        }
    }

    /// Like `union` but in-place (updates `self`).
    pub fn union_inplace(&mut self, other: &Self) -> Option<()> {
        if self.is_comparable(other) {
            for i in 0..self.bytes.len() {
                self.bytes[i] |= other.bytes[i];
            }
            Some(())
        } else {
            None
        }
    }

    /// Compute the difference (binary-minus) of this bitfield with another. Lengths must match.
    ///
    /// Returns `None` if `self.is_comparable(other) == false`.
    pub fn difference(&self, other: &Self) -> Option<Self> {
        if self.is_comparable(other) {
            let mut res = self.clone();
            res.difference_inplace(other);
            Some(res)
        } else {
            None
        }
    }

    /// Like `difference` but in-place (updates `self`).
    pub fn difference_inplace(&mut self, other: &Self) -> Option<()> {
        if self.is_comparable(other) {
            for i in 0..self.bytes.len() {
                self.bytes[i] &= !other.bytes[i];
            }
            Some(())
        } else {
            None
        }
    }

    /// Returns true if `self` and `other` have the same lengths and can be used in binary
    /// comparison operations.
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
        buf.append(&mut self.clone().into_bytes())
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
        buf.append(&mut self.clone().into_bytes())
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
        let bytes = self.clone().into_bytes();

        let (mut cache, schema) = cached_tree_hash::vec::new_tree_hash_cache(&bytes, depth)?;

        cache.add_length_nodes(schema.into_overlay(0).chunk_range(), bytes.len())?;

        Ok(cache)
    }

    fn num_tree_hash_cache_chunks(&self) -> usize {
        // Add two extra nodes to cater for the node before and after to allow mixing-in length.
        cached_tree_hash::BTreeOverlay::new(self, 0, 0).num_chunks() + 2
    }

    fn tree_hash_cache_schema(&self, depth: usize) -> cached_tree_hash::BTreeSchema {
        let bytes = self.clone().into_bytes();
        cached_tree_hash::vec::produce_schema(&bytes, depth)
    }

    fn update_tree_hash_cache(
        &self,
        cache: &mut cached_tree_hash::TreeHashCache,
    ) -> Result<(), cached_tree_hash::Error> {
        let bytes = self.clone().into_bytes();

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
mod bitvector {
    use super::*;

    pub type BitVector<N> = crate::Bitfield<crate::BitVector<N>>;
    pub type BitVector0 = BitVector<typenum::U0>;
    pub type BitVector1 = BitVector<typenum::U1>;
    pub type BitVector4 = BitVector<typenum::U4>;
    pub type BitVector8 = BitVector<typenum::U8>;
    pub type BitVector16 = BitVector<typenum::U16>;

    #[test]
    fn ssz_encode() {
        assert_eq!(BitVector0::new().as_ssz_bytes(), vec![0b0000_0000]);
        assert_eq!(BitVector1::new().as_ssz_bytes(), vec![0b0000_0000]);
        assert_eq!(BitVector4::new().as_ssz_bytes(), vec![0b0000_0000]);
        assert_eq!(BitVector8::new().as_ssz_bytes(), vec![0b0000_0000]);
        assert_eq!(
            BitVector16::new().as_ssz_bytes(),
            vec![0b0000_0000, 0b0000_0000]
        );

        let mut b = BitVector8::new();
        for i in 0..8 {
            b.set(i, true).unwrap();
        }
        assert_eq!(b.as_ssz_bytes(), vec![255]);

        let mut b = BitVector4::new();
        for i in 0..4 {
            b.set(i, true).unwrap();
        }
        assert_eq!(b.as_ssz_bytes(), vec![0b0000_1111]);
    }

    #[test]
    fn ssz_decode() {
        assert!(BitVector0::from_ssz_bytes(&[0b0000_0000]).is_ok());
        assert!(BitVector0::from_ssz_bytes(&[0b0000_0001]).is_err());
        assert!(BitVector0::from_ssz_bytes(&[0b0000_0010]).is_err());

        assert!(BitVector1::from_ssz_bytes(&[0b0000_0001]).is_ok());
        assert!(BitVector1::from_ssz_bytes(&[0b0000_0010]).is_err());
        assert!(BitVector1::from_ssz_bytes(&[0b0000_0100]).is_err());
        assert!(BitVector1::from_ssz_bytes(&[0b0000_0000, 0b0000_0000]).is_err());

        assert!(BitVector8::from_ssz_bytes(&[0b0000_0000]).is_ok());
        assert!(BitVector8::from_ssz_bytes(&[1, 0b0000_0000]).is_err());
        assert!(BitVector8::from_ssz_bytes(&[0b0000_0001]).is_ok());
        assert!(BitVector8::from_ssz_bytes(&[0b0000_0010]).is_ok());
        assert!(BitVector8::from_ssz_bytes(&[0b0000_0001, 0b0000_0100]).is_err());
        assert!(BitVector8::from_ssz_bytes(&[0b0000_0010, 0b0000_0100]).is_err());

        assert!(BitVector16::from_ssz_bytes(&[0b0000_0000]).is_err());
        assert!(BitVector16::from_ssz_bytes(&[0b0000_0000, 0b0000_0000]).is_ok());
        assert!(BitVector16::from_ssz_bytes(&[1, 0b0000_0000, 0b0000_0000]).is_err());
    }

    #[test]
    fn ssz_round_trip() {
        assert_round_trip(BitVector0::new());

        let mut b = BitVector1::new();
        b.set(0, true);
        assert_round_trip(b);

        let mut b = BitVector8::new();
        for j in 0..8 {
            if j % 2 == 0 {
                b.set(j, true);
            }
        }
        assert_round_trip(b);

        let mut b = BitVector8::new();
        for j in 0..8 {
            b.set(j, true);
        }
        assert_round_trip(b);

        let mut b = BitVector16::new();
        for j in 0..16 {
            if j % 2 == 0 {
                b.set(j, true);
            }
        }
        assert_round_trip(b);

        let mut b = BitVector16::new();
        for j in 0..16 {
            b.set(j, true);
        }
        assert_round_trip(b);
    }

    fn assert_round_trip<T: Encode + Decode + PartialEq + std::fmt::Debug>(t: T) {
        assert_eq!(T::from_ssz_bytes(&t.as_ssz_bytes()).unwrap(), t);
    }
}

#[cfg(test)]
mod bitlist {
    use super::*;

    pub type BitList<N> = super::Bitfield<crate::BitList<N>>;
    pub type BitList0 = BitList<typenum::U0>;
    pub type BitList1 = BitList<typenum::U1>;
    pub type BitList8 = BitList<typenum::U8>;
    pub type BitList16 = BitList<typenum::U16>;
    pub type BitList1024 = BitList<typenum::U1024>;

    #[test]
    fn ssz_encode() {
        assert_eq!(
            BitList0::with_capacity(0).unwrap().as_ssz_bytes(),
            vec![0b0000_00001],
        );

        assert_eq!(
            BitList1::with_capacity(0).unwrap().as_ssz_bytes(),
            vec![0b0000_00001],
        );

        assert_eq!(
            BitList1::with_capacity(1).unwrap().as_ssz_bytes(),
            vec![0b0000_00010],
        );

        assert_eq!(
            BitList8::with_capacity(8).unwrap().as_ssz_bytes(),
            vec![0b0000_0001, 0b0000_0000],
        );

        assert_eq!(
            BitList8::with_capacity(7).unwrap().as_ssz_bytes(),
            vec![0b1000_0000]
        );

        let mut b = BitList8::with_capacity(8).unwrap();
        for i in 0..8 {
            b.set(i, true).unwrap();
        }
        assert_eq!(b.as_ssz_bytes(), vec![0b0000_0001, 255]);

        let mut b = BitList8::with_capacity(8).unwrap();
        for i in 0..4 {
            b.set(i, true).unwrap();
        }
        assert_eq!(b.as_ssz_bytes(), vec![0b0000_0001, 0b0000_1111]);

        assert_eq!(
            BitList16::with_capacity(16).unwrap().as_ssz_bytes(),
            vec![0b0000_0001, 0b0000_0000, 0b0000_0000]
        );
    }

    #[test]
    fn ssz_decode() {
        assert!(BitList0::from_ssz_bytes(&[0b0000_0000]).is_err());
        assert!(BitList1::from_ssz_bytes(&[0b0000_0000, 0b0000_0000]).is_err());
        assert!(BitList8::from_ssz_bytes(&[0b0000_0000]).is_err());
        assert!(BitList16::from_ssz_bytes(&[0b0000_0000]).is_err());

        assert!(BitList0::from_ssz_bytes(&[0b0000_0001]).is_ok());
        assert!(BitList0::from_ssz_bytes(&[0b0000_0010]).is_err());

        assert!(BitList1::from_ssz_bytes(&[0b0000_0001]).is_ok());
        assert!(BitList1::from_ssz_bytes(&[0b0000_0010]).is_ok());
        assert!(BitList1::from_ssz_bytes(&[0b0000_0100]).is_err());

        assert!(BitList8::from_ssz_bytes(&[0b0000_0001]).is_ok());
        assert!(BitList8::from_ssz_bytes(&[0b0000_0010]).is_ok());
        assert!(BitList8::from_ssz_bytes(&[0b0000_0001, 0b0000_0100]).is_ok());
        assert!(BitList8::from_ssz_bytes(&[0b0000_0010, 0b0000_0100]).is_err());
    }

    #[test]
    fn ssz_round_trip() {
        assert_round_trip(BitList0::with_capacity(0).unwrap());

        for i in 0..2 {
            assert_round_trip(BitList1::with_capacity(i).unwrap());
        }
        for i in 0..9 {
            assert_round_trip(BitList8::with_capacity(i).unwrap());
        }
        for i in 0..17 {
            assert_round_trip(BitList16::with_capacity(i).unwrap());
        }

        let mut b = BitList1::with_capacity(1).unwrap();
        b.set(0, true);
        assert_round_trip(b);

        for i in 0..8 {
            let mut b = BitList8::with_capacity(i).unwrap();
            for j in 0..i {
                if j % 2 == 0 {
                    b.set(j, true);
                }
            }
            assert_round_trip(b);

            let mut b = BitList8::with_capacity(i).unwrap();
            for j in 0..i {
                b.set(j, true);
            }
            assert_round_trip(b);
        }

        for i in 0..16 {
            let mut b = BitList16::with_capacity(i).unwrap();
            for j in 0..i {
                if j % 2 == 0 {
                    b.set(j, true);
                }
            }
            assert_round_trip(b);

            let mut b = BitList16::with_capacity(i).unwrap();
            for j in 0..i {
                b.set(j, true);
            }
            assert_round_trip(b);
        }
    }

    fn assert_round_trip<T: Encode + Decode + PartialEq + std::fmt::Debug>(t: T) {
        assert_eq!(T::from_ssz_bytes(&t.as_ssz_bytes()).unwrap(), t);
    }

    #[test]
    fn from_raw_bytes() {
        assert!(BitList1024::from_raw_bytes(vec![0b0000_0000], 0).is_some());
        assert!(BitList1024::from_raw_bytes(vec![0b0000_0001], 1).is_some());
        assert!(BitList1024::from_raw_bytes(vec![0b0000_0011], 2).is_some());
        assert!(BitList1024::from_raw_bytes(vec![0b0000_0111], 3).is_some());
        assert!(BitList1024::from_raw_bytes(vec![0b0000_1111], 4).is_some());
        assert!(BitList1024::from_raw_bytes(vec![0b0001_1111], 5).is_some());
        assert!(BitList1024::from_raw_bytes(vec![0b0011_1111], 6).is_some());
        assert!(BitList1024::from_raw_bytes(vec![0b0111_1111], 7).is_some());
        assert!(BitList1024::from_raw_bytes(vec![0b1111_1111], 8).is_some());

        assert!(BitList1024::from_raw_bytes(vec![0b0000_0001, 0b1111_1111], 9).is_some());
        assert!(BitList1024::from_raw_bytes(vec![0b0000_0011, 0b1111_1111], 10).is_some());
        assert!(BitList1024::from_raw_bytes(vec![0b0000_0111, 0b1111_1111], 11).is_some());
        assert!(BitList1024::from_raw_bytes(vec![0b0000_1111, 0b1111_1111], 12).is_some());
        assert!(BitList1024::from_raw_bytes(vec![0b0001_1111, 0b1111_1111], 13).is_some());
        assert!(BitList1024::from_raw_bytes(vec![0b0011_1111, 0b1111_1111], 14).is_some());
        assert!(BitList1024::from_raw_bytes(vec![0b0111_1111, 0b1111_1111], 15).is_some());
        assert!(BitList1024::from_raw_bytes(vec![0b1111_1111, 0b1111_1111], 16).is_some());

        for i in 0..8 {
            assert!(BitList1024::from_raw_bytes(vec![], i).is_none());
            assert!(BitList1024::from_raw_bytes(vec![0b1111_1111], i).is_none());
            assert!(BitList1024::from_raw_bytes(vec![0b1111_1110, 0b0000_0000], i).is_none());
        }

        assert!(BitList1024::from_raw_bytes(vec![0b0000_0001], 0).is_none());

        assert!(BitList1024::from_raw_bytes(vec![0b0000_0001], 0).is_none());
        assert!(BitList1024::from_raw_bytes(vec![0b0000_0011], 1).is_none());
        assert!(BitList1024::from_raw_bytes(vec![0b0000_0111], 2).is_none());
        assert!(BitList1024::from_raw_bytes(vec![0b0000_1111], 3).is_none());
        assert!(BitList1024::from_raw_bytes(vec![0b0001_1111], 4).is_none());
        assert!(BitList1024::from_raw_bytes(vec![0b0011_1111], 5).is_none());
        assert!(BitList1024::from_raw_bytes(vec![0b0111_1111], 6).is_none());
        assert!(BitList1024::from_raw_bytes(vec![0b1111_1111], 7).is_none());

        assert!(BitList1024::from_raw_bytes(vec![0b0000_0001, 0b1111_1111], 8).is_none());
        assert!(BitList1024::from_raw_bytes(vec![0b0000_0011, 0b1111_1111], 9).is_none());
        assert!(BitList1024::from_raw_bytes(vec![0b0000_0111, 0b1111_1111], 10).is_none());
        assert!(BitList1024::from_raw_bytes(vec![0b0000_1111, 0b1111_1111], 11).is_none());
        assert!(BitList1024::from_raw_bytes(vec![0b0001_1111, 0b1111_1111], 12).is_none());
        assert!(BitList1024::from_raw_bytes(vec![0b0011_1111, 0b1111_1111], 13).is_none());
        assert!(BitList1024::from_raw_bytes(vec![0b0111_1111, 0b1111_1111], 14).is_none());
        assert!(BitList1024::from_raw_bytes(vec![0b1111_1111, 0b1111_1111], 15).is_none());
    }

    fn test_set_unset(num_bits: usize) {
        let mut bitfield = BitList1024::with_capacity(num_bits).unwrap();

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
            let mut bitfield = BitList1024::with_capacity(num_bits).unwrap();
            bitfield.set(i, true).unwrap();

            let bytes = bitfield.clone().into_raw_bytes();
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
    fn into_raw_bytes() {
        let mut bitfield = BitList1024::with_capacity(9).unwrap();
        bitfield.set(0, true);
        assert_eq!(
            bitfield.clone().into_raw_bytes(),
            vec![0b0000_0000, 0b0000_0001]
        );
        bitfield.set(1, true);
        assert_eq!(
            bitfield.clone().into_raw_bytes(),
            vec![0b0000_0000, 0b0000_0011]
        );
        bitfield.set(2, true);
        assert_eq!(
            bitfield.clone().into_raw_bytes(),
            vec![0b0000_0000, 0b0000_0111]
        );
        bitfield.set(3, true);
        assert_eq!(
            bitfield.clone().into_raw_bytes(),
            vec![0b0000_0000, 0b0000_1111]
        );
        bitfield.set(4, true);
        assert_eq!(
            bitfield.clone().into_raw_bytes(),
            vec![0b0000_0000, 0b0001_1111]
        );
        bitfield.set(5, true);
        assert_eq!(
            bitfield.clone().into_raw_bytes(),
            vec![0b0000_0000, 0b0011_1111]
        );
        bitfield.set(6, true);
        assert_eq!(
            bitfield.clone().into_raw_bytes(),
            vec![0b0000_0000, 0b0111_1111]
        );
        bitfield.set(7, true);
        assert_eq!(
            bitfield.clone().into_raw_bytes(),
            vec![0b0000_0000, 0b1111_1111]
        );
        bitfield.set(8, true);
        assert_eq!(
            bitfield.clone().into_raw_bytes(),
            vec![0b0000_0001, 0b1111_1111]
        );
    }

    #[test]
    fn highest_set_bit() {
        assert_eq!(
            BitList1024::with_capacity(16).unwrap().highest_set_bit(),
            None
        );

        assert_eq!(
            BitList1024::from_raw_bytes(vec![0b0000_000, 0b0000_0001], 16)
                .unwrap()
                .highest_set_bit(),
            Some(0)
        );

        assert_eq!(
            BitList1024::from_raw_bytes(vec![0b0000_000, 0b0000_0010], 16)
                .unwrap()
                .highest_set_bit(),
            Some(1)
        );

        assert_eq!(
            BitList1024::from_raw_bytes(vec![0b0000_1000], 8)
                .unwrap()
                .highest_set_bit(),
            Some(3)
        );

        assert_eq!(
            BitList1024::from_raw_bytes(vec![0b1000_0000, 0b0000_0000], 16)
                .unwrap()
                .highest_set_bit(),
            Some(15)
        );
    }

    #[test]
    fn intersection() {
        let a = BitList1024::from_raw_bytes(vec![0b1100, 0b0001], 16).unwrap();
        let b = BitList1024::from_raw_bytes(vec![0b1011, 0b1001], 16).unwrap();
        let c = BitList1024::from_raw_bytes(vec![0b1000, 0b0001], 16).unwrap();

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
        let a = BitList1024::from_raw_bytes(vec![0b1100, 0b0001], 16).unwrap();
        let b = BitList1024::from_raw_bytes(vec![0b1011, 0b1001], 16).unwrap();
        let c = BitList1024::from_raw_bytes(vec![0b1111, 0b1001], 16).unwrap();

        assert_eq!(a.union(&b).unwrap(), c);
        assert_eq!(b.union(&a).unwrap(), c);
        assert_eq!(a.union(&a).unwrap(), a);
        assert_eq!(b.union(&b).unwrap(), b);
        assert_eq!(c.union(&c).unwrap(), c);
    }

    #[test]
    fn difference() {
        let a = BitList1024::from_raw_bytes(vec![0b1100, 0b0001], 16).unwrap();
        let b = BitList1024::from_raw_bytes(vec![0b1011, 0b1001], 16).unwrap();
        let a_b = BitList1024::from_raw_bytes(vec![0b0100, 0b0000], 16).unwrap();
        let b_a = BitList1024::from_raw_bytes(vec![0b0011, 0b1000], 16).unwrap();

        assert_eq!(a.difference(&b).unwrap(), a_b);
        assert_eq!(b.difference(&a).unwrap(), b_a);
        assert!(a.difference(&a).unwrap().is_zero());
    }

    #[test]
    fn iter() {
        let mut bitfield = BitList1024::with_capacity(9).unwrap();
        bitfield.set(2, true);
        bitfield.set(8, true);

        assert_eq!(
            bitfield.iter().collect::<Vec<bool>>(),
            vec![false, false, true, false, false, false, false, false, true]
        );
    }
}
