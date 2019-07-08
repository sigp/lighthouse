use super::*;
use crate::{bitfield::Bitfield, impl_bitfield_fns, Error};
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode, PrefixedHexVisitor};
use ssz::{Decode, Encode};
use std::cmp;
use std::default;
use std::marker::PhantomData;
use typenum::Unsigned;

/// Emulates a SSZ `Bitlist`.
///
/// An ordered, heap-allocated, variable-length, collection of `bool` values, limited to `N`
/// values.
///
/// ## Notes
///
/// Considering this struct is backed by bytes, errors may be raised when attempting to decode
/// bytes into a `BitList<N>` where `N` is not a multiple of 8. It is advised to always set `N` to
/// a multiple of 8.
///
/// ## Example
/// ```
/// use ssz_types::{BitList, typenum};
///
/// let mut bitlist: BitList<typenum::U8> = BitList::new();
///
/// assert_eq!(bitlist.len(), 0);
///
/// assert!(bitlist.get(0).is_err());  // Cannot get at or below the length.
///
/// for i in 0..8 {
///     assert!(bitlist.set(i, true).is_ok());
/// }
///
/// assert!(bitlist.set(8, true).is_err());  // Cannot set out-of-bounds.
///
/// // Cannot create with an excessive capacity.
/// let result: Result<BitList<typenum::U8>, _> = BitList::with_capacity(9);
/// assert!(result.is_err());
/// ```
#[derive(Debug, Clone)]
pub struct BitList<N> {
    bitfield: Bitfield,
    _phantom: PhantomData<N>,
}

impl_bitfield_fns!(BitList);

impl<N: Unsigned> BitList<N> {
    /// Create a new, empty BitList.
    pub fn new() -> Self {
        Self {
            bitfield: Bitfield::with_capacity(Self::max_len()),
            _phantom: PhantomData,
        }
    }

    fn validate_length(len: usize) -> Result<(), Error> {
        let max_len = Self::max_len();

        if len > max_len {
            Err(Error::InvalidLength {
                i: len,
                len: max_len,
            })
        } else {
            Ok(())
        }
    }

    /// The maximum possible number of bits.
    pub fn max_len() -> usize {
        N::to_usize()
    }
}

/*
fn encode_bitfield(bitfield: Bitfield) -> Vec<u8> {
    // Set the next bit of the bitfield to true.
    //
    // SSZ spec:
    //
    // An additional leading 1 bit is added so that the length in bits will also be known.
    bitfield.set(bitfield.len(), true);
    let bytes = bitfield.to_bytes();
}
*/

impl<N: Unsigned + Clone> BitList<N> {
    /// Compute the intersection (binary-and) of this bitfield with another
    ///
    /// ## Panics
    ///
    /// If `self` and `other` have different lengths.
    pub fn intersection(&self, other: &Self) -> Self {
        assert_eq!(self.len(), other.len());
        let mut res: Self = self.to_owned();
        res.intersection_inplace(other);
        res
    }

    /// Like `intersection` but in-place (updates `self`).
    ///
    /// ## Panics
    ///
    /// If `self` and `other` have different lengths.
    pub fn intersection_inplace(&mut self, other: &Self) {
        self.bitfield.intersection(&other.bitfield);
    }

    /// Compute the union (binary-or) of this bitfield with another. Lengths must match.
    ///
    /// ## Panics
    ///
    /// If `self` and `other` have different lengths.
    pub fn union(&self, other: &Self) -> Self {
        assert_eq!(self.len(), other.len());
        let mut res = self.clone();
        res.union_inplace(other);
        res
    }

    /// Like `union` but in-place (updates `self`).
    ///
    /// ## Panics
    ///
    /// If `self` and `other` have different lengths.
    pub fn union_inplace(&mut self, other: &Self) {
        self.bitfield.union(&other.bitfield);
    }

    /// Compute the difference (binary-minus) of this bitfield with another. Lengths must match.
    ///
    /// Computes `self - other`.
    ///
    /// ## Panics
    ///
    /// If `self` and `other` have different lengths.
    pub fn difference(&self, other: &Self) -> Self {
        assert_eq!(self.len(), other.len());
        let mut res = self.clone();
        res.difference_inplace(other);
        res
    }

    /// Like `difference` but in-place (updates `self`).
    ///
    /// ## Panics
    ///
    /// If `self` and `other` have different lengths.
    pub fn difference_inplace(&mut self, other: &Self) {
        self.bitfield.difference(&other.bitfield);
    }
}

/*
#[cfg(test)]
mod test {
    use super::*;
    use serde_yaml;
    use ssz::ssz_encode;
    // use tree_hash::TreeHash;

    pub type BitList1024 = BitList<typenum::U1024>;

    /*
    #[test]
    pub fn cached_tree_hash() {
        let original = BitList1024::from_bytes(&vec![18; 12][..]);

        let mut cache = cached_tree_hash::TreeHashCache::new(&original).unwrap();

        assert_eq!(
            cache.tree_hash_root().unwrap().to_vec(),
            original.tree_hash_root()
        );

        let modified = BitList1024::from_bytes(&vec![2; 1][..]);

        cache.update(&modified).unwrap();

        assert_eq!(
            cache.tree_hash_root().unwrap().to_vec(),
            modified.tree_hash_root()
        );
    }
    */

    #[test]
    fn new_bitfield() {
        let mut field = BitList1024::new();
        let original_len = field.len();

        for i in 0..100 {
            if i < original_len {
                assert!(!field.get(i).unwrap());
            } else {
                assert!(field.get(i).is_err());
            }
            field.set(i, true).unwrap();
        }
    }

    #[test]
    fn empty_bitfield() {
        let mut field = BitList1024::from_elem(0, false).unwrap();
        let original_len = field.len();

        assert_eq!(original_len, 0);

        for i in 0..100 {
            if i < original_len {
                assert!(!field.get(i).unwrap());
            } else {
                assert!(field.get(i).is_err());
            }
            field.set(i, true).unwrap();
        }

        assert_eq!(field.len(), 100);
        assert_eq!(field.num_set_bits(), 100);
    }

    const INPUT: &[u8] = &[0b0100_0000, 0b0100_0000];

    #[test]
    fn get_from_bitfield() {
        let field = BitList1024::from_bytes(INPUT).unwrap();
        field.get(0).unwrap();
        field.get(6).unwrap();
        field.get(14).unwrap();
    }

    #[test]
    fn set_for_bitfield() {
        let mut field = BitList1024::from_bytes(INPUT).unwrap();
        field.set(10, true).unwrap();
        field.get(10).unwrap();
        field.set(6, false).unwrap();
        field.get(6).unwrap();
    }

    #[test]
    fn len() {
        let field = BitList1024::from_bytes(INPUT).unwrap();
        assert_eq!(field.len(), 16);

        let field = BitList1024::new();
        assert_eq!(field.len(), 0);
    }

    #[test]
    fn num_set_bits() {
        let field = BitList1024::from_bytes(INPUT).unwrap();
        assert_eq!(field.num_set_bits(), 2);

        let field = BitList1024::new();
        assert_eq!(field.num_set_bits(), 0);
    }

    #[test]
    fn to_bytes() {
        let field = BitList1024::from_bytes(INPUT).unwrap();
        assert_eq!(field.to_bytes(), INPUT);

        let field = BitList1024::new();
        assert_eq!(field.to_bytes(), vec![0]);
    }

    #[test]
    fn out_of_bounds() {
        let mut field = BitList1024::from_bytes(INPUT).unwrap();

        let out_of_bounds_index = field.len();
        assert!(field.set(out_of_bounds_index, true).is_ok());
        assert!(field.len() == out_of_bounds_index + 1);
        assert!(field.get(out_of_bounds_index).unwrap());

        for i in 0..100 {
            if i <= out_of_bounds_index {
                assert!(field.set(i, true).is_ok());
            } else {
                assert!(field.set(i, true).is_ok());
            }
        }
    }

    #[test]
    fn grows_with_false() {
        let input_all_set: &[u8] = &[0b1111_1111, 0b1111_1111];
        let mut field = BitList1024::from_bytes(input_all_set).unwrap();

        // Define `a` and `b`, where both are out of bounds and `b` is greater than `a`.
        let a = field.len();
        let b = a + 1;

        // Ensure `a` is out-of-bounds for test integrity.
        assert!(field.get(a).is_err());

        // Set `b` to `true`..
        assert!(field.set(b, true).is_ok());

        // Ensure that `a` wasn't also set to `true` during the grow.
        assert_eq!(field.get(a), Ok(false));
        assert_eq!(field.get(b), Ok(true));
    }

    #[test]
    fn num_bytes() {
        let field = BitList1024::from_bytes(INPUT).unwrap();
        assert_eq!(field.num_bytes(), 2);

        let field = BitList1024::from_elem(2, true).unwrap();
        assert_eq!(field.num_bytes(), 1);

        let field = BitList1024::from_elem(13, true).unwrap();
        assert_eq!(field.num_bytes(), 2);
    }

    #[test]
    fn ssz_encoding() {
        let field = create_bitfield();
        assert_eq!(field.as_ssz_bytes(), vec![0b0000_0011, 0b1000_0111]);

        let field = BitList1024::from_elem(18, true).unwrap();
        assert_eq!(
            field.as_ssz_bytes(),
            vec![0b0000_0011, 0b1111_1111, 0b1111_1111]
        );

        let mut b = BitList1024::new();
        b.set(1, true).unwrap();
        assert_eq!(ssz_encode(&b), vec![0b0000_0010]);
    }

    fn create_bitfield() -> BitList1024 {
        let count = 2 * 8;
        let mut field = BitList1024::with_capacity(count).unwrap();

        let indices = &[0, 1, 2, 7, 8, 9];
        for &i in indices {
            field.set(i, true).unwrap();
        }
        field
    }

    #[test]
    fn ssz_decode() {
        let encoded = vec![0b0000_0011, 0b1000_0111];
        let field = BitList1024::from_ssz_bytes(&encoded).unwrap();
        let expected = create_bitfield();
        assert_eq!(field, expected);

        let encoded = vec![255, 255, 3];
        let field = BitList1024::from_ssz_bytes(&encoded).unwrap();
        let expected = BitList1024::from_bytes(&[255, 255, 3]).unwrap();
        assert_eq!(field, expected);
    }

    #[test]
    fn serialize_deserialize() {
        use serde_yaml::Value;

        let data: &[(_, &[_])] = &[
            ("0x01", &[0b00000001]),
            ("0xf301", &[0b11110011, 0b00000001]),
        ];
        for (hex_data, bytes) in data {
            let bitfield = BitList1024::from_bytes(bytes).unwrap();
            assert_eq!(
                serde_yaml::from_str::<BitList1024>(hex_data).unwrap(),
                bitfield
            );
            assert_eq!(
                serde_yaml::to_value(&bitfield).unwrap(),
                Value::String(hex_data.to_string())
            );
        }
    }

    #[test]
    fn ssz_round_trip() {
        let original = BitList1024::from_bytes(&vec![18; 12][..]).unwrap();
        let ssz = ssz_encode(&original);
        let decoded = BitList1024::from_ssz_bytes(&ssz).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn bitor() {
        let a = BitList1024::from_bytes(&vec![2, 8, 1][..]).unwrap();
        let b = BitList1024::from_bytes(&vec![4, 8, 16][..]).unwrap();
        let c = BitList1024::from_bytes(&vec![6, 8, 17][..]).unwrap();
        assert_eq!(c, a | b);
    }

    #[test]
    fn is_zero() {
        let yes_data: &[&[u8]] = &[&[], &[0], &[0, 0], &[0, 0, 0]];
        for bytes in yes_data {
            assert!(BitList1024::from_bytes(bytes).unwrap().is_zero());
        }
        let no_data: &[&[u8]] = &[&[1], &[6], &[0, 1], &[0, 0, 1], &[0, 0, 255]];
        for bytes in no_data {
            assert!(!BitList1024::from_bytes(bytes).unwrap().is_zero());
        }
    }

    #[test]
    fn intersection() {
        let a = BitList1024::from_bytes(&[0b1100, 0b0001]).unwrap();
        let b = BitList1024::from_bytes(&[0b1011, 0b1001]).unwrap();
        let c = BitList1024::from_bytes(&[0b1000, 0b0001]).unwrap();
        assert_eq!(a.intersection(&b), c);
        assert_eq!(b.intersection(&a), c);
        assert_eq!(a.intersection(&c), c);
        assert_eq!(b.intersection(&c), c);
        assert_eq!(a.intersection(&a), a);
        assert_eq!(b.intersection(&b), b);
        assert_eq!(c.intersection(&c), c);
    }

    #[test]
    fn union() {
        let a = BitList1024::from_bytes(&[0b1100, 0b0001]).unwrap();
        let b = BitList1024::from_bytes(&[0b1011, 0b1001]).unwrap();
        let c = BitList1024::from_bytes(&[0b1111, 0b1001]).unwrap();
        assert_eq!(a.union(&b), c);
        assert_eq!(b.union(&a), c);
        assert_eq!(a.union(&a), a);
        assert_eq!(b.union(&b), b);
        assert_eq!(c.union(&c), c);
    }

    #[test]
    fn difference() {
        let a = BitList1024::from_bytes(&[0b1100, 0b0001]).unwrap();
        let b = BitList1024::from_bytes(&[0b1011, 0b1001]).unwrap();
        let a_b = BitList1024::from_bytes(&[0b0100, 0b0000]).unwrap();
        let b_a = BitList1024::from_bytes(&[0b0011, 0b1000]).unwrap();
        assert_eq!(a.difference(&b), a_b);
        assert_eq!(b.difference(&a), b_a);
        assert!(a.difference(&a).is_zero());
    }
}
*/
