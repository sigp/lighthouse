use super::*;
use crate::{bitfield::Bitfield, impl_bitfield_fns, Error};
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode, PrefixedHexVisitor};
use ssz::{Decode, Encode};
use std::cmp;
use std::marker::PhantomData;
use typenum::Unsigned;

/// Emulates a SSZ `Bitvector`.
///
/// An ordered, heap-allocated, fixed-length, collection of `bool` values, with `N` values.
///
/// ## Notes
///
/// Considering this struct is backed by bytes, errors may be raised when attempting to decode
/// bytes into a `BitVector<N>` where `N` is not a multiple of 8. It is advised to always set `N` to
/// a multiple of 8.
///
/// ## Example
/// ```
/// use ssz_types::{BitVector, typenum};
///
/// let mut bitvec: BitVector<typenum::U8> = BitVector::new();
///
/// assert_eq!(bitvec.len(), 8);
///
/// for i in 0..8 {
///     assert_eq!(bitvec.get(i).unwrap(), false);  // Defaults to false.
/// }
///
/// assert!(bitvec.get(8).is_err());  // Cannot get out-of-bounds.
///
/// assert!(bitvec.set(7, true).is_ok());
/// assert!(bitvec.set(8, true).is_err());  // Cannot set out-of-bounds.
/// ```
#[derive(Debug, Clone)]
pub struct BitVector<N> {
    bitfield: Bitfield,
    _phantom: PhantomData<N>,
}

impl_bitfield_fns!(BitVector);

impl<N: Unsigned> BitVector<N> {
    /// Create a new bitfield.
    pub fn new() -> Self {
        Self {
            bitfield: Bitfield::with_capacity(Self::capacity()),
            _phantom: PhantomData,
        }
    }

    fn capacity() -> usize {
        N::to_usize()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_yaml;
    use ssz::ssz_encode;
    // use tree_hash::TreeHash;

    pub type BitVector4 = BitVector<typenum::U4>;
    pub type BitVector1024 = BitVector<typenum::U1024>;

    /*
    #[test]
    pub fn cached_tree_hash() {
        let original = BitVector1024::from_bytes(&vec![18; 12][..]);

        let mut cache = cached_tree_hash::TreeHashCache::new(&original).unwrap();

        assert_eq!(
            cache.tree_hash_root().unwrap().to_vec(),
            original.tree_hash_root()
        );

        let modified = BitVector1024::from_bytes(&vec![2; 1][..]);

        cache.update(&modified).unwrap();

        assert_eq!(
            cache.tree_hash_root().unwrap().to_vec(),
            modified.tree_hash_root()
        );
    }
    */

    /*
    #[test]
    fn new_bitfield() {
        let mut field = BitVector1024::new();
        let original_len = field.len();

        assert_eq!(original_len, 1024);

        for i in 0..1028 {
            if i < original_len {
                assert!(!field.get(i).unwrap());
                assert!(field.set(i, true).is_ok());
            } else {
                assert!(field.get(i).is_err());
                assert!(field.set(i, true).is_err());
            }
        }
    }

    #[test]
    fn from_bytes_bitvec4() {
        let bytes = &[3];

        let bitvec = BitVector4::from_bytes(bytes).unwrap();

        assert_eq!(bitvec.get(0), Ok(true));
        assert_eq!(bitvec.get(1), Ok(true));
        assert_eq!(bitvec.get(2), Ok(false));
        assert_eq!(bitvec.get(3), Ok(false));

        assert!(bitvec.get(4).is_err());
    }

    #[test]
    fn from_bytes_bytes_too_long() {
        let bytes = &[0, 0];

        assert_eq!(
            BitVector4::from_bytes(bytes),
            Err(Error::InvalidLength { i: 16, len: 4 })
        );
    }

    const INPUT: &[u8] = &[0b0100_0000, 0b0100_0000];

    #[test]
    fn get_from_bitfield() {
        let field = BitVector1024::from_bytes(INPUT).unwrap();
        field.get(0).unwrap();
        field.get(6).unwrap();
        field.get(14).unwrap();
    }

    #[test]
    fn set_for_bitfield() {
        let mut field = BitVector1024::from_bytes(INPUT).unwrap();
        field.set(10, true).unwrap();
        field.get(10).unwrap();
        field.set(6, false).unwrap();
        field.get(6).unwrap();
    }

    #[test]
    fn len() {
        let field = BitVector1024::from_bytes(INPUT).unwrap();
        assert_eq!(field.len(), 16);

        let field = BitVector1024::new();
        assert_eq!(field.len(), 0);
    }

    #[test]
    fn num_set_bits() {
        let field = BitVector1024::from_bytes(INPUT).unwrap();
        assert_eq!(field.num_set_bits(), 2);

        let field = BitVector1024::new();
        assert_eq!(field.num_set_bits(), 0);
    }

    #[test]
    fn to_bytes() {
        let field = BitVector1024::from_bytes(INPUT).unwrap();
        assert_eq!(field.to_bytes(), INPUT);

        let field = BitVector1024::new();
        assert_eq!(field.to_bytes(), vec![0]);
    }

    #[test]
    fn out_of_bounds() {
        let mut field = BitVector1024::from_bytes(INPUT).unwrap();

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
        let mut field = BitVector1024::from_bytes(input_all_set).unwrap();

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
        let field = BitVector1024::from_bytes(INPUT).unwrap();
        assert_eq!(field.num_bytes(), 2);

        let field = BitVector1024::from_elem(2, true).unwrap();
        assert_eq!(field.num_bytes(), 1);

        let field = BitVector1024::from_elem(13, true).unwrap();
        assert_eq!(field.num_bytes(), 2);
    }

    #[test]
    fn ssz_encoding() {
        let field = create_bitfield();
        assert_eq!(field.as_ssz_bytes(), vec![0b0000_0011, 0b1000_0111]);

        let field = BitVector1024::from_elem(18, true).unwrap();
        assert_eq!(
            field.as_ssz_bytes(),
            vec![0b0000_0011, 0b1111_1111, 0b1111_1111]
        );

        let mut b = BitVector1024::new();
        b.set(1, true).unwrap();
        assert_eq!(ssz_encode(&b), vec![0b0000_0010]);
    }

    fn create_bitfield() -> BitVector1024 {
        let count = 2 * 8;
        let mut field = BitVector1024::with_capacity(count).unwrap();

        let indices = &[0, 1, 2, 7, 8, 9];
        for &i in indices {
            field.set(i, true).unwrap();
        }
        field
    }

    #[test]
    fn ssz_decode() {
        let encoded = vec![0b0000_0011, 0b1000_0111];
        let field = BitVector1024::from_ssz_bytes(&encoded).unwrap();
        let expected = create_bitfield();
        assert_eq!(field, expected);

        let encoded = vec![255, 255, 3];
        let field = BitVector1024::from_ssz_bytes(&encoded).unwrap();
        let expected = BitVector1024::from_bytes(&[255, 255, 3]).unwrap();
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
            let bitfield = BitVector1024::from_bytes(bytes).unwrap();
            assert_eq!(
                serde_yaml::from_str::<BitVector1024>(hex_data).unwrap(),
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
        let original = BitVector1024::from_bytes(&vec![18; 12][..]).unwrap();
        let ssz = ssz_encode(&original);
        let decoded = BitVector1024::from_ssz_bytes(&ssz).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn bitor() {
        let a = BitVector1024::from_bytes(&vec![2, 8, 1][..]).unwrap();
        let b = BitVector1024::from_bytes(&vec![4, 8, 16][..]).unwrap();
        let c = BitVector1024::from_bytes(&vec![6, 8, 17][..]).unwrap();
        assert_eq!(c, a | b);
    }

    #[test]
    fn is_zero() {
        let yes_data: &[&[u8]] = &[&[], &[0], &[0, 0], &[0, 0, 0]];
        for bytes in yes_data {
            assert!(BitVector1024::from_bytes(bytes).unwrap().is_zero());
        }
        let no_data: &[&[u8]] = &[&[1], &[6], &[0, 1], &[0, 0, 1], &[0, 0, 255]];
        for bytes in no_data {
            assert!(!BitVector1024::from_bytes(bytes).unwrap().is_zero());
        }
    }
    */
}
